#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Client A for the marker-address experiment. EXPERIMENT ONLY.

Opens one inbound P2P connection to node 1 (mainnet, localhost) and sends
one unique class E "marker" address per addr message. Each message goes out
just after a whole-second boundary with nTime = floor(now) - age, so the
age node 1 sees is `age` plus a few ms. Messages are spaced at least
--interval seconds apart to stay inside node 1's addr rate limit (1 token
on connect, +0.1 per second). Every send is appended to --csv.

Run from the repository root of the node-1 branch:
    contrib/marker-experiment/client_a.py --csv markers-sent.csv
"""

import argparse
import csv
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "test", "functional"))

from test_framework.messages import (  # noqa: E402
    CAddress,
    NODE_NETWORK,
    NODE_NETWORK_LIMITED,
    NODE_P2P_V2,
    NODE_WITNESS,
    msg_addr,
)
from test_framework.p2p import NetworkThread, P2PInterface  # noqa: E402

# Looks like a current Core node, and passes node 1's service checks.
MARKER_SERVICES = NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED | NODE_P2P_V2
MARKER_PORT = 8333
DEFAULT_AGES = "599,598,597,593,587,579,568,552,531,495"
# Delay after the whole-second boundary before sending.
SEND_OFFSET = 0.02
CSV_FIELDS = ["seq", "send_unix_us", "ntime", "age_s", "addr", "services"]


def new_marker(rng, used):
    """A random class E address, unused so far. 240.x is skipped since 240.0.0.x
    junk already circulates on mainnet; 255.x is skipped since 255.255.255.255
    is invalid."""
    while True:
        ip = f"{rng.randint(241, 254)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        if ip not in used:
            assert 241 <= int(ip.split(".")[0]) <= 254
            used.add(ip)
            return ip


class ClientA(P2PInterface):
    def on_inv(self, message):
        # Stay passive: don't fetch the blocks node 1 announces.
        pass

    def send_without_ping(self, message, *args, **kwargs):
        # P2PInterface sends getaddr after the handshake. A only ever sends
        # addresses, so it never asks node 1 for any.
        if message.msgtype == b"getaddr":
            return
        return super().send_without_ping(message, *args, **kwargs)


def connect(host, port, net):
    peer = ClientA()
    create_conn = peer.peer_connect(dstaddr=host, dstport=port, net=net, timeout_factor=1,
                                    supports_v2_p2p=False, send_version=True)
    # No transaction relay to A.
    peer.on_connection_send_msg.relay = 0
    create_conn()
    peer.wait_for_connect(timeout=30)
    peer.wait_for_verack(timeout=30)
    print(f"{time.strftime('%FT%TZ', time.gmtime())} connected to {host}:{port}", flush=True)
    return peer


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8333)
    parser.add_argument("--net", default="mainnet", choices=["mainnet", "regtest", "signet", "testnet4"], help="network magic (default: mainnet); regtest is for dry runs")
    parser.add_argument("--ages", default=DEFAULT_AGES, help=f"comma-separated nTime ages in seconds, cycled in shuffled rounds (default: {DEFAULT_AGES})")
    parser.add_argument("--interval", type=float, default=11.0, help="minimum seconds between messages; node 1 refills 0.1 tokens/s (default: 11)")
    parser.add_argument("--count", type=int, default=0, help="stop after this many markers (default: 0 = run until Ctrl-C)")
    parser.add_argument("--csv", required=True, help="append one row per marker sent; existing rows are never reused as markers")
    args = parser.parse_args()

    ages = [int(a) for a in args.ages.split(",")]
    assert all(0 <= a < 600 for a in ages), "ages must be under 10 minutes, or node 1 won't relay at all"
    assert args.interval >= 10.5, "interval must leave slack above node 1's 0.1/s token refill"

    used = set()
    seq = 0
    new_file = not os.path.exists(args.csv) or os.path.getsize(args.csv) == 0
    if not new_file:
        with open(args.csv, newline="") as f:
            for row in csv.DictReader(f):
                used.add(row["addr"].split(":")[0])
                seq = max(seq, int(row["seq"]) + 1)
    out = open(args.csv, "a", newline="")
    writer = csv.DictWriter(out, fieldnames=CSV_FIELDS)
    if new_file:
        writer.writeheader()

    rng = random.SystemRandom()
    network_thread = NetworkThread()
    # Daemon, so an error in the main thread can't leave the process hanging.
    network_thread.daemon = True
    network_thread.start()
    while NetworkThread.network_event_loop is None or not NetworkThread.network_event_loop.is_running():
        time.sleep(0.01)
    peer = connect(args.host, args.port, args.net)

    round_ages = []
    last_send = 0.0
    sent = 0
    try:
        while args.count == 0 or sent < args.count:
            if not peer.is_connected:
                print(f"{time.strftime('%FT%TZ', time.gmtime())} disconnected, reconnecting in 10s", flush=True)
                time.sleep(10)
                try:
                    peer = connect(args.host, args.port, args.net)
                except Exception as e:
                    print(f"reconnect failed: {e}", flush=True)
                    continue
                # A fresh connection starts with 1 token, so send right away.
                last_send = 0.0

            # Wait for the interval, then for the next whole second (the 50 ms
            # tolerance keeps an 11 s interval from rounding up to 12 s).
            earliest = max(time.time(), last_send + args.interval)
            target = math.ceil(earliest - SEND_OFFSET - 0.05) + SEND_OFFSET
            time.sleep(max(0.0, target - time.time()))

            if not round_ages:
                round_ages = ages[:]
                rng.shuffle(round_ages)
            age = round_ages.pop()

            ip = new_marker(rng, used)
            now = time.time()
            ntime = math.floor(now) - age
            addr = CAddress()
            addr.time = ntime
            addr.nServices = MARKER_SERVICES
            addr.ip = ip
            addr.port = MARKER_PORT
            msg = msg_addr()
            msg.addrs = [addr]
            try:
                peer.send_without_ping(msg)
            except OSError as e:
                # Disconnected while waiting: nothing was sent, so no CSV row.
                print(f"{time.strftime('%FT%TZ', time.gmtime())} send failed ({e}); {ip} not sent", flush=True)
                round_ages.append(age)
                continue
            last_send = now

            writer.writerow({"seq": seq, "send_unix_us": int(now * 1e6), "ntime": ntime, "age_s": age,
                             "addr": f"{ip}:{MARKER_PORT}", "services": MARKER_SERVICES})
            out.flush()
            seq += 1
            sent += 1
            if sent % 30 == 0:
                print(f"{time.strftime('%FT%TZ', time.gmtime())} sent {sent} markers (seq {seq - 1})", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"sent {sent} markers this run; csv: {args.csv}", flush=True)
        out.close()
        if peer.is_connected:
            peer.peer_disconnect()
            peer.wait_for_disconnect(timeout=10)
        network_thread.close(timeout=10)


if __name__ == "__main__":
    main()
