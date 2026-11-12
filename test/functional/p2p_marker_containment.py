#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""EXPERIMENT ONLY. Marker addresses (240.0.0.0/4) must never leave node T.

Stand-in "mainnet" peers (inbound and outbound) must never receive a marker,
through gossip or a GETADDR response, and the node must never dial one. Plain
addresses injected the same way must still relay (positive control).
"""

import time

from test_framework.messages import (
    CAddress,
    CBlockHeader,
    from_hex,
    msg_addr,
    msg_headers,
)
from test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

TAG = "MARKER_T"
LEAK_TAG = "!!MARKER_T_LEAK_BLOCKED"
NUM_MARKERS = 40
NUM_CONTROLS = 20


def is_marker(ip):
    return int(ip.split('.')[0]) >= 240


def addr_msg(addrs):
    msg = msg_addr()
    msg.addrs = addrs
    return msg


def marker_ip(i):
    # Spread markers across /16s, like client A does.
    return f"{241 + i % 13}.{i}.{i % 7}.1"


class AddrObserver(P2PInterface):
    """Stand-in for a mainnet peer: records every address it is sent."""
    def __init__(self):
        super().__init__(support_addrv2=True)
        self.received = []

    def on_addr(self, message):
        self.received.extend(a.ip for a in message.addrs)

    def on_addrv2(self, message):
        self.received.extend(a.ip for a in message.addrs)

    def markers(self):
        with p2p_lock:
            return [ip for ip in self.received if is_marker(ip)]

    def num_controls(self):
        with p2p_lock:
            return len([ip for ip in self.received if not is_marker(ip)])


class MarkerContainmentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def bump(self, seconds):
        self.mocktime += seconds
        self.nodes[0].setmocktime(self.mocktime)

    def make_addr(self, ip, age):
        addr = CAddress()
        addr.time = self.mocktime - age
        addr.nServices = P2P_SERVICES
        addr.ip = ip
        addr.port = 8333
        return addr

    def flush(self, peers):
        # Advance past the addr trickle timer so queued addresses go out.
        for _ in range(3):
            self.bump(10 * 60)
            for p in peers:
                p.sync_with_ping()

    def run_test(self):
        node = self.nodes[0]
        self.mocktime = int(time.time())
        node.setmocktime(self.mocktime)

        self.log.info("Connect stand-in mainnet peers: 3 inbound, 2 outbound")
        observers = []
        for _ in range(3):
            obs = node.add_p2p_connection(AddrObserver())
            # An empty addr message enables addr relay to this inbound peer
            # without using up its one GETADDR response.
            obs.send_and_ping(msg_addr())
            observers.append(obs)
        # Outbound peers announce our tip so they aren't evicted for an old chain.
        tip_header = from_hex(CBlockHeader(), node.getblockheader(node.getbestblockhash(), False))
        for i in range(2):
            obs = node.add_outbound_p2p_connection(AddrObserver(), p2p_idx=i, connection_type="outbound-full-relay")
            obs.send_and_ping(msg_headers([tip_header]))
            observers.append(obs)

        injector = node.add_p2p_connection(P2PInterface())

        self.log.info("Rate-limited markers are logged")
        with node.assert_debug_log([f"{TAG} recv addr=240.200.0.1:8333", "result=rate-limited"]):
            # Fresh connection has 1 token, so 2 of these 3 are rate limited.
            injector.send_and_ping(addr_msg([self.make_addr(f"240.200.0.{i}", 30) for i in (1, 2, 3)]))

        self.log.info("Age boundary: 599s is relay eligible, 600s is not")
        self.bump(11)
        with node.assert_debug_log([f"{TAG} recv addr=240.201.0.1:8333", "age_ms=599000 queue_ms=0 msg_addrs=1 result=processed relay_eligible=1",
                                    f"{TAG} relay addr=240.201.0.1:8333 candidates=5", f"{LEAK_TAG} kind=gossip addr=240.201.0.1:8333"]):
            injector.send_and_ping(addr_msg([self.make_addr("240.201.0.1", 599)]))
        self.bump(11)
        with node.assert_debug_log(["age_ms=600000 queue_ms=0 msg_addrs=1 result=processed relay_eligible=0"],
                                   unexpected_msgs=[f"{TAG} relay addr=240.202.0.1:8333"]):
            injector.send_and_ping(addr_msg([self.make_addr("240.202.0.1", 600)]))

        self.log.info(f"Inject {NUM_MARKERS} markers and {NUM_CONTROLS} plain addresses, one per message, within the rate limit")
        for i in range(NUM_MARKERS + NUM_CONTROLS):
            self.bump(11)
            ip = marker_ip(i) if i < NUM_MARKERS else f"123.123.{i}.1"
            injector.send_and_ping(addr_msg([self.make_addr(ip, 30)]))
        self.flush(observers)

        self.log.info("No stand-in peer received a marker, but plain addresses did relay")
        for obs in observers:
            assert_equal(obs.markers(), [])
        # Each plain address goes to 2 of the 5 stand-ins.
        assert_equal(sum(obs.num_controls() for obs in observers), 2 * NUM_CONTROLS)

        self.log.info("GETADDR responses never carry markers")
        # Every P2PInterface sends getaddr on connect, so the response cache was
        # built while addrman was empty. Restart to rebuild it (addrman persists).
        self.restart_node(0, extra_args=[f"-mocktime={self.mocktime}"])
        with node.assert_debug_log([f"{LEAK_TAG} kind=getaddr"]):
            getaddr_peer = node.add_p2p_connection(AddrObserver())
            getaddr_peer.sync_with_ping()
        self.flush([getaddr_peer])
        assert_equal(getaddr_peer.markers(), [])

        self.log.info("Markers are never dialled")
        with node.assert_debug_log([f"{LEAK_TAG} kind=dial addr=241.1.2.3:8333 conn=manual"]):
            node.addnode("241.1.2.3:8333", "onetry")


if __name__ == '__main__':
    MarkerContainmentTest(__file__).main()
