#!/usr/bin/env bash
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# EXPERIMENT ONLY. The experiment binaries keep their addrman in
# peers-marker.dat, never peers.dat, so a stock bitcoind can't load a marker.
#
#   prepare  copy peers.dat to peers-marker.dat and record peers.dat's sha256
#   finish   check peers.dat is byte-for-byte unchanged since prepare
#
# Both refuse to run while bitcoind holds the datadir.
#
# Usage: peersdat.sh prepare|finish <datadir>
#   <datadir> is the directory holding peers.dat (for mainnet, the datadir itself).

set -euo pipefail

if [ $# -ne 2 ] || { [ "$1" != prepare ] && [ "$1" != finish ]; }; then
    echo "Usage: $0 prepare|finish <datadir>" >&2
    exit 1
fi
cmd=$1
dir=$2
peers="$dir/peers.dat"
marker="$dir/peers-marker.dat"
hashfile="$dir/peers.dat.pre-marker.sha256"

sha256() {
    if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

running() {
    if [ -f "$dir/bitcoind.pid" ] && kill -0 "$(cat "$dir/bitcoind.pid")" 2>/dev/null; then return 0; fi
    # bitcoind keeps <datadir>/.lock open while running (also covers a -pid elsewhere).
    if command -v lsof >/dev/null && [ -e "$dir/.lock" ] && [ -n "$(lsof -t "$dir/.lock" 2>/dev/null)" ]; then return 0; fi
    return 1
}

if running; then
    echo "bitcoind is running on $dir; stop it first" >&2
    exit 1
fi
command -v lsof >/dev/null || echo "warning: lsof not found, only checked $dir/bitcoind.pid; make sure bitcoind is stopped" >&2

case $cmd in
prepare)
    [ -f "$peers" ] || { echo "no $peers" >&2; exit 1; }
    [ -e "$marker" ] && { echo "$marker already exists (from an earlier run?); move it away first" >&2; exit 1; }
    cp -p "$peers" "$marker"
    sha256 "$peers" > "$hashfile"
    echo "copied $peers -> $marker; peers.dat sha256 $(cat "$hashfile")"
    ;;
finish)
    [ -f "$hashfile" ] || { echo "no $hashfile; was prepare run?" >&2; exit 1; }
    if [ "$(sha256 "$peers")" = "$(cat "$hashfile")" ]; then
        echo "OK: $peers unchanged since prepare (sha256 $(cat "$hashfile"))"
        echo "$marker holds markers; stock bitcoind never reads it. Keep it for analysis or delete it."
    else
        echo "CHANGED: $peers differs from prepare. A stock bitcoind ran on this datadir during the run?" >&2
        exit 1
    fi
    ;;
esac
