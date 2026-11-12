# Marker-address relay experiment (EXPERIMENT ONLY, never merge)

Client A injects class E "marker" addresses (`240.0.0.0/4`) into node 1, and node 1
gossips them. Node 1 may send markers only to T, over its manual outbound connection
to `-markerpeer` (default `137.184.134.174:8333`). T sends them to no one. Every attempt
to send or dial a marker elsewhere is blocked and logged.

| Branch | Runs on | Log tags |
|---|---|---|
| `2026-11-marker-nodeT` | T | `MARKER_T`, `!!MARKER_T_LEAK_BLOCKED` |
| `2026-11-marker-node1` | node 1, plus client A (`client_a.py`) | `MARKER_N1`, `MARKER_N1_LEAK_BLOCKED` |

Both binaries keep their addrman in `peers-marker.dat`, a copy of `peers.dat`. The
real `peers.dat` is never written, so a stock `bitcoind` can never load a marker,
even after a crash and auto-restart. On mainnet, the experiment binary refuses to
start if `peers-marker.dat` is missing.

## Before

1. **T, at least 30 min before node 1.**
   1. Stop T and run `peersdat.sh prepare <datadir>`.
   2. Start the T branch's `bitcoind` with your usual config plus `-logtimemicros=1`
      and `-whitelist=noban@<node 1's public IP>`. `noban` only keeps T from
      evicting node 1. It does not lift the addr rate limit, so hop 2 is unaffected.
   3. Wait until it is synced.
2. **Clock logs, on both machines, for the whole run.**
   - T: `while true; do date -u +%FT%T.%NZ; chronyc tracking | grep -E 'System time|Last offset'; sleep 300; done >> clock-T.log &`.
     Without chrony, use `timedatectl timesync-status`.
   - Node 1 (macOS): `while true; do date -u +%FT%TZ; sntp time.apple.com; sleep 300; done >> clock-node1.log &`.
3. **Node 1.**
   1. Stop it and run `peersdat.sh prepare <datadir>`. Run `caffeinate -dimsu &`.
   2. Start the node-1 branch's `bitcoind` with your usual config plus
      `-addnode=137.184.134.174:8333 -logtimemicros=1`.
   3. As soon as `debug.log` shows
      `MARKER_N1 allowed peer connected ... conn=manual ip=137.184.134.174:8333`,
      start A. Starting then captures the low-`candidates` ramp. If node 1
      accepts no inbound connections, `candidates` levels off at about 9–10.

Don't feed `getnodeaddresses` or `getrawaddrman` output from either node to anything
outside your machines during the run. RPC is not filtered.

## Run

```
contrib/marker-experiment/client_a.py --csv markers-sent.csv
```

A sends one marker per message, every 11 s, just after a whole second (about 327
markers an hour). Ages default to `599,598,597,593,587,579,568,552,531,495` seconds, in
shuffled rounds. A reconnects if node 1 drops it. Ctrl-C stops A. Rerunning with the
same `--csv` continues the sequence and never reuses an address.

## Containment checks (any time)

- On both nodes, `grep -cE 'kind=(guard|self)' debug.log` should be 0.
  - `guard` means an earlier filter missed a path.
  - `self` means a peer reported a 240/4 address as ours. It was blocked, but note it.
- On node 1, `grep 'MARKER_N1 send ' debug.log | grep -vc 'conn=manual ip=137.184.134.174:8333'`
  must be 0.
- `grep -E 'Excessive logging|Restarting logging' debug.log` should be empty. If it
  isn't, the log rate limiter dropped marker lines.

## After

1. Stop A.
2. On both nodes, run `bitcoin-cli getrawaddrman > addrman-end-<node>.json`.
3. Stop both nodes, then run `peersdat.sh finish <datadir>` on both. It confirms
   `peers.dat` is untouched. After that, stock binaries can start as usual.
4. Hand back:
   - both `debug.log`s;
   - `markers-sent.csv`;
   - both clock logs;
   - both `addrman-end-*.json`.

## Log lines

On T the tags are `MARKER_T` and `!!MARKER_T_LEAK_BLOCKED`. Times are in
microseconds (`t_us`) or milliseconds (`*_ms`). Ages are `now - nTime`.

| Line | Where | Meaning |
|---|---|---|
| `recv ... result=processed` | both | Marker processed. `age_ms` is measured on the same clock value as the 10-minute relay check. `queue_ms` is the time from socket read to processing. `msg_addrs` is the message size. `relay_eligible` is the relay decision; at T this is hop 2. `tokens` is the rate-limit bucket after this address. |
| `recv ... result=rate-limited` | both | Dropped by the sender's addr rate limit, before the relay check. |
| `relay ... candidates=N` | both | RelayAddress ran. N is the number of eligible peers. `pickK` lists the chosen peers, each with `allowed=`. |
| `*_LEAK_BLOCKED kind=gossip` | both | A pick that wasn't allowed. The push was dropped. |
| `*_LEAK_BLOCKED kind=getaddr` | both | Markers removed from a GETADDR response. `addrs=` lists them. |
| `*_LEAK_BLOCKED kind=dial` | both | An outbound or feeler dial to a marker was skipped, and counted as a failed attempt. |
| `*_LEAK_BLOCKED kind=self` | both | A self-announcement of a 240/4 address was skipped. |
| `*_LEAK_BLOCKED kind=guard` | both | The final guard dropped a marker. This should never happen. |
| `addrman ... slot=` | both | The add outcome: `empty`, `self`, `evicted:<occupant>` or `kept:<occupant>`, with the occupant's terrible, refcount and marker flags. `existing=1` means the address was already known. |
| `addrman-removed` | both | A stored marker was later pushed out of a new-table slot. |
| `send ...` | node 1 | Marker serialized to T. `t_us` is the send time, `msg_addrs` the batch size, and `min_ping_us` is INT64_MAX until the first pong. |
| `send-skipped ... already-known` | node 1 | Marker dropped by T's known-address filter. |
| `allowed peer connected/disconnected` | node 1 | The connection to T. |
