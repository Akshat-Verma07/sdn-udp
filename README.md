# Reliable File Transfer over UDP with SDN Path Control

Computer Networks mini project (SDN–Socket Programming, problem 4).
Python sockets + Mininet + Ryu (OpenFlow 1.3).

## 1. Problem and goals

UDP does not guarantee delivery, order or uniqueness. We build a reliable
file-transfer protocol on top of raw UDP sockets, run it over a Mininet
network that has two disjoint paths, and let an SDN controller handle path
changes (reroute on failure).

| Project bullet | Where it is implemented |
|---|---|
| File transfer using UDP | `src/sender.py`, `src/receiver.py` |
| Sequence numbering | `seq` field in every packet (`src/protocol.py`) |
| Acknowledgments | per-chunk selective ACKs (`receiver.py`) |
| Retransmission and timeout | per-packet timers, adaptive RTO (`sender.py`) |
| Detect missing and duplicate packets | `Session.handle_data` in `receiver.py` |
| Verify file integrity | CRC-32 per packet + SHA-256 of whole file (FIN) |
| Detect path problems using SDN information | `PortStatus` handling in the controller; app stats channel |
| Reroute traffic during failures | `_reevaluate_path` in `controller/sdn_controller.py` |

## 2. Architecture

```
                      +---- s2 ----+          PRIMARY : s1-s2-s4 (5 ms links)
          h1 --- s1 --+            +-- s4 --- h2
       (sender)       +---- s3 ----+        (receiver)
                                            BACKUP  : s1-s3-s4 (15 ms links)
                 ^                              ^
                 |  OpenFlow 1.3                |
                 +------- Ryu controller -------+
                          UDP :9999  <--- sender app stats (retx, RTT)
```

Components: `h1` runs the sender, `h2` runs the receiver, four OVS switches
form the diamond, and one Ryu controller programs them.

## 3. Wire protocol

Every datagram: `magic(1) type(1) session(4) seq(4) len(2) | payload | CRC32(4)`.

| Type | Direction | Meaning |
|---|---|---|
| START / START_ACK | S→R / R→S | file name, size, chunk count |
| DATA / ACK | S→R / R→S | chunk `seq` / selective ack for that `seq` |
| FIN / FIN_ACK | S→R / R→S | SHA-256 of file / 1 = match, 0 = mismatch |

Reliability design (Selective Repeat):
* Sliding window (default 32 chunks of 1024 B).
* One timer per in-flight chunk; only the expired chunk is resent.
* RTO from RFC 6298 (SRTT/RTTVAR), exponential back-off per retry,
  Karn's rule (no RTT sample from retransmitted packets).
* Receiver ACKs duplicates too, because the first ACK may have been lost.
* Corrupted packets fail the CRC and are dropped, then recovered by timeout.
* START and FIN are also retried, since they can be lost.

## 4. Controller behaviour (D1)

* On switch connect: install flows for the active path (match `ipv4_dst`,
  priority 100). Table-miss drops, so nothing floods the loop.
* On `PortStatus` link-down: if the active path uses that port and the other
  path is healthy, reinstall flows on the other path (same match, so the
  new actions replace the old ones).
* UDP :9999 listener logs `app_stats` from the sender (D2 will use these to
  detect degraded paths, not just dead links).

## 5. Setup (Ubuntu VM)

```bash
bash setup_ubuntu.sh
```

## 6. Running

**A. Protocol tests, no Mininet or root needed**
```bash
python3 tests/run_local_tests.py
```
Runs 10 scenarios (clean, 10%/25% loss, duplicates, reordering, corruption,
combined, tiny file, exact-multiple file) through an impairment proxy and
checks the received file is byte-identical.

**B. Full system (two terminals)**
```bash
# Terminal 1
source ~/ryu-venv/bin/activate
ryu-manager controller/sdn_controller.py

# Terminal 2
sudo mn -c                                   # clean old state
sudo python3 topology/diamond_topo.py --transfer --size-mb 5 --tag normal
sudo python3 topology/diamond_topo.py --transfer --size-mb 20 --fail-at 2 --tag failover
```
Expected: in the failover run the controller prints `PORT DOWN` and
`REROUTE: primary -> backup`, the sender shows a burst of timeouts and
retransmissions, then the transfer completes and the SHA-256 is verified.
Results are written to `results/*.json`.

Manual exploration: `sudo python3 topology/diamond_topo.py --cli`, then e.g.
`link s1 s2 down` and `sh ovs-ofctl -O OpenFlow13 dump-flows s1`.

## 7. Test results so far (local, UDP layer only)

All 10 scenarios in `tests/run_local_tests.py` pass (file verified
byte-identical). Example: at 10% loss each way a 500 KB file completes with
119 retransmissions; with loss+duplication+reordering+corruption combined it
still completes with correct SHA-256.

## 8. Status

| Item | Status |
|---|---|
| UDP reliable transfer | done, tested on localhost |
| Mininet topology | written, **not yet run on a real Mininet install** |
| Ryu controller (static path + failover) | written, **not yet run on a real Ryu install** |
| App-stats feedback channel | sender side done, controller logs only |

## 9. Roadmap for D2

1. Run and debug the Mininet + Ryu pieces on your VM (see Troubleshooting).
2. Controller monitoring: poll port/flow stats, use `app_stats` to flag a
   degraded path (high retransmission rate) and reroute without a link failure.
3. Static baseline: same experiments with the controller's rerouting disabled.
4. Experiments: completion time, goodput, retransmissions, recovery time under
   no loss, packet loss (`loss=` on links), link failure, congestion.
5. Graphs plus final write-up.

## 10. Troubleshooting

* `h1 cannot reach h2`: start Ryu first; check it prints `switch s1 connected` …
  `s4 connected`.
* Ryu import errors on new Python: use Python 3.9/3.10 for the virtualenv or
  `eventlet==0.30.2`.
* Stale state: `sudo mn -c`.
* Port-down events not seen: confirm switches use OpenFlow 1.3
  (`ovs-vsctl list bridge`).
