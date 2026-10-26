#!/usr/bin/env python3
"""
sender.py - Reliable UDP file-transfer SENDER (client side).

Reliability mechanisms implemented here:
  * SEQUENCE NUMBERS : the file is cut into fixed-size chunks; chunk i is sent
    in a DATA packet with seq = i.
  * ACKNOWLEDGMENTS  : the receiver ACKs every chunk individually
    (Selective Repeat), so we always know exactly which chunks got through.
  * SLIDING WINDOW   : up to --window chunks may be unacknowledged at once, so
    the pipe stays full instead of waiting one RTT per packet.
  * TIMEOUT + RETRANSMISSION : every in-flight chunk has its own timer; if the
    ACK has not arrived when the timer fires, only THAT chunk is resent.
  * ADAPTIVE RTO     : the retransmission timeout follows the measured RTT
    using the standard RFC 6298 estimator (SRTT / RTTVAR), with exponential
    back-off per retry and Karn's rule (never take an RTT sample from a
    retransmitted packet, because we cannot tell which copy was ACKed).
  * INTEGRITY        : after all chunks are ACKed we send FIN carrying the
    SHA-256 of the file; the receiver compares it with what it reassembled.

Usage:
    python3 sender.py --file data.bin --host 10.0.0.2 --port 5005
"""

import argparse
import hashlib
import json
import os
import random
import select
import socket
import sys
import time

import protocol as P

# ---- RTO estimator constants (RFC 6298) -----------------------------------
ALPHA = 1 / 8          # SRTT smoothing factor
BETA = 1 / 4           # RTTVAR smoothing factor
K = 4                  # RTO = SRTT + K * RTTVAR
MIN_RTO = 0.05         # 50 ms floor (RFC says 1 s; far too slow for a LAN)
MAX_RTO = 2.0          # cap on back-off so recovery after a reroute is quick
INITIAL_RTO = 0.3
MAX_RETRIES = 40       # per packet, before we give up on the transfer


class TransferError(Exception):
    pass


class RtoEstimator:
    """Adaptive retransmission timeout (RFC 6298 style)."""

    def __init__(self):
        self.srtt = None
        self.rttvar = None
        self.rto = INITIAL_RTO

    def sample(self, rtt):
        """Feed in one RTT measurement (from a never-retransmitted packet)."""
        if self.srtt is None:                      # first sample
            self.srtt = rtt
            self.rttvar = rtt / 2
        else:
            self.rttvar = (1 - BETA) * self.rttvar + BETA * abs(self.srtt - rtt)
            self.srtt = (1 - ALPHA) * self.srtt + ALPHA * rtt
        self.rto = min(MAX_RTO, max(MIN_RTO, self.srtt + K * self.rttvar))


class ReliableSender:
    def __init__(self, sock, dest, session_id, window, report=None):
        self.sock = sock
        self.dest = dest
        self.session = session_id
        self.window = window
        self.est = RtoEstimator()
        self.report = report              # optional (host, port) for SDN stats
        self.last_report = 0.0
        self.stats = {
            "data_packets_sent": 0,       # includes retransmissions
            "retransmissions": 0,
            "timeouts": 0,
            "acks_received": 0,
            "duplicate_acks": 0,
            "bad_packets_dropped": 0,
        }
        self.rtt_samples = []

    # ------------------------------------------------------------------
    def _recv_packet(self, timeout):
        """Wait up to `timeout` s for one valid packet for our session.
        Returns (ptype, seq, payload) or None."""
        r, _, _ = select.select([self.sock], [], [], max(0.0, timeout))
        if not r:
            return None
        data, _addr = self.sock.recvfrom(P.MAX_PACKET)
        try:
            ptype, session, seq, payload = P.parse_packet(data)
        except P.PacketError:
            self.stats["bad_packets_dropped"] += 1
            return None
        if session != self.session:
            return None                       # stale packet from another run
        return ptype, seq, payload

    def _handshake(self, ptype_out, payload, ptype_expected, what):
        """Send a control packet and wait for its reply, retrying on timeout
        (START/FIN themselves can be lost too!).  Returns the reply seq."""
        pkt = P.build_packet(ptype_out, self.session, 0, payload)
        rto = INITIAL_RTO
        for attempt in range(MAX_RETRIES):
            self.sock.sendto(pkt, self.dest)
            deadline = time.time() + rto
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                got = self._recv_packet(remaining)
                if got and got[0] == ptype_expected:
                    return got[1]
                # Late ACKs for DATA arriving during FIN wait are ignored.
            rto = min(MAX_RTO, rto * 2)       # back off
        raise TransferError("no reply to %s after %d tries" % (what, MAX_RETRIES))

    # ------------------------------------------------------------------
    def _maybe_report(self, now, sent_unique, total, force=False):
        """Send a small JSON stats datagram to the SDN controller (optional).

        This is the application -> network feedback channel: the controller
        can use retransmission rate / RTT to decide a path is degraded.
        """
        if not self.report:
            return
        if not force and now - self.last_report < 1.0:
            return
        self.last_report = now
        msg = {
            "type": "app_stats", "session": self.session, "ts": now,
            "acked": sent_unique, "total": total,
            "retransmissions": self.stats["retransmissions"],
            "timeouts": self.stats["timeouts"],
            "srtt": self.est.srtt, "rto": self.est.rto,
        }
        try:
            if isinstance(self.report, str):        # Unix datagram socket path
                us = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                try:
                    us.sendto(json.dumps(msg).encode(), self.report)
                finally:
                    us.close()
            else:                                   # (host, port) over UDP
                self.sock.sendto(json.dumps(msg).encode(), self.report)
        except OSError:
            pass

    # ------------------------------------------------------------------
    def send_file(self, path, verbose=False):
        filename = os.path.basename(path)
        with open(path, "rb") as f:
            blob = f.read()
        size = len(blob)
        chunks = [blob[i:i + P.CHUNK_SIZE] for i in range(0, size, P.CHUNK_SIZE)]
        n = len(chunks)
        digest = hashlib.sha256(blob).hexdigest()

        print("[sender] file=%s size=%d bytes chunks=%d window=%d sha256=%s"
              % (filename, size, n, self.window, digest[:16] + "..."), flush=True)

        t0 = time.time()

        # ---- 1. START handshake -------------------------------------------
        self._handshake(P.T_START, P.encode_start(filename, size, n),
                        P.T_START_ACK, "START")

        # ---- 2. Selective-Repeat data phase -------------------------------
        acked = [False] * n          # acked[i] -> chunk i confirmed
        sent_at = [0.0] * n          # time of the most recent transmission
        tx_count = [0] * n           # how many times chunk i has been sent
        deadline = [0.0] * n         # when chunk i's retransmit timer fires
        base = 0                     # lowest un-ACKed seq (window left edge)
        next_seq = 0                 # next never-sent seq
        acked_count = 0

        def transmit(i, now):
            """(Re)send chunk i and (re)arm its timer."""
            self.sock.sendto(P.build_packet(P.T_DATA, self.session, i, chunks[i]),
                             self.dest)
            tx_count[i] += 1
            sent_at[i] = now
            # Exponential back-off per retry of THIS packet.
            backoff = min(MAX_RTO, self.est.rto * (2 ** (tx_count[i] - 1)))
            deadline[i] = now + backoff
            self.stats["data_packets_sent"] += 1
            if tx_count[i] > 1:
                self.stats["retransmissions"] += 1

        while base < n:
            now = time.time()

            # (a) Fill the window with fresh chunks.
            while next_seq < n and next_seq < base + self.window:
                transmit(next_seq, now)
                next_seq += 1

            # (b) Sleep until an ACK arrives or the earliest timer fires.
            in_flight = [i for i in range(base, next_seq) if not acked[i]]
            wait = min(deadline[i] for i in in_flight) - now if in_flight else 0.05
            got = self._recv_packet(wait)

            # (c) Process every ACK that is already waiting in the socket.
            while got:
                ptype, seq, _ = got
                if ptype == P.T_ACK and 0 <= seq < n:
                    self.stats["acks_received"] += 1
                    if acked[seq]:
                        self.stats["duplicate_acks"] += 1
                    else:
                        acked[seq] = True
                        acked_count += 1
                        # Karn's rule: only sample RTT if never retransmitted.
                        if tx_count[seq] == 1:
                            rtt = time.time() - sent_at[seq]
                            self.est.sample(rtt)
                            self.rtt_samples.append(rtt)
                        # Slide the window past contiguous ACKed chunks.
                        while base < n and acked[base]:
                            base += 1
                got = self._recv_packet(0)      # non-blocking drain

            # (d) Retransmit every in-flight chunk whose timer has expired.
            now = time.time()
            for i in range(base, next_seq):
                if not acked[i] and deadline[i] <= now:
                    if tx_count[i] >= MAX_RETRIES:
                        raise TransferError(
                            "chunk %d unacknowledged after %d tries"
                            % (i, MAX_RETRIES))
                    self.stats["timeouts"] += 1
                    transmit(i, now)
                    if verbose:
                        print("[sender] timeout -> retransmit seq=%d (try %d)"
                              % (i, tx_count[i]))

            self._maybe_report(now, acked_count, n)

        # ---- 3. FIN: send whole-file hash, wait for verdict ---------------
        verdict = self._handshake(P.T_FIN, digest.encode(), P.T_FIN_ACK, "FIN")
        elapsed = time.time() - t0
        ok = (verdict == 1)
        self._maybe_report(time.time(), acked_count, n, force=True)

        result = dict(self.stats)
        result.update({
            "file": filename, "size_bytes": size, "chunks": n,
            "window": self.window, "elapsed_s": elapsed,
            "goodput_mbps": (size * 8 / elapsed / 1e6) if elapsed > 0 else 0,
            "retransmission_rate": (self.stats["retransmissions"] /
                                    max(1, self.stats["data_packets_sent"])),
            "avg_rtt_ms": (1000 * sum(self.rtt_samples) / len(self.rtt_samples)
                           if self.rtt_samples else None),
            "final_rto_ms": 1000 * self.est.rto,
            "integrity_ok": ok,
            "sha256": digest,
        })
        return result


def main():
    ap = argparse.ArgumentParser(description="Reliable UDP file sender")
    ap.add_argument("--file", required=True)
    ap.add_argument("--host", required=True, help="receiver IP address")
    ap.add_argument("--port", type=int, default=P.DEFAULT_PORT)
    ap.add_argument("--window", type=int, default=32,
                    help="max unacknowledged chunks in flight")
    ap.add_argument("--report", default=None, metavar="HOST:PORT | unix:/path",
                    help="send periodic app stats to the SDN controller")
    ap.add_argument("--stats", default=None, help="write result JSON here")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)

    report = None
    if args.report:
        if args.report.startswith("unix:"):
            report = args.report[5:]
        else:
            rh, rp = args.report.rsplit(":", 1)
            report = (rh, int(rp))

    session_id = random.getrandbits(32)
    sender = ReliableSender(sock, (args.host, args.port), session_id,
                            args.window, report)
    try:
        result = sender.send_file(args.file, args.verbose)
    except TransferError as exc:
        print("[sender] TRANSFER FAILED: %s" % exc, file=sys.stderr)
        sys.exit(2)

    print("[sender] done: %s" % json.dumps(result, indent=2))
    if args.stats:
        with open(args.stats, "w") as f:
            json.dump(result, f, indent=2)
    print("[sender] integrity %s" % ("VERIFIED" if result["integrity_ok"]
                                      else "FAILED"))
    sys.exit(0 if result["integrity_ok"] else 3)


if __name__ == "__main__":
    main()
