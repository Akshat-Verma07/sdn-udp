#!/usr/bin/env python3
"""
receiver.py - Reliable UDP file-transfer RECEIVER (server side).

Responsibilities (these map directly to the project bullets):
  * Receive file chunks over a plain UDP socket.
  * Verify every packet's CRC-32  -> corrupted packets are dropped silently.
  * Send a SELECTIVE ACK for every valid DATA packet (even duplicates, because
    the earlier ACK may have been the thing that got lost).
  * Detect DUPLICATE packets (same seq arrives twice) and MISSING packets
    (gaps in the sequence numbers).
  * Reassemble the file by writing each chunk at offset seq * chunk_size, so
    out-of-order arrival is not a problem.
  * Verify FILE INTEGRITY: compare the SHA-256 of the reassembled file with the
    digest the sender puts in the FIN packet.

Usage:
    python3 receiver.py --port 5005 --outdir ./received [--once]
"""

import argparse
import hashlib
import json
import os
import socket
import sys
import time

import protocol as P


class Session:
    """State for one in-progress (or just-finished) file transfer."""

    def __init__(self, session_id, meta, outdir):
        self.id = session_id
        self.filename = os.path.basename(meta["filename"])  # no path traversal
        self.size = int(meta["size"])
        self.chunks = int(meta["chunks"])
        self.chunk_size = int(meta["chunk_size"])
        self.path = os.path.join(outdir, self.filename)

        # Open for read+write, truncating any old file.  We write each chunk at
        # its own offset, so arrival order does not matter.
        self.fh = open(self.path, "wb+")

        self.received = set()        # sequence numbers stored so far
        self.highest_seq = -1        # highest seq seen (for gap detection)
        self.start_time = time.time()
        self.finished = False
        self.integrity_ok = None     # filled in when FIN is processed

        # Statistics -------------------------------------------------------
        self.stats = {
            "unique_packets": 0,
            "duplicate_packets": 0,       # same chunk seen again
            "corrupt_dropped": 0,         # failed CRC (counted in main loop)
            "out_of_order_events": 0,     # a seq arrived after a higher one
            "gaps_detected": 0,           # times a gap (missing seqs) was seen
            "missing_seqs_seen": 0,       # total seqs skipped over at the time
        }

    def handle_data(self, seq, payload):
        """Store one DATA chunk.  Returns True if it was new, False if dup."""
        if seq >= self.chunks:
            return False                       # out-of-range seq: ignore

        if seq in self.received:
            # DUPLICATE: we already have this chunk.  Do not rewrite it, but
            # the caller will still ACK it (the sender evidently missed the
            # first ACK, otherwise it would not have retransmitted).
            self.stats["duplicate_packets"] += 1
            return False

        # ---- Missing / out-of-order detection ----------------------------
        if seq > self.highest_seq + 1:
            # We jumped over one or more sequence numbers -> a gap.  Those
            # chunks are missing (lost, or just delayed/reordered).
            skipped = seq - self.highest_seq - 1
            self.stats["gaps_detected"] += 1
            self.stats["missing_seqs_seen"] += skipped
        if seq < self.highest_seq:
            # Arrived after a higher-numbered chunk: reordering or a
            # retransmission filling an earlier gap.
            self.stats["out_of_order_events"] += 1
        self.highest_seq = max(self.highest_seq, seq)

        # Write the chunk at its file offset.
        self.fh.seek(seq * self.chunk_size)
        self.fh.write(payload)
        self.received.add(seq)
        self.stats["unique_packets"] += 1
        return True

    def missing(self):
        """Sequence numbers we still have not received."""
        return sorted(set(range(self.chunks)) - self.received)

    def sha256(self):
        """Hash the reassembled file from disk (streamed, constant memory)."""
        self.fh.flush()
        h = hashlib.sha256()
        with open(self.path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
        return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Reliable UDP file receiver")
    ap.add_argument("--bind", default="0.0.0.0", help="address to bind to")
    ap.add_argument("--port", type=int, default=P.DEFAULT_PORT)
    ap.add_argument("--outdir", default="./received")
    ap.add_argument("--once", action="store_true",
                    help="exit after one completed transfer")
    ap.add_argument("--linger", type=float, default=3.0,
                    help="seconds to keep answering after FIN (so a lost "
                         "FIN_ACK can be re-sent)")
    ap.add_argument("--stats", default=None,
                    help="write receiver statistics JSON to this file")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Large kernel buffer so bursts of DATA are not dropped by the OS itself.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind((args.bind, args.port))
    sock.settimeout(0.5)       # wake up regularly to check the linger timer
    print("[receiver] listening on %s:%d" % (args.bind, args.port), flush=True)

    sess = None                # current Session (or None)
    corrupt_total = 0
    finished_at = None         # time FIN was processed (for linger)

    while True:
        # ---- exit condition for --once ------------------------------------
        if (args.once and finished_at is not None
                and time.time() - finished_at > args.linger):
            break

        try:
            data, addr = sock.recvfrom(P.MAX_PACKET)
        except socket.timeout:
            continue

        # ---- 1. Validate packet (CRC, magic, length) ---------------------
        try:
            ptype, session, seq, payload = P.parse_packet(data)
        except P.PacketError as exc:
            # Corrupted/garbage datagram: DROP it.  Sender will time out and
            # retransmit, exactly as if the packet had been lost.
            corrupt_total += 1
            if sess:
                sess.stats["corrupt_dropped"] += 1
            if args.verbose:
                print("[receiver] dropped bad packet: %s" % exc)
            continue

        # ---- 2. START: begin (or re-confirm) a session --------------------
        if ptype == P.T_START:
            try:
                meta = P.decode_start(payload)
            except P.PacketError as exc:
                print("[receiver] bad START ignored: %s" % exc)
                continue
            if sess is None or sess.id != session:
                if sess is not None and not sess.finished:
                    print("[receiver] new session replaces unfinished one")
                if sess is not None:
                    sess.fh.close()
                sess = Session(session, meta, args.outdir)
                finished_at = None
                print("[receiver] START session=%08x file=%s size=%d chunks=%d"
                      % (session, sess.filename, sess.size, sess.chunks),
                      flush=True)
            # ACK the START every time it arrives (the previous START_ACK
            # might have been lost, which is why we got a duplicate START).
            sock.sendto(P.build_packet(P.T_START_ACK, session), addr)
            continue

        # Everything below requires an active session with a matching id.
        if sess is None or sess.id != session:
            continue

        # ---- 3. DATA: store chunk and acknowledge it ----------------------
        if ptype == P.T_DATA:
            sess.handle_data(seq, payload)
            # SELECTIVE ACK: acknowledge exactly this sequence number, new or
            # duplicate.  Always ACK so the sender can stop retransmitting.
            sock.sendto(P.build_packet(P.T_ACK, session, seq), addr)
            if args.verbose and len(sess.received) % 200 == 0:
                print("[receiver] %d/%d chunks" %
                      (len(sess.received), sess.chunks))

        # ---- 4. FIN: verify integrity and answer ---------------------------
        elif ptype == P.T_FIN:
            miss = sess.missing()
            if miss:
                # Sender thinks it is done but we are missing chunks (should
                # not happen with per-chunk ACKs, but be defensive).  Answer
                # "not OK" and keep waiting for retransmissions.
                print("[receiver] FIN but %d chunks missing" % len(miss))
                sock.sendto(P.build_packet(P.T_FIN_ACK, session, 0), addr)
                continue

            digest_expected = payload.decode(errors="replace")
            digest_actual = sess.sha256()
            ok = (digest_expected == digest_actual)
            if not sess.finished:
                elapsed = time.time() - sess.start_time
                sess.finished = True
                sess.integrity_ok = ok
                finished_at = time.time()
                print("[receiver] FIN: integrity %s  (%d bytes, %.2fs)"
                      % ("OK" if ok else "FAILED", sess.size, elapsed),
                      flush=True)
                print("[receiver] expected sha256 %s" % digest_expected)
                print("[receiver] actual   sha256 %s" % digest_actual)
                print("[receiver] stats: %s" % json.dumps(sess.stats))
                if args.stats:
                    out = dict(sess.stats)
                    out.update({
                        "filename": sess.filename, "size": sess.size,
                        "integrity_ok": ok, "elapsed_s": elapsed,
                        "sha256": digest_actual,
                    })
                    with open(args.stats, "w") as f:
                        json.dump(out, f, indent=2)
            # Always (re)send FIN_ACK; the sender keeps retrying FIN until it
            # hears one, and the previous FIN_ACK may have been lost.
            sock.sendto(P.build_packet(P.T_FIN_ACK, session, 1 if ok else 0),
                        addr)

    if sess is not None:
        sess.fh.close()
    sys.exit(0 if (sess and sess.integrity_ok) else 1)


if __name__ == "__main__":
    main()
