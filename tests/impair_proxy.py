#!/usr/bin/env python3
"""
impair_proxy.py - A tiny UDP "bad network" for testing WITHOUT Mininet.

Sits between sender and receiver and misbehaves on purpose:
    sender  ->  proxy:LISTEN_PORT  ->  receiver
    sender  <-  proxy              <-  receiver

Impairments (applied independently in BOTH directions, so ACKs get lost too):
    --loss     probability a packet is dropped
    --dup      probability a packet is delivered twice
    --reorder  probability a packet is delayed extra (so it overtakes/trails)
    --corrupt  probability one random bit in the packet is flipped
    --delay    base one-way delay in ms

This lets us exercise every reliability path (timeouts, duplicates, gaps, CRC
failures) on a laptop before moving to the real Mininet topology.
"""

import argparse
import heapq
import random
import select
import socket
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--to-host", default="127.0.0.1")
    ap.add_argument("--to-port", type=int, required=True)
    ap.add_argument("--loss", type=float, default=0.0)
    ap.add_argument("--dup", type=float, default=0.0)
    ap.add_argument("--reorder", type=float, default=0.0)
    ap.add_argument("--corrupt", type=float, default=0.0)
    ap.add_argument("--delay", type=float, default=0.0, help="ms")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--duration", type=float, default=120.0,
                    help="self-terminate after this many seconds")
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    server = (args.to_host, args.to_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", args.listen))
    out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # towards server

    client = None
    queue = []            # heap of (release_time, counter, dest_sock, dest_addr, data)
    counter = 0
    stats = {"seen": 0, "lost": 0, "dup": 0, "reordered": 0, "corrupt": 0}
    end = time.time() + args.duration

    def schedule(data, dest_sock, dest_addr):
        """Apply impairments to one packet and queue it for delivery."""
        nonlocal counter
        stats["seen"] += 1
        if rnd.random() < args.loss:
            stats["lost"] += 1
            return
        if rnd.random() < args.corrupt:
            b = bytearray(data)
            pos = rnd.randrange(len(b))
            b[pos] ^= 1 << rnd.randrange(8)       # flip one random bit
            data = bytes(b)
            stats["corrupt"] += 1
        delay = args.delay / 1000.0
        if rnd.random() < args.reorder:
            delay += rnd.uniform(0.005, 0.03)     # extra jitter -> reorder
            stats["reordered"] += 1
        copies = 1
        if rnd.random() < args.dup:
            copies = 2
            stats["dup"] += 1
        for _ in range(copies):
            counter += 1
            heapq.heappush(queue, (time.time() + delay, counter, dest_sock,
                                   dest_addr, data))

    while time.time() < end:
        timeout = 0.01
        if queue:
            timeout = max(0.0, min(timeout, queue[0][0] - time.time()))
        r, _, _ = select.select([sock, out], [], [], timeout)
        for s in r:
            data, addr = s.recvfrom(65535)
            if s is sock:                       # from the sender
                client = addr
                schedule(data, out, server)
            elif client is not None:            # reply from the receiver
                schedule(data, sock, client)
        now = time.time()
        while queue and queue[0][0] <= now:
            _, _, dsock, daddr, data = heapq.heappop(queue)
            dsock.sendto(data, daddr)

    print("[proxy] stats:", stats)


if __name__ == "__main__":
    main()
