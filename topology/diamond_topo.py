#!/usr/bin/env python3
"""
diamond_topo.py - Mininet topology + experiment runner for Reliable UDP over SDN.

                      +---- s2 ----+          PRIMARY path : s1-s2-s4 (low delay)
          h1 --- s1 --+            +-- s4 --- h2
        10.0.0.1      +---- s3 ----+        10.0.0.2
                                            BACKUP path  : s1-s3-s4 (higher delay)

Port numbering is fixed explicitly so the controller can hard-code it:
    s1: 1=h1   2=s2   3=s3
    s2: 1=s1   2=s4
    s3: 1=s1   2=s4
    s4: 1=h2   2=s2   3=s3

Two disjoint paths give the SDN controller something real to reroute between.
ARP is static (autoStaticArp=True) because the diamond contains a loop: flooding
ARP broadcasts through it would cause a broadcast storm.

Run (needs root, Open vSwitch, and the Ryu controller already running):
    sudo python3 topology/diamond_topo.py --cli                 # explore
    sudo python3 topology/diamond_topo.py --transfer            # one transfer
    sudo python3 topology/diamond_topo.py --transfer --fail-at 2   # cut primary link
                                                                   # 2 s into the transfer
"""

import argparse
import json
import os
import sys
import threading
import time

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
RESULTS = os.path.join(ROOT, "results")


def build_network(controller_ip="127.0.0.1", controller_port=6653,
                  primary_delay="5ms", backup_delay="15ms",
                  bw=10, loss=0):
    """Create the diamond network and return the (not yet started) Mininet."""
    net = Mininet(controller=None, link=TCLink, switch=OVSKernelSwitch,
                  autoSetMacs=True,      # deterministic MACs: 00:..:01, 02, ...
                  autoStaticArp=True)    # no ARP broadcast -> no loop storm

    net.addController("c0", controller=RemoteController,
                      ip=controller_ip, port=controller_port)

    # Switches speak OpenFlow 1.3 to the Ryu app.
    s1, s2, s3, s4 = [net.addSwitch("s%d" % i, protocols="OpenFlow13")
                      for i in range(1, 5)]
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")

    # Host links (fast, so the diamond core is the bottleneck).
    net.addLink(h1, s1, port1=1, port2=1, bw=100)
    net.addLink(h2, s4, port1=1, port2=1, bw=100)

    # PRIMARY path s1 - s2 - s4
    net.addLink(s1, s2, port1=2, port2=1, bw=bw, delay=primary_delay, loss=loss)
    net.addLink(s2, s4, port1=2, port2=2, bw=bw, delay=primary_delay, loss=loss)

    # BACKUP path s1 - s3 - s4
    net.addLink(s1, s3, port1=3, port2=1, bw=bw, delay=backup_delay)
    net.addLink(s3, s4, port1=2, port2=3, bw=bw, delay=backup_delay)
    return net


def run_transfer(net, size_mb, window, fail_at, tag):
    """Start receiver on h2, sender on h1; optionally cut the primary link."""
    os.makedirs(RESULTS, exist_ok=True)
    h1, h2 = net.get("h1"), net.get("h2")

    src_file = os.path.join(RESULTS, "payload_%s.bin" % tag)
    outdir = os.path.join(RESULTS, "received_%s" % tag)
    os.makedirs(outdir, exist_ok=True)
    with open(src_file, "wb") as f:
        f.write(os.urandom(int(size_mb * 1024 * 1024)))

    sstats = os.path.join(RESULTS, "sender_%s.json" % tag)
    rstats = os.path.join(RESULTS, "receiver_%s.json" % tag)

    info("*** Starting receiver on h2\n")
    recv = h2.popen(["python3", os.path.join(SRC, "receiver.py"),
                     "--port", "5005", "--outdir", outdir, "--once",
                     "--linger", "2", "--stats", rstats])
    time.sleep(1)

    if fail_at is not None:
        # Cut the primary link s1<->s2 part-way through the transfer.  The
        # controller should see the port-down event and move traffic to the
        # backup path; the sender's retransmissions bridge the gap.
        def cut():
            info("*** LINK FAILURE: s1 <-> s2 DOWN\n")
            net.configLinkStatus("s1", "s2", "down")
        threading.Timer(fail_at, cut).start()

    info("*** Starting sender on h1\n")
    t0 = time.time()
    # Report app stats to the controller. h1 has its own network namespace, so
    # 127.0.0.1 would be h1's own loopback; a filesystem Unix socket is shared
    # between all namespaces, so it reaches the controller in the root ns.
    send = h1.popen(["python3", os.path.join(SRC, "sender.py"),
                     "--file", src_file, "--host", "10.0.0.2",
                     "--window", str(window), "--stats", sstats,
                     "--report", "unix:/tmp/sdn_app_stats.sock"])
    out, _ = send.communicate()
    elapsed = time.time() - t0
    recv.wait(timeout=15)
    if out:
        print(out.decode(errors="replace"))
    info("*** Transfer wall time: %.2f s (sender exit code %s)\n"
         % (elapsed, send.returncode))
    if os.path.exists(sstats):
        print(json.dumps(json.load(open(sstats)), indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--controller-ip", default="127.0.0.1")
    ap.add_argument("--controller-port", type=int, default=6653)
    ap.add_argument("--cli", action="store_true", help="drop to Mininet CLI")
    ap.add_argument("--transfer", action="store_true", help="run one transfer")
    ap.add_argument("--size-mb", type=float, default=5.0)
    ap.add_argument("--window", type=int, default=32)
    ap.add_argument("--fail-at", type=float, default=None,
                    help="seconds after sender start to take s1-s2 down")
    ap.add_argument("--tag", default="run")
    args = ap.parse_args()

    setLogLevel("info")
    net = build_network(args.controller_ip, args.controller_port)
    net.start()
    try:
        info("*** Waiting for the controller to install flows\n")
        time.sleep(3)
        info("*** Connectivity check\n")
        if net.ping([net.get("h1"), net.get("h2")]) > 0:
            info("!!! h1 cannot reach h2 - is the Ryu controller running?\n")
            if not args.cli:
                sys.exit(1)
        if args.transfer:
            run_transfer(net, args.size_mb, args.window, args.fail_at, args.tag)
        if args.cli or not args.transfer:
            CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
