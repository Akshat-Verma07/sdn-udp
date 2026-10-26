#!/usr/bin/env python3
"""
run_local_tests.py - Functional tests of the UDP reliability layer on localhost.

No Mininet/root needed.  For each scenario we start the receiver, optionally
the impairment proxy, run the sender, then check:
   * sender exit code 0 (transfer completed and SHA-256 verified)
   * the received file is byte-identical to the original
Prints a results table and exits non-zero if any scenario fails.

Run:  python3 tests/run_local_tests.py
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
PROXY = os.path.join(ROOT, "tests", "impair_proxy.py")
PY = sys.executable

# name, proxy args (None = direct), file size in bytes
SCENARIOS = [
    ("clean (no proxy)",            None,                                      500_000),
    ("clean via proxy",             [],                                        500_000),
    ("10% loss",                    ["--loss", "0.10"],                        500_000),
    ("25% loss",                    ["--loss", "0.25"],                        300_000),
    ("duplicates 20%",              ["--dup", "0.20"],                         500_000),
    ("reordering 30%",              ["--reorder", "0.30"],                     500_000),
    ("corruption 10%",              ["--corrupt", "0.10"],                     500_000),
    ("loss+dup+reorder+corrupt",    ["--loss", "0.10", "--dup", "0.10",
                                     "--reorder", "0.20", "--corrupt", "0.05"], 500_000),
    ("empty-ish file (100 bytes)",  [],                                        100),
    ("exact chunk multiple",        ["--loss", "0.05"],                        1024 * 100),
]


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def run_scenario(idx, name, proxy_args, size, tmp):
    recv_port = 6000 + idx * 3
    proxy_port = recv_port + 1
    src_file = os.path.join(tmp, "src_%d.bin" % idx)
    outdir = os.path.join(tmp, "out_%d" % idx)
    os.makedirs(outdir)
    with open(src_file, "wb") as f:
        f.write(os.urandom(size))

    rstats = os.path.join(tmp, "r_%d.json" % idx)
    sstats = os.path.join(tmp, "s_%d.json" % idx)

    receiver = subprocess.Popen(
        [PY, os.path.join(SRC, "receiver.py"), "--bind", "127.0.0.1",
         "--port", str(recv_port), "--outdir", outdir, "--once",
         "--linger", "1.0", "--stats", rstats],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    proxy = None
    target_port = recv_port
    if proxy_args is not None:
        proxy = subprocess.Popen(
            [PY, PROXY, "--listen", str(proxy_port), "--to-port", str(recv_port),
             "--seed", str(idx + 7), "--duration", "90"] + proxy_args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        target_port = proxy_port
    time.sleep(0.4)                              # let sockets bind

    t0 = time.time()
    sender = subprocess.run(
        [PY, os.path.join(SRC, "sender.py"), "--file", src_file,
         "--host", "127.0.0.1", "--port", str(target_port),
         "--stats", sstats],
        capture_output=True, text=True, timeout=120)
    elapsed = time.time() - t0

    try:
        receiver.wait(timeout=15)
    except subprocess.TimeoutExpired:
        receiver.kill()
    if proxy:
        proxy.kill()

    same = False
    dst = os.path.join(outdir, os.path.basename(src_file))
    if os.path.exists(dst):
        same = (sha(dst) == sha(src_file))

    s = json.load(open(sstats)) if os.path.exists(sstats) else {}
    r = json.load(open(rstats)) if os.path.exists(rstats) else {}
    passed = (sender.returncode == 0) and same
    return {
        "name": name, "pass": passed, "elapsed": elapsed,
        "retx": s.get("retransmissions"), "timeouts": s.get("timeouts"),
        "dups": r.get("duplicate_packets"), "corrupt": r.get("corrupt_dropped"),
        "gaps": r.get("gaps_detected"), "ooo": r.get("out_of_order_events"),
        "rc": sender.returncode, "stderr": sender.stderr[-300:],
    }


def main():
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, (name, pargs, size) in enumerate(SCENARIOS):
            print("running: %s ..." % name, flush=True)
            rows.append(run_scenario(i, name, pargs, size, tmp))

    print()
    hdr = "%-28s %-5s %7s %6s %7s %6s %7s %6s %5s" % (
        "scenario", "pass", "time(s)", "retx", "timeout", "dups", "corrupt", "gaps", "ooo")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print("%-28s %-5s %7.2f %6s %7s %6s %7s %6s %5s" % (
            r["name"], "PASS" if r["pass"] else "FAIL", r["elapsed"],
            r["retx"], r["timeouts"], r["dups"], r["corrupt"], r["gaps"], r["ooo"]))
        if not r["pass"]:
            print("    rc=%s stderr=%s" % (r["rc"], r["stderr"]))
    ok = all(r["pass"] for r in rows)
    print("\nOVERALL:", "ALL PASSED" if ok else "FAILURES")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
