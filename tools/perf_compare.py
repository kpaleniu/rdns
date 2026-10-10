"""Compare two commits' performance on this machine (TODO.md #203).

    python3 tools/perf_compare.py BASE HEAD OUT_DIR

Linux only (`taskset`, `dnsperf`). Two halves:

- criterion's `answer_path` benches: BASE saved as a baseline, HEAD compared;
- dnsperf against `rdnsd --udp-workers 1`, server and client pinned to one
  CPU each, BASE and HEAD alternated three times, 10 s per run. Throughput
  drifts between server starts (#185), so only alternated runs compare.

Prints a Markdown report and writes raw output under OUT_DIR. Fails on a
build failure or a server that does not answer, never on a slower HEAD.
BASE = HEAD is the A/A run: the spread it shows is this machine's noise.
"""

import json
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

RUNS = 3
SECONDS = 10
PORT = 15353
ZONE = """$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@   IN NS  ns1.example.com.
ns1 IN A   192.0.2.1
www IN A   192.0.2.10
"""
QUERY = bytes.fromhex("424201000001000000000000") + b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"


def run(args, **kw):
    print("+", " ".join(map(str, args)), file=sys.stderr, flush=True)
    # Stdout is the report; a child's chatter goes to stderr.
    if "capture_output" not in kw:
        kw.setdefault("stdout", sys.stderr)
    return subprocess.run(args, check=True, **kw)


def sha(ref):
    return run(["git", "rev-parse", f"{ref}^{{commit}}"], capture_output=True, text=True).stdout.strip()


def build_and_bench(side, commit, out, target, baseline_flag):
    tree = out / f"tree-{side}"
    run(["git", "worktree", "add", "--detach", "--force", tree, commit])
    try:
        env = dict(os.environ, CARGO_TARGET_DIR=str(target))
        run(["cargo", "build", "--release", "--locked", "-p", "rdnsd"], cwd=tree, env=env)
        shutil.copy(target / "release" / "rdnsd", out / f"rdnsd-{side}")
        with open(out / f"criterion-{side}.txt", "w") as log:
            run(
                ["cargo", "bench", "--locked", "-p", "rdns", "--bench", "answer_path", "--",
                 baseline_flag, "base"],
                cwd=tree, env=env, stdout=log, stderr=subprocess.STDOUT,
            )
    finally:
        run(["git", "worktree", "remove", "--force", tree])


def answered():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.2)
        try:
            s.sendto(QUERY, ("127.0.0.1", PORT))
            return len(s.recv(512)) > 12
        except OSError:
            return False


def dnsperf(binary, zone, qfile, server_cpu, client_cpu, log):
    server = subprocess.Popen(
        ["taskset", "-c", str(server_cpu), binary, "--host", "127.0.0.1", "--port", str(PORT),
         "--zone-file", zone, "--udp-workers", "1", "--query-rate", "0", "--response-rate", "0",
         "--quiet"],
        stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 20
        while not answered():
            if server.poll() is not None or time.monotonic() > deadline:
                sys.exit(f"{binary} did not answer on 127.0.0.1:{PORT}")
            time.sleep(0.2)
        result = run(
            ["taskset", "-c", str(client_cpu), "dnsperf", "-s", "127.0.0.1", "-p", str(PORT),
             "-d", qfile, "-l", str(SECONDS), "-c", "16", "-T", "1", "-q", "1000"],
            capture_output=True, text=True,
        ).stdout
        log.write(result)
        qps = re.search(r"Queries per second:\s+([\d.]+)", result)
        if not qps or float(qps.group(1)) == 0:
            sys.exit(f"dnsperf got no answers from {binary}")
        return float(qps.group(1))
    finally:
        server.terminate()
        server.wait()


def criterion_changes(target):
    rows = []
    for est in sorted((target / "criterion").glob("**/change/estimates.json")):
        bench = json.loads((est.parent.parent / "new" / "benchmark.json").read_text())
        mean = json.loads(est.read_text())["mean"]
        rows.append((bench["full_id"], mean["point_estimate"], mean["confidence_interval"]))
    return rows


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    base, head = sha(sys.argv[1]), sha(sys.argv[2])
    out = Path(sys.argv[3]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    target = out / "target"
    shutil.rmtree(target / "criterion", ignore_errors=True)

    cpus = sorted(os.sched_getaffinity(0))
    if len(cpus) < 2:
        sys.exit("needs two CPUs: one for the server, one for dnsperf")
    server_cpu, client_cpu = cpus[0], cpus[1]

    build_and_bench("base", base, out, target, "--save-baseline")
    build_and_bench("head", head, out, target, "--baseline")

    zone = out / "example.com.zone"
    zone.write_text(ZONE)
    qfile = out / "queries.txt"
    qfile.write_text("www.example.com A\n")
    qps = {"base": [], "head": []}
    with open(out / "dnsperf.txt", "w") as log:
        for _ in range(RUNS):
            for side in ("base", "head"):
                log.write(f"\n=== {side}\n")
                log.flush()
                qps[side].append(dnsperf(out / f"rdnsd-{side}", zone, qfile, server_cpu, client_cpu, log))

    print(f"## Performance: `{head[:12]}` against `{base[:12]}`\n")
    print("Relative to this runner only: absolute figures do not travel.\n")
    print(f"### dnsperf, {RUNS} alternated runs of {SECONDS} s, `--udp-workers 1`, "
          f"server on CPU {server_cpu}, client on CPU {client_cpu}\n")
    print("| | q/s | median | range |")
    print("|---|---|---|---|")
    for side in ("base", "head"):
        v = qps[side]
        print(f"| {side} | {', '.join(f'{q:,.0f}' for q in v)} | {statistics.median(v):,.0f} "
              f"| {min(v):,.0f}-{max(v):,.0f} |")
    ratio = statistics.median(qps["head"]) / statistics.median(qps["base"])
    print(f"\nhead / base, medians: **{ratio:.3f}**\n")
    print("### criterion `answer_path`, change in mean time (head against base)\n")
    print("| bench | change | 95% CI |")
    print("|---|---|---|")
    for name, point, ci in criterion_changes(target):
        print(f"| {name} | {point:+.1%} | {ci['lower_bound']:+.1%} to {ci['upper_bound']:+.1%} |")


if __name__ == "__main__":
    main()
