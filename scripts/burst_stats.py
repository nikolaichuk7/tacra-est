#!/usr/bin/env python3
"""Statistics of a run's report burst (drill D8), computed from drills.json, for the Handle
Lifetime text of the draft. Every number the draft quotes about the burst comes from here.

    python3 scripts/burst_stats.py evidence/<stamp>/drills.json [...]

What D8 times: the SNP_GET_EXT_REPORT ioctl alone (impl/tee.py, last_ioctl_ms), 200 times in a
row with REPORT_DATA of zeroes. A call counts as stalled above 1 s. For a stalled call the stall
is compared with the Linux guest driver's retry sleep: on a host "busy" answer the driver sleeps
SNP_REQ_RETRY_DELAY = 2 s and retries, and gives up after SNP_REQ_MAX_RETRY_DURATION = 60 s
(Linux 7.0, arch/x86/include/asm/sev.h lines 159-160; arch/x86/coco/sev/core.c lines 1831-1841).

One exception. The first hardware run, 20260926T165938Z (evidence/20260926T165724Z-gcp-sev-snp),
ran the code of commit 8836e0f, whose Attester downloaded AMD's certificate chain from the KDS for
every report and whose burst timed the whole call; its per-report times are the implementation's
of that day, not the chip's. The bare ioctl is timed from commit 78dc60f on.
"""
WHOLE_CALL_RUNS = {"20260926T165938Z"}
import json
import math
import statistics
import sys

RETRY_S = 2.0


def stats(path):
    d = json.load(open(path))
    b = d["drills"]["D8_report_burst"]
    t = b["per_call_ms"]
    stalled = [(i + 1, ms) for i, ms in enumerate(t) if ms > 1000.0]
    fast = [ms for ms in t if ms <= 1000.0]
    idx = [i for i, _ in stalled]
    gaps = sorted({b - a for a, b in zip(idx, idx[1:])})
    full = [ms for i, ms in stalled if i != idx[0]]          # the first stall may be partial
    sleeps = sorted({math.floor(ms / 1000.0 / RETRY_S) for _, ms in stalled})
    total_s = sum(t) / 1000.0
    return {
        "run": d["stamp"], "host": d.get("host", "").split(".")[0], "n": len(t),
        "timed": "whole call, with KDS download" if d["stamp"] in WHOLE_CALL_RUNS else "ioctl alone",
        "unstalled_n": len(fast), "unstalled_median_ms": round(statistics.median(fast), 2),
        "unstalled_p95_ms": round(sorted(fast)[math.ceil(0.95 * len(fast)) - 1], 2),
        "unstalled_max_ms": round(max(fast), 2),
        "stalled_n": len(stalled), "stalled_indices_first": idx[:3], "gap_between_stalls": gaps,
        "stall_min_s_excluding_first": round(min(full) / 1000.0, 2) if full else None,
        "stall_max_s": round(max(ms for _, ms in stalled) / 1000.0, 2),
        "retry_sleeps_per_stall": sleeps,
        "sum_of_calls_s": round(total_s, 1), "wall_clock_s": b["total_s"],
        "reports_per_s": round(len(t) / b["total_s"], 3),
    }


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(json.dumps(stats(p), sort_keys=False))
