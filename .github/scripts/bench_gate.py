#!/usr/bin/env python3
"""Fail when any benchmark regressed beyond threshold since the baseline.

Compares mean point estimates by benchmark name between two
`critcmp --export` JSON files (base first, new second) and fails when a
benchmark's ratio exceeds `threshold` **after normalizing by the run's
machine factor** — the median ratio across all common benchmarks.

Why normalize: GitHub-hosted runners vary by CPU and region between
runs, so a machine-level speed difference shifts *every* ratio
together (observed: a 1.0–1.44x uniform shift across crates untouched
by the diff, tripping the raw gate). The median is dominated by
unchanged code, so `ratio / median` cancels the machine and leaves
per-benchmark regressions. Blind spot: a *global* regression that
slows every benchmark by the same factor is indistinguishable from a
slower machine and is not flagged — quiet-machine `bench-release` runs
stay the source of truth for absolute numbers.

Benchmarks present only in the new file seed silently (exit 0);
benchmarks missing from the new file are skipped (a failed suite
already fails the job via cargo's own exit code). Prints a sorted
ratio table (raw and normalized) for the log.

Usage: bench_gate.py base.json new.json [--threshold 1.30]
A missing base file means a cold cache: prints SEED and exits 0.
"""

import json
import statistics
import sys


def means(path):
    with open(path) as f:
        data = json.load(f)
    return {
        name: entry["criterion_estimates_v1"]["mean"]["point_estimate"]
        for name, entry in data["benchmarks"].items()
    }


def main(argv):
    threshold = 1.30
    pos = []
    it = iter(argv[1:])
    for arg in it:
        if arg == "--threshold":
            threshold = float(next(it))
        elif arg.startswith("--threshold="):
            threshold = float(arg.split("=", 1)[1])
        else:
            pos.append(arg)
    base_path, new_path = pos
    try:
        base = means(base_path)
    except FileNotFoundError:
        print(f"SEED: no baseline at {base_path}; this run becomes the baseline.")
        return 0
    new = means(new_path)
    rows = []
    for name in sorted(new):
        if name not in base:
            print(f"new benchmark, no baseline (seeding): {name}")
            continue
        rows.append((name, base[name], new[name], new[name] / base[name]))

    # Machine factor: the median ratio cancels a uniform cross-machine
    # speed difference. Unstable under five benchmarks — compare raw then.
    if len(rows) >= 5:
        machine = statistics.median(r for _, _, _, r in rows)
    else:
        machine = 1.0
        print(f"note: only {len(rows)} benchmarks; comparing raw (no median)")

    print(f"machine factor (median ratio): {machine:.3f} over {len(rows)} benchmarks")
    print(f"{'benchmark':<44}{'base':>14}{'new':>14}{'ratio':>8}{'norm':>8}")
    for name, b, n, r in rows:
        print(f"{name:<44}{b:>14.1f}{n:>14.1f}{r:>8.2f}{r / machine:>8.2f}")

    bad = [(name, r, r / machine) for name, _, _, r in rows if r / machine > threshold]
    if bad:
        print(
            f"\nREGRESSIONS beyond threshold {threshold} "
            f"(normalized by machine factor {machine:.3f}):"
        )
        for name, r, norm in bad:
            print(f"  {name}: x{norm:.2f} (raw x{r:.2f})")
        return 1
    print(f"\nno regression beyond threshold {threshold} across {len(rows)} benchmarks.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
