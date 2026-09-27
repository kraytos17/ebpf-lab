#!/usr/bin/env python3
"""Fail when any benchmark regressed beyond threshold since the baseline.

Compares mean point estimates by benchmark name between two
`critcmp --export` JSON files (base first, new second). Benchmarks
present only in the new file seed silently (exit 0); benchmarks missing
from the new file are skipped (a failed suite already fails the job via
cargo's own exit code). Prints a sorted ratio table for the log.

Usage: bench_gate.py base.json new.json [--threshold 1.30]
A missing base file means a cold cache: prints SEED and exits 0.
"""

import json
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
        ratio = new[name] / base[name]
        rows.append((name, base[name], new[name], ratio))
    print(f"{'benchmark':<44}{'base':>14}{'new':>14}{'ratio':>8}")
    for name, b, n, r in rows:
        print(f"{name:<44}{b:>14.1f}{n:>14.1f}{r:>8.2f}")
    bad = [(name, r) for name, _, _, r in rows if r > threshold]
    if bad:
        print(f"\nREGRESSIONS beyond threshold {threshold}:")
        for name, r in bad:
            print(f"  {name}: x{r:.2f}")
        return 1
    print(f"\nno regression beyond threshold {threshold} across {len(rows)} benchmarks.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
