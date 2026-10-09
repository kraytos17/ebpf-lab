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

Two-strike confirmation: with `--strikes PATH`, breach counts persist
across runs (`{name: consecutive_breach_count}`) so one noisy run
cannot fail `main`. A benchmark fails only on its second consecutive
breach. `--confirm-on main` updates the strikes file (for `main`
pushes); `--confirm-on never` (PRs) compares read-only and reports
breaches as advisory. A breach clears the moment the benchmark goes
green again. A missing strikes file means all counts are zero, so the
first run after a cache eviction can only strike, never confirm —
same forgiveness class as the baseline SEED below.

Exit codes: 0 = clean (no breaches; baseline promotion allowed),
1 = first-strike only (breaches, none confirmed; no promotion),
2 = confirmed (a benchmark breached twice consecutively).
`confirmed=true/false` and `breaches=<csv>` are also appended to
`GITHUB_OUTPUT` when that variable is set, for workflow `if:` checks
(exit codes alone blur under `continue-on-error`).

Benchmarks present only in the new file seed silently (exit 0);
benchmarks missing from the new file are skipped (a failed suite
already fails the job via cargo's own exit code). Prints a sorted
ratio table (raw and normalized) for the log, and writes the same
table plus strike state to `--report PATH` (markdown) for PR comments.

Usage: bench_gate.py base.json new.json [--threshold 1.30]
    [--strikes strikes.json] [--confirm-on main|never]
    [--report report.md]
A missing base file means a cold cache: prints SEED and exits 0.
"""

import json
import os
import statistics
import sys


def means(path):
    with open(path) as f:
        data = json.load(f)
    return {
        name: entry["criterion_estimates_v1"]["mean"]["point_estimate"]
        for name, entry in data["benchmarks"].items()
    }


def load_strikes(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def main(argv):
    threshold = 1.30
    strikes_path = None
    confirm_on = "main"
    report_path = None
    pos = []
    it = iter(argv[1:])
    for arg in it:
        if arg == "--threshold":
            threshold = float(next(it))
        elif arg.startswith("--threshold="):
            threshold = float(arg.split("=", 1)[1])
        elif arg == "--strikes":
            strikes_path = next(it)
        elif arg.startswith("--strikes="):
            strikes_path = arg.split("=", 1)[1]
        elif arg == "--confirm-on":
            confirm_on = next(it)
        elif arg.startswith("--confirm-on="):
            confirm_on = arg.split("=", 1)[1]
        elif arg == "--report":
            report_path = next(it)
        elif arg.startswith("--report="):
            report_path = arg.split("=", 1)[1]
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

    breached = [name for name, _, _, r in rows if r / machine > threshold]

    strikes = load_strikes(strikes_path) if strikes_path else {}
    confirmed = []
    if confirm_on == "main" and strikes_path:
        for name in breached:
            count = int(strikes.get(name, 0)) + 1
            strikes[name] = count
            (confirmed if count >= 2 else []).append(name)
        for name in list(strikes):
            if name not in breached:
                del strikes[name]
    if strikes_path:
        # Always write back (even unchanged/empty) so the workflow cache
        # save never sees a missing path.
        with open(strikes_path, "w") as f:
            json.dump(strikes, f, indent=2, sort_keys=True)

    print(f"machine factor (median ratio): {machine:.3f} over {len(rows)} benchmarks")
    print(f"{'benchmark':<44}{'base':>14}{'new':>14}{'ratio':>8}{'norm':>8}")
    for name, b, n, r in rows:
        print(f"{name:<44}{b:>14.1f}{n:>14.1f}{r:>8.2f}{r / machine:>8.2f}")

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"confirmed={'true' if confirmed else 'false'}\n")
            f.write(f"breaches={','.join(breached)}\n")

    lines = [
        "## Bench gate",
        f"machine factor (median ratio): {machine:.3f} over {len(rows)} benchmarks.",
        "",
        "| benchmark | base | new | ratio | norm | state |",
        "|---|---|---|---|---|---|",
    ]
    for name, b, n, r in rows:
        if name in confirmed:
            state = "confirmed (2nd consecutive breach)"
        elif name in breached:
            state = "first strike" if confirm_on == "main" else "advisory"
        else:
            state = "ok"
        lines.append(f"| {name} | {b:.1f} | {n:.1f} | {r:.2f} | {r / machine:.2f} | {state} |")
    if confirmed:
        lines += ["", f"CONFIRMED beyond threshold {threshold}: {', '.join(confirmed)}"]
    elif breached:
        lines += ["", f"breaches beyond threshold {threshold} (not yet confirmed): {', '.join(breached)}"]
    else:
        lines += ["", f"no regression beyond threshold {threshold} across {len(rows)} benchmarks."]
    if report_path:
        with open(report_path, "w") as f:
            f.write("\n".join(lines) + "\n")

    if confirmed:
        print(
            f"\nCONFIRMED beyond threshold {threshold} "
            f"(normalized by machine factor {machine:.3f}):"
        )
        for name in confirmed:
            print(f"  {name}: second consecutive breach")
        return 2
    if breached:
        print(
            f"\nbreaches beyond threshold {threshold} "
            f"(normalized by machine factor {machine:.3f}, first strike):"
        )
        for name in breached:
            print(f"  {name}")
        return 1
    print(f"\nno regression beyond threshold {threshold} across {len(rows)} benchmarks.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
