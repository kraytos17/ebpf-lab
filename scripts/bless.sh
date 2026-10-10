#!/usr/bin/env bash
# Bless snapshot goldens: overwrite `.snap` files in place, but ONLY for
# the three snapshot suites (disasm/cfg goldens, verifier trace schema).
#
# EBPF_LAB_UPDATE_GOLD=1 just bless. Refuses under CI.
# Blessing writes, it never reviews: under INSTA_UPDATE=always rewrites
# are silent-green, so the printed `*.snap` diff plus the warning below
# are the entire review surface. Do not weaken them (no quiet flag, no
# auto-commit). Never wire this into `verify` or CI — mismatches there
# must fail loudly. Everything else gold-like (CLI text pins, exit
# codes, `.bin` inputs) is intentionally NOT blessable: those are the
# user-visible contract, hand-edit them.
set -u
if [ "${CI:-}" != "" ]; then echo "bless: refusing under CI" >&2; exit 1; fi
if [ "${EBPF_LAB_UPDATE_GOLD:-}" != "1" ]; then
    echo "bless: set EBPF_LAB_UPDATE_GOLD=1 to overwrite goldens" >&2
    exit 1
fi

rc=0
INSTA_UPDATE=always cargo test --locked -p ebpf-disasm --test golden || rc=$?
INSTA_UPDATE=always cargo test --locked -p ebpf-cfg --test golden || rc=$?
INSTA_UPDATE=always cargo test --locked -p ebpf-verifier --test trace_snapshot || rc=$?
echo "--- *.snap changes (review every hunk before committing) ---"

snap_changes=$(git status --short -- '*.snap')
printf '%s\n' "$snap_changes"
git diff --stat -- '*.snap'
if [ -n "$snap_changes" ]; then
    echo "bless: goldens rewritten above — eyeball every hunk, then re-run just verify" >&2
fi
if [ "$rc" != "0" ]; then
    echo "bless: snapshots were rewritten (or a real failure occurred) — review the diff above, then re-run just verify" >&2
fi
exit "$rc"
