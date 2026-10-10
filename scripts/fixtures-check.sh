#!/usr/bin/env bash
# Fixture-table consistency: every program file has a README row and vice
# versa, `.bin` slot counts match file bytes, `.o` instruction counts
# match `inspect`, packet lengths and the fixtures badge match.
# Exit codes are NOT checked here (context-dependent; the CLI e2e pins
# own them). Read-only apart from building the CLI: never writes the tree.
set -euo pipefail
cd "$(dirname "$0")/.."

fails=0
fail() { echo "fixtures-check: FAIL: $1" >&2; fails=$((fails + 1)); }

TABLE=tests/fixtures/README.md
rows=$(grep -E '^\| `' "$TABLE" || true)
[ -n "$rows" ] || { fail "no table rows parsed"; exit 1; }

cargo build -q --locked -p ebpf-lab-cli >&2
BIN=target/debug/ebpf-lab

while IFS= read -r line; do
    name=$(echo "$line" | awk -F'|' '{print $2}' | tr -d ' `')
    cell=$(echo "$line" | awk -F'|' '{print $3}' | tr -d ' ')
    case "$name" in
        *.bin)
            [ -f "tests/fixtures/$name" ] || { fail "row without file: $name"; continue; }
            want=$(echo "$cell" | grep -oE '[0-9]+' | head -n1)
            have=$(($(stat -c%s "tests/fixtures/$name") / 8))
            [ "$want" = "$have" ] || fail "$name: table slots $want != file slots $have"
            ;;
        *.o)
            [ -f "tests/fixtures/$name" ] || { fail "row without file: $name"; continue; }
            want=$(echo "$cell" | grep -oE '\([0-9]+insns\)' | grep -oE '[0-9]+' || true)
            have=$("$BIN" inspect "tests/fixtures/$name" | grep -oE 'Instructions: [0-9]+' | grep -oE '[0-9]+')
            [ "$want" = "$have" ] || fail "$name: table insns $want != inspect insns $have"
            ;;
        *.pkt)
            [ -f "tests/fixtures/$name" ] || { fail "row without file: $name"; continue; }
            want=$(echo "$cell" | grep -oE '[0-9]+' | head -n1)
            have=$(stat -c%s "tests/fixtures/$name")
            [ "$want" = "$have" ] || fail "$name: table length $want != file bytes $have"
            ;;
    esac
done <<< "$rows"

for f in tests/fixtures/*.bin tests/fixtures/*.o tests/fixtures/*.pkt; do
    n=$(basename "$f")
    echo "$rows" | grep -qF "| \`$n\` |" || fail "file without row: $n"
done
for f in tests/fixtures/*.json; do
    grep -qF "$(basename "$f")" "$TABLE" || fail "json unmentioned in README: $(basename "$f")"
done
# fixtures-NN badge counts programs (`.bin` + `.o`).
badge=$(grep -oE 'fixtures-[0-9]+' README.md | head -n1 | grep -oE '[0-9]+')
progs=$(ls tests/fixtures/*.bin tests/fixtures/*.o | wc -l)
[ "$badge" = "$progs" ] || fail "badge fixtures-$badge != program files $progs"

nrows=$(echo "$rows" | wc -l)
echo "fixtures-check: $nrows rows × $progs programs checked"
if [ "$fails" -ne 0 ]; then exit 1; fi
