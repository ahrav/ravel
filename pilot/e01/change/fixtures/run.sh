#!/usr/bin/env bash
# E01 Change fixture check — PRIVATE, UNSTABLE. commentlint: allow(JUDGE)
# Expected results per fixture are predeclared in contract.md.
#
# Usage: pilot/e01/change/fixtures/run.sh
set -u
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
DISCOVER="$HERE/../discover.sh"

FAILURES=0
check() { # check <name> <0|1 ok> <detail>
	if [ "$2" -eq 0 ]; then
		echo "PASS  $1${3:+ — $3}"
	else
		echo "FAIL  $1${3:+ — $3}"
		FAILURES=$((FAILURES + 1))
	fi
}

TMP="$(mktemp -d /tmp/e01-fixtures.XXXXXX)" || exit 1
trap 'rm -rf -- "$TMP"' EXIT

run_fixture() { # run_fixture <name.rs> — discover over a copy in a plain dir
	local d="$TMP/${1%.rs}-$RANDOM"
	mkdir -p "$d" && cp "$HERE/$1" "$d/"
	bash "$DISCOVER" "$d"
}

pos1="$(run_fixture positive.rs)"
pos2="$(run_fixture positive.rs)"
check "positive: two runs field-for-field identical" "$([ "$pos1" = "$pos2" ] && [ -n "$pos1" ] && echo 0 || echo 1)"
check "positive: exactly one record" "$([ "$(printf '%s' "$pos1" | grep -c .)" -eq 1 ] && echo 0 || echo 1)"
for field in \
	'"source_revision":"no-git"' \
	'"path":"positive.rs"' \
	'"semantic_locator":"positive.rs:3:18 .unwrap() call site"'; do
	check "positive: has $field" "$(printf '%s' "$pos1" | grep -qF "$field" && echo 0 || echo 1)"
done
for field in rule_digest target_id context_digest; do
	check "positive: $field is 64-hex" "$(printf '%s' "$pos1" | grep -qE "\"$field\":\"[0-9a-f]{64}\"" && echo 0 || echo 1)"
done

before="$(sha256sum "$HERE/negative.rs" | cut -d' ' -f1)"
neg="$(run_fixture negative.rs)"
after="$(sha256sum "$HERE/negative.rs" | cut -d' ' -f1)"
check "negative: zero records" "$([ -z "$neg" ] && echo 0 || echo 1)"
check "negative: file byte-identical after run" "$([ "$before" = "$after" ] && echo 0 || echo 1)"

res="$(run_fixture resolved.rs)"
check "resolved: zero records (completion permitted)" "$([ -z "$res" ] && echo 0 || echo 1)"

rem="$(run_fixture remaining.rs)"
check "remaining: >=1 record (completion blocked)" "$([ -n "$rem" ] && echo 0 || echo 1)"

for f in positive.rs negative.rs resolved.rs remaining.rs; do
	check "$f: compiles (rustc --edition 2024)" "$(rustc --edition 2024 --crate-type bin -o "$TMP/fixture-bin" "$HERE/$f" >/dev/null 2>&1 && echo 0 || echo 1)"
done

gd="$TMP/dirty"
mkdir -p "$gd" && git -C "$gd" init --quiet && cp "$HERE/positive.rs" "$gd/"
out="$(bash "$DISCOVER" "$gd" 2>/dev/null)"
rc=$?
check "dirty worktree: refused with no output" "$([ "$rc" -ne 0 ] && [ -z "$out" ] && echo 0 || echo 1)"

echo "== result: $([ "$FAILURES" -eq 0 ] && echo FIXTURES-PASS || echo "FIXTURES-FAIL ($FAILURES)") =="
exit "$((FAILURES > 0))"
