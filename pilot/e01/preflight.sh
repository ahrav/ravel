#!/usr/bin/env bash
# E01 preflight — PRIVATE, UNSTABLE. Direct checks for the one frozen subject
# (ahrav/hyperfine @ f12f3d9f). Not a framework; do not generalize.
#
# Usage: pilot/e01/preflight.sh [checkout-dir]
#   With no argument, clones the fork at the frozen revision into a temp dir.
#   Runs hygiene checks + trusted evaluators, compares predeclared verdicts,
#   and prints a receipt to stdout. Any unexpected result exits nonzero.
set -u

REPO_URL="https://github.com/ahrav/hyperfine.git"
FROZEN_SHA="f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7"

# Numeric limits (must match environment.yaml repository_limits)
MAX_FILE_COUNT=2000
MAX_FILE_BYTES=1048576
MAX_TOTAL_BYTES=33554432
MAX_PATH_LENGTH=180
MAX_PATH_DEPTH=10

# Trust roots in the subject repo (must match environment.yaml trust_roots).
# pilot/ is a trust root of the ravel repo, not the subject; the subject must
# not contain it either, so it is checked for absence below.
SUBJECT_TRUST_ROOTS=(".github/" "Cargo.toml" "Cargo.lock" "pilot/")

FAILURES=0
check() { # check <name> <0|1 ok> <detail>
	if [ "$2" -eq 0 ]; then
		echo "PASS  $1${3:+ — $3}"
	else
		echo "FAIL  $1${3:+ — $3}"
		FAILURES=$((FAILURES + 1))
	fi
}

echo "== E01 preflight receipt =="
for tool in git rg python3 stat cargo rustc; do
	command -v "$tool" >/dev/null || {
		echo "FAIL required tool missing: $tool"
		exit 1
	}
done
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "host: $(uname -sr)"
echo "rustc: $(rustc --version 2>/dev/null || echo MISSING)"
echo "cargo: $(cargo --version 2>/dev/null || echo MISSING)"

# --- checkout ---------------------------------------------------------------
if [ $# -ge 1 ]; then
	DIR="$1"
else
	DIR="$(mktemp -d /tmp/e01-preflight.XXXXXX)/hyperfine"
	echo "cloning $REPO_URL -> $DIR"
	git clone --quiet "$REPO_URL" "$DIR" || {
		echo "FAIL clone"
		exit 1
	}
fi
cd "$DIR" || {
	echo "FAIL cd $DIR"
	exit 1
}
git checkout --quiet "$FROZEN_SHA" 2>/dev/null
head_sha=$(git rev-parse HEAD)
check "frozen revision" "$([ "$head_sha" = "$FROZEN_SHA" ] && echo 0 || echo 1)" "$head_sha"
check "clean worktree" "$([ -z "$(git status --porcelain)" ] && echo 0 || echo 1)"

# --- repository hygiene (all counts must be zero) ---------------------------
n=$(git ls-files -s | awk '$1==160000' | wc -l)
check "no submodules" "$((n != 0))" "count=$n"
n=$(git ls-files -s | awk '$1==120000' | wc -l)
check "no symlinks" "$((n != 0))" "count=$n"
n=$(git ls-files -s | awk '$1!~/^100(644|755)$/' | wc -l)
check "no special modes" "$((n != 0))" "count=$n"
n=$(git grep -l 'version https://git-lfs' -- . 2>/dev/null | wc -l)
check "no LFS pointers" "$((n != 0))" "count=$n"
# target/ pruned: the evaluators below create hardlinked artifacts there.
n=$(find . -path ./.git -prune -o -path ./target -prune -o \( -type p -o -type s -o -type b -o -type c \) -print | wc -l)
check "no special files on disk" "$((n != 0))" "count=$n"
n=$(git ls-files -z | xargs -0 stat -c%h | awk '$1>1' | wc -l)
check "no hardlinks (tracked files)" "$((n != 0))" "count=$n"
n=$(git ls-files | tr '[:upper:]' '[:lower:]' | sort | uniq -d | wc -l)
check "no case collisions" "$((n != 0))" "count=$n"
n=$(git ls-files -z | python3 -c '
import sys, unicodedata
fs = [x for x in sys.stdin.buffer.read().decode().split("\0") if x]
seen = {}
for f in fs:
    seen.setdefault(unicodedata.normalize("NFC", f), []).append(f)
print(sum(1 for v in seen.values() if len(v) > 1))')
check "no unicode-normalization collisions" "$((n != 0))" "count=$n"

# --- numeric limits ----------------------------------------------------------
fc=$(git ls-files | wc -l)
check "file count <= $MAX_FILE_COUNT" "$((fc > MAX_FILE_COUNT))" "count=$fc"
tb=$(git ls-files -z | xargs -0 stat -c%s | awk '{s+=$1} END{print s}')
check "total bytes <= $MAX_TOTAL_BYTES" "$((tb > MAX_TOTAL_BYTES))" "bytes=$tb"
mb=$(git ls-files -z | xargs -0 stat -c%s | sort -rn | head -1)
check "max file bytes <= $MAX_FILE_BYTES" "$((mb > MAX_FILE_BYTES))" "largest=$mb"
pl=$(git ls-files | awk '{print length}' | sort -rn | head -1)
check "max path length <= $MAX_PATH_LENGTH" "$((pl > MAX_PATH_LENGTH))" "longest=$pl"
pd=$(git ls-files | awk -F/ '{print NF}' | sort -rn | head -1)
check "max path depth <= $MAX_PATH_DEPTH" "$((pd > MAX_PATH_DEPTH))" "deepest=$pd"

# --- trust roots vs candidate-writable paths ---------------------------------
# Change targets are discovered by the gate command below; none may sit under
# a trust root.
GATE_TARGETS=$(rg -l '\.unwrap\(\)' --type rust -g '!tests/**' -g '!benches/**' | sort)
overlap=0
for f in $GATE_TARGETS; do
	for root in "${SUBJECT_TRUST_ROOTS[@]}"; do
		case "$f" in "$root"*) overlap=$((overlap + 1)) ;; esac
	done
done
check "trust roots disjoint from change targets" "$((overlap != 0))" "overlaps=$overlap"

# --- change viability gate ----------------------------------------------------
# Provisional discovery rule: .unwrap() -> .expect("...") in non-test code.
# (Plan's original Lazy->LazyLock rule failed every candidate; see preflight.md.)
tc=$(rg -n '\.unwrap\(\)' --type rust -g '!tests/**' -g '!benches/**' | wc -l)
check "change targets >= 36" "$((tc < 36))" "count=$tc"

# --- trusted evaluators (predeclared verdicts; all PASS) -----------------------
run_eval() { # run_eval <command...> — expected PASS
	local name="$*"
	local log
	log="/tmp/e01-eval-$(echo "$name" | tr -cs 'a-zA-Z0-9' '-').log"
	if "$@" >"$log" 2>&1; then
		check "evaluator: $name" 0 "expected=PASS got=PASS"
	else
		check "evaluator: $name" 1 "expected=PASS got=FAIL (see $log)"
	fi
}
run_eval cargo build --locked
run_eval cargo test --locked
run_eval cargo fmt --check
run_eval cargo clippy --all-targets --locked

echo "== result: $([ "$FAILURES" -eq 0 ] && echo PREFLIGHT-PASS || echo "PREFLIGHT-FAIL ($FAILURES)") =="
exit "$((FAILURES > 0))"
