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
# Enforcement here is overlap-only: no discovered change target may sit under
# any of these prefixes. pilot/ is listed so a subject-side pilot/ tree could
# never become candidate-writable.
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
for tool in git rg python3 stat cargo rustc timeout; do
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
TEMP_ROOT=""
cleanup() {
	[ -n "$TEMP_ROOT" ] && rm -rf -- "$TEMP_ROOT"
	rm -rf -- "$EVAL_TARGET_DIR"
}
# Evaluators always build into a fresh target dir: a caller-supplied checkout
# may carry stale artifacts in an ignored target/ that `git status` cannot see.
EVAL_TARGET_DIR="$(mktemp -d /tmp/e01-target.XXXXXX)" || {
	echo "FAIL mktemp"
	exit 1
}
export CARGO_TARGET_DIR="$EVAL_TARGET_DIR"
trap cleanup EXIT
if [ $# -ge 1 ]; then
	DIR="$1"
else
	TEMP_ROOT="$(mktemp -d /tmp/e01-preflight.XXXXXX)" || {
		echo "FAIL mktemp"
		exit 1
	}
	DIR="$TEMP_ROOT/hyperfine"
	echo "cloning $REPO_URL -> $DIR"
	git clone --quiet "$REPO_URL" "$DIR" || {
		echo "FAIL clone"
		exit 1
	}
	git -C "$DIR" checkout --quiet "$FROZEN_SHA" || {
		echo "FAIL checkout $FROZEN_SHA"
		exit 1
	}
fi
cd "$DIR" || {
	echo "FAIL cd $DIR"
	exit 1
}
# A caller-supplied checkout is verified as-is, never reset to the frozen SHA.
head_sha=$(git rev-parse HEAD)
check "frozen revision" "$([ "$head_sha" = "$FROZEN_SHA" ] && echo 0 || echo 1)" "$head_sha"
check "clean worktree (incl. ignored files)" "$([ -z "$(git status --porcelain --ignored)" ] && echo 0 || echo 1)"
# The evaluators below execute code from the tree (build scripts, tests).
# Never run them against anything but the clean frozen revision.
if [ "$FAILURES" -ne 0 ]; then
	echo "refusing to evaluate a non-frozen tree"
	echo "== result: PREFLIGHT-FAIL ($FAILURES) =="
	exit 1
fi

# --- repository hygiene (all counts must be zero) ---------------------------
n=$(git ls-files -s | awk '$1==160000' | wc -l)
check "no submodules" "$((n != 0))" "count=$n"
n=$(git ls-files -s | awk '$1==120000' | wc -l)
check "no symlinks" "$((n != 0))" "count=$n"
n=$(git ls-files -s | awk '$1!~/^100(644|755)$/' | wc -l)
check "no special modes" "$((n != 0))" "count=$n"
n=$(find . -path ./.git -prune -o -path ./target -prune -o \( -perm -4000 -o -perm -2000 -o -perm -0002 \) -print | wc -l)
check "no setuid/setgid/world-writable on disk" "$((n != 0))" "count=$n"
n=$(git grep -l 'version https://git-lfs' -- . 2>/dev/null | wc -l)
check "no LFS pointers" "$((n != 0))" "count=$n"
n=$(find . -path ./.git -prune -o -path ./target -prune -o \( -type p -o -type s -o -type b -o -type c \) -print | wc -l)
check "no special files on disk" "$((n != 0))" "count=$n"
n=$(git ls-files -z | xargs -0 stat -c '%h %F' 2>/dev/null | awk '$2=="regular" && $1>1' | wc -l)
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
GATE_TARGETS=$(rg -l '\.unwrap\(\)' --type rust --hidden -g '!.git/**' -g '!tests/**' -g '!benches/**' | sort)
overlap=0
for f in $GATE_TARGETS; do
	for root in "${SUBJECT_TRUST_ROOTS[@]}"; do
		case "$f" in "$root"*) overlap=$((overlap + 1)) ;; esac
	done
done
check "trust roots disjoint from change targets" "$((overlap != 0))" "overlaps=$overlap"

# --- change viability gate ----------------------------------------------------
# The discovery rule matches `.unwrap()` calls for conversion to `.expect("...")`
# in Rust files outside `tests/**` and `benches/**`. The scope is path-based:
# inline `#[test]`/`#[cfg(test)]` code in matched files IS counted.
# preflight.md §1 and §6 define the strictly-non-test count.
tc=$(rg -n '\.unwrap\(\)' --type rust --hidden -g '!.git/**' -g '!tests/**' -g '!benches/**' | wc -l)
check "change targets >= 36" "$((tc < 36))" "count=$tc"

vec_out=$(
	python3 - <<'PY' 2>&1
import sys, unicodedata

MAX_PATH_BYTES, MAX_DEPTH = 180, 10  # environment.yaml repository_limits
FORBIDDEN = {'"', '\\'}              # same characters discover.sh refuses


def collision_key(raw):
    """(key, None) for an accepted path, (None, reason) for a rejection."""
    try:
        p = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "invalid-utf8"
    if len(raw) > MAX_PATH_BYTES:
        return None, "path-too-long"
    comps = p.split("/")
    if len(comps) > MAX_DEPTH:
        return None, "path-too-deep"
    for c in comps:
        if c == "":
            return None, "empty-component"
        if c in (".", ".."):
            return None, "dot-component"
        if c.casefold() == ".git":
            return None, "git-component"
        for ch in c:
            if ord(ch) <= 0x1F or ord(ch) == 0x7F:
                return None, "control-char"
            if ch in FORBIDDEN:
                return None, "forbidden-char"
    # casefold output is not guaranteed NFC, hence the outer normalize.
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", p).casefold()), None


VECTORS = [  # frozen: runtime.md §4.1, row order
    (b"src/main.rs", "src/main.rs"),
    (b"src/Main.rs", "src/main.rs"),
    (b"src/caf\xc3\xa9.rs", "src/caf\u00e9.rs"),
    (b"src/cafe\xcc\x81.rs", "src/caf\u00e9.rs"),
    (b"src/stra\xc3\x9fe.rs", "src/strasse.rs"),
    (b"src/strasse.rs", "src/strasse.rs"),
    (b"src/\xffbad.rs", "REJECT:invalid-utf8"),
    (b"src/../etc/passwd", "REJECT:dot-component"),
    (b"src/.", "REJECT:dot-component"),
    (b"src/a\x01b.rs", "REJECT:control-char"),
    (b"src/a\x7fb.rs", "REJECT:control-char"),
    (b'src/a"b.rs', "REJECT:forbidden-char"),
    (b"src/a\\b.rs", "REJECT:forbidden-char"),
    (b"src//main.rs", "REJECT:empty-component"),
    (b"src/" + b"a" * 177, "REJECT:path-too-long"),
    (b"src/.git/config", "REJECT:git-component"),
]

fails = 0
keys = {}
for raw, want in VECTORS:
    k, reason = collision_key(raw)
    got = "REJECT:" + reason if reason else k
    if got != want:
        print("vector %r: want %r got %r" % (raw, want, got))
        fails += 1
    if reason is None:
        keys.setdefault(k, []).append(raw)
pairs = sum(1 for v in keys.values() if len(v) > 1)
if pairs != 3:  # (1,2) ASCII case, (3,4) NFC/NFD, (5,6) casefold
    print("collision key pairs: want 3 got %d" % pairs)
    fails += 1
print("unidata_version=%s" % unicodedata.unidata_version)
sys.exit(1 if fails else 0)
PY
)
vec_rc=$?
echo "unicodedata: $(printf '%s\n' "$vec_out" | sed -n 's/^unidata_version=//p') (runtime.md §4 reference: 13.0.0)"
check "path collision golden vectors (16 rows, 3 collision pairs)" "$vec_rc" \
	"$(printf '%s\n' "$vec_out" | grep -v '^unidata_version=' | tr '\n' ';')"

for tool in bwrap prlimit; do
	check "containment tool present: $tool" "$(command -v "$tool" >/dev/null && echo 0 || echo 1)"
done
# Presence is not enough: runtime.md §3.2 fails the launch when "any limit
# cannot be applied", so preflight must apply the frozen limits, not just
# find prlimit on PATH.
if ! command -v prlimit >/dev/null; then
	check "prlimit frozen limits apply" 1 "prlimit missing"
elif prlimit --as=8589934592 --nproc=512 --cpu=900 --nofile=4096 -- true >/dev/null 2>&1; then
	check "prlimit frozen limits apply" 0
else
	check "prlimit frozen limits apply" 1 "nonzero exit"
fi
# Smoke the frozen invocation shape (runtime.md §3.1) end to end — production
# mounts, env, and the in-sandbox timeout+prlimit chain — not a permissive
# bind that can pass while the real shape fails.
if ! command -v bwrap >/dev/null; then
	check "bwrap frozen-shape smoke (runtime.md §3.1)" 1 "bwrap missing"
elif ! SMOKE_DIR="$(mktemp -d /tmp/e01-bwrap.XXXXXX)"; then
	check "bwrap frozen-shape smoke (runtime.md §3.1)" 1 "mktemp failed"
else
	mkdir -p "$SMOKE_DIR/src" "$SMOKE_DIR/toolchain" "$SMOKE_DIR/out"
	if bwrap --unshare-all --die-with-parent \
		--ro-bind /usr /usr \
		--symlink usr/bin /bin --symlink usr/lib /lib \
		--symlink usr/lib64 /lib64 --symlink usr/sbin /sbin \
		--ro-bind "$SMOKE_DIR/src" /work/src \
		--ro-bind "$SMOKE_DIR/toolchain" /opt/toolchain \
		--bind "$SMOKE_DIR/out" /work/out \
		--tmpfs /tmp --proc /proc --dev /dev \
		--chdir /work/src --new-session --clearenv \
		--setenv PATH /opt/toolchain/bin:/usr/bin \
		--setenv HOME /work/out --setenv TMPDIR /tmp \
		-- timeout --kill-after=60 30 \
		prlimit --as=8589934592 --nproc=512 --cpu=900 --nofile=4096 -- true \
		>/dev/null 2>&1; then
		check "bwrap frozen-shape smoke (runtime.md §3.1)" 0
	else
		check "bwrap frozen-shape smoke (runtime.md §3.1)" 1 "nonzero exit"
	fi
	rm -rf -- "$SMOKE_DIR"
fi
mun=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo 0)
check "user namespaces enabled" "$([ "${mun:-0}" -gt 0 ] && echo 0 || echo 1)" "max_user_namespaces=$mun"

# Evaluators execute code from the tree; do not run them after any preflight
# check fails.
if [ "$FAILURES" -ne 0 ]; then
	echo "refusing to evaluate a tree that failed preflight checks"
	echo "== result: PREFLIGHT-FAIL ($FAILURES) =="
	exit 1
fi

# --- trusted evaluators (predeclared verdicts; all PASS) -----------------------
EVAL_TIMEOUT=1800 # seconds per evaluator; a hang must become a verdict, not a stall
run_eval() {      # run_eval <command...> — expected PASS
	local name="$*"
	local log rc=0
	log="$(mktemp /tmp/e01-eval.XXXXXX.log)" || {
		check "evaluator: $name" 1 "mktemp failed"
		return
	}
	timeout --kill-after=60 "$EVAL_TIMEOUT" "$@" >"$log" 2>&1 || rc=$?
	if [ "$rc" -eq 0 ]; then
		check "evaluator: $name" 0 "expected=PASS got=PASS"
	elif [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
		check "evaluator: $name" 1 "expected=PASS got=TIMEOUT rc=$rc (see $log)"
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
