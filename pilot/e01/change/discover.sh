#!/usr/bin/env bash
# E01 Change trusted discovery — PRIVATE, UNSTABLE. Lives under the pilot/
# trust root; never candidate-writable. Not a framework; do not generalize.
#
# Usage: pilot/e01/change/discover.sh <checkout-dir>
#   Emits one JSONL record per discovered legacy target to stdout, sorted by
#   (path, line, col). Record fields, digest inputs, and determinism are
#   defined in contract.md. Read-only: never modifies the checkout.
#
#   <checkout-dir> with a .git entry: worktree must be clean (untracked files
#   would produce phantom targets); source_revision = git rev-parse HEAD.
#   The revision is emitted, not pinned, so the same script serves both
#   inventory freezing (frozen revision) and final rediscovery (candidate
#   revision). Plain directories (fixtures): source_revision = "no-git".
set -euo pipefail
export LC_ALL=C

SCRIPT="$(readlink -f "$0")"

# RULE-BEGIN — rule digest = sha256 of this block, marker lines included.
# Any edit to the pattern or scope below changes the digest, which breaks
# field-for-field comparison against previously frozen output.
#
# Rule: every textual occurrence of `.unwrap()` in Rust files, excluding
# tests/**, benches/**, and .git/** (hidden files otherwise included;
# .gitignore respected). Path-based scope: inline #[test]/#[cfg(test)] code
# in matched files IS counted. Treatment: contract.md §1.
RULE_PATTERN='\.unwrap\(\)'
RULE_ARGS=(--type rust --hidden -g '!.git/**' -g '!tests/**' -g '!benches/**')
# RULE-END
RULE_DIGEST="$(sed -n '/^# RULE-BEGIN/,/^# RULE-END/p' "$SCRIPT" | sha256sum | cut -d' ' -f1)"

DIR="${1:?usage: discover.sh <checkout-dir>}"
cd "$DIR"

if [ -e .git ]; then
	if [ -n "$(git status --porcelain)" ]; then
		echo "discover.sh: refusing dirty worktree in $DIR" >&2
		exit 1
	fi
	SOURCE_REVISION="$(git rev-parse HEAD)"
else
	SOURCE_REVISION="no-git"
fi

# --vimgrep: one output line per match (path:line:col:text), col 1-based.
set +e
MATCHES="$(rg --vimgrep "${RULE_ARGS[@]}" -e "$RULE_PATTERN")"
rc=$?
set -e
if [ "$rc" -ge 2 ]; then
	echo "discover.sh: rg failed with rc=$rc" >&2
	exit 1
fi
[ "$rc" -eq 1 ] && exit 0 # zero targets: empty output, success

printf '%s\n' "$MATCHES" | sort -t: -k1,1 -k2,2n -k3,3n | while IFS= read -r rec; do
	path="${rec%%:*}"
	rest="${rec#*:}"
	line="${rest%%:*}"
	rest="${rest#*:}"
	col="${rest%%:*}"
	text="${rest#*:}"
	# Non-numeric line/col means a path containing ':' broke the field split.
	case "$line$col" in
	'' | *[!0-9]*)
		echo "discover.sh: cannot parse match record: $rec" >&2
		exit 1
		;;
	esac
	# Records are emitted without JSON escaping; refuse any path that would
	# need it (none exist in the frozen subject or fixtures).
	case "$path" in
	*[\"\\]* | *[[:cntrl:]]*)
		echo "discover.sh: path needs JSON escaping, unsupported: $path" >&2
		exit 1
		;;
	esac
	target_id="$(printf '%s' "$path:$line:$col:$text" | sha256sum | cut -d' ' -f1)"
	start=$((line - 2))
	[ "$start" -lt 1 ] && start=1
	context_digest="$(sed -n "${start},$((line + 2))p" "$path" | sha256sum | cut -d' ' -f1)"
	printf '{"source_revision":"%s","rule_digest":"%s","target_id":"%s","path":"%s","semantic_locator":"%s:%s:%s .unwrap() call site","context_digest":"%s"}\n' \
		"$SOURCE_REVISION" "$RULE_DIGEST" "$target_id" "$path" "$path" "$line" "$col" "$context_digest"
done
