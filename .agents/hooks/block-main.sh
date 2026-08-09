#!/usr/bin/env bash
# PreToolUse guard shared by Claude Code, Codex, opencode, and pi:
# deny any `git commit` while on main and any `git push` that would update main.
# Feature-branch pushes and PRs pass through.
# This is a guardrail against agent mistakes, not a security boundary.
#
# Wire formats:
#   default: Claude Code / Codex JSON on stdin ({tool_input:{command},cwd}),
#            deny via hookSpecificOutput JSON on stdout.
#   --cmd "<command>" [--cwd <dir>]: plain-text mode for the opencode plugin
#            and pi extension shims; deny via reason on stdout + exit 2.
#
# Override: a segment whose git invocation is prefixed with ALLOW_MAIN=1
# passes (use only when the user explicitly approved touching main).
set -u

mode=json
cmd=""
cwd=""
if [ "${1:-}" = "--cmd" ]; then
  mode=plain
  cmd="${2:-}"
  if [ "${3:-}" = "--cwd" ]; then cwd="${4:-}"; fi
else
  input=$(cat)
  cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)
  cwd=$(printf '%s' "$input" | jq -r '.cwd // empty' 2>/dev/null)
fi

[ -n "$cmd" ] || exit 0
case "$cmd" in *commit* | *push*) ;; *) exit 0 ;; esac

deny() {
  local r="Blocked: $1. Work on a feature branch and open a PR; direct commits/pushes to main require explicit user approval (prefix with ALLOW_MAIN=1 once granted)."
  if [ "$mode" = json ]; then
    jq -n --arg r "$r" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
    exit 0
  fi
  printf '%s\n' "$r"
  exit 2
}

current_branch() {
  # An earlier `git switch`/`git checkout` segment in the same compound
  # command sets assumed_branch; it overrides the on-disk state because the
  # hook inspects the command before the shell executes any segment.
  if [ -n "$assumed_branch" ]; then printf '%s\n' "$assumed_branch"; return; fi
  git -C "${1:-${cwd:-.}}" symbolic-ref --quiet --short HEAD 2>/dev/null
}

push_dest() {
  # Effective destination of a bare `git push` (covers push.default=upstream
  # and remote.<name>.push mappings), e.g. "origin/main". Empty if unset.
  git -C "${1:-${cwd:-.}}" rev-parse --abbrev-ref --symbolic-full-name '@{push}' 2>/dev/null
}

assumed_branch=""

reason=""

check_segment() {
  local seg="$1"
  # Normalize away quote/paren characters so `git push origin "main"`,
  # `'git' push`, and `(git push ...)` tokenize the same as the bare form.
  # ponytail: over-approximates (quoted prose mentioning git may match); this
  # is a guardrail, not a security boundary — real parsing needs a shell parser.
  seg=${seg//[\"\'()]/}
  local -a toks
  read -ra toks <<<"$seg" || return 0
  local n=${#toks[@]} i gi=-1

  # Locate the git executable token
  for ((i = 0; i < n; i++)); do
    case "${toks[$i]}" in git | */git) gi=$i; break ;; esac
  done
  ((gi >= 0)) || return 0

  # Override: ALLOW_MAIN=1 must appear as a token before this segment's git
  # invocation (env-assignment position). Scoped per segment so it cannot
  # whitelist an unrelated command riding along in a compound line.
  for ((i = 0; i < gi; i++)); do
    [ "${toks[$i]}" = "ALLOW_MAIN=1" ] && return 0
  done

  # Find the git subcommand, skipping global options (so `git stash push` etc.
  # don't match). Capture `-C <dir>` so branch checks run against the repo the
  # command actually targets.
  local j=$((gi + 1)) sub="" cdir=""
  while ((j < n)); do
    case "${toks[$j]}" in
      -C) cdir="${toks[$((j + 1))]:-}"; ((j += 2)); continue ;;
      -c | --git-dir | --work-tree | --namespace) ((j += 2)); continue ;;
      -*) ((j += 1)); continue ;;
      *) sub="${toks[$j]}"; break ;;
    esac
  done

  case "$sub" in
    switch | checkout)
      # Record the target branch so segments after `git switch main` are
      # evaluated against main, not the pre-switch branch. `checkout -- <path>`
      # and detach forms do not switch branches.
      local tgt=""
      for ((i = j + 1; i < n; i++)); do
        case "${toks[$i]}" in
          --) break ;;
          --detach | --orphan) return 0 ;;
          -*) ;;
          *) tgt="${toks[$i]}"; break ;;
        esac
      done
      # `checkout <branch> -- <path>` restores paths without switching.
      [ "${toks[$((i + 1))]:-}" = "--" ] && return 0
      [ -n "$tgt" ] && assumed_branch="$tgt"
      return 0
      ;;
    commit)
      if [ "$(current_branch "$cdir")" = "main" ]; then
        reason="'$seg' commits while on main"
      fi
      return 0
      ;;
    push) ;;
    *) return 0 ;;
  esac

  # Parse args after `push`: first bare word is the remote, the rest are refspecs
  local remote="" push_all=0
  local -a refspecs=()
  for ((i = j + 1; i < n; i++)); do
    case "${toks[$i]}" in
      --all | --mirror | --branches) push_all=1 ;;
      -*) ;;
      *) if [ -z "$remote" ]; then remote="${toks[$i]}"; else refspecs+=("${toks[$i]}"); fi ;;
    esac
  done

  local rs dest
  for rs in ${refspecs[@]+"${refspecs[@]}"}; do
    dest="${rs#+}"
    case "$dest" in *:*) dest="${dest##*:}" ;; esac
    case "$dest" in
      main | refs/heads/main) reason="'$seg' targets main on ${remote:-the default remote}"; return 0 ;;
      HEAD)
        if [ "$(current_branch "$cdir")" = "main" ]; then
          reason="'$seg' pushes HEAD while on main"; return 0
        fi ;;
    esac
  done

  if ((push_all)); then
    reason="'$seg' uses --all/--mirror, which would update main"; return 0
  fi

  if ((${#refspecs[@]} == 0)); then
    if [ "$(current_branch "$cdir")" = "main" ]; then
      reason="'$seg' is a bare push while on main"; return 0
    fi
    if [ -n "$remote" ]; then
      # A repository-only push honors remote.<name>.push mappings, which can
      # target main from any branch.
      local m dest2
      while IFS= read -r m; do
        dest2="${m#+}"
        case "$dest2" in *:*) dest2="${dest2##*:}" ;; esac
        case "$dest2" in
          main | refs/heads/main)
            reason="'$seg' pushes via remote.$remote.push mapping to main"; return 0 ;;
        esac
      done < <(git -C "${cdir:-${cwd:-.}}" config --get-all "remote.$remote.push" 2>/dev/null)
    fi
    # Resolves default-remote mappings via @{push} and named remote.<name>.push
    # entries; push.default=matching is not modeled.
    case "$(push_dest "$cdir")" in
      */main) reason="'$seg' is a bare push whose configured destination is main"; return 0 ;;
    esac
  fi
}

while IFS= read -r seg; do
  check_segment "$seg"
  [ -n "$reason" ] && break
done < <(printf '%s\n' "$cmd" | tr ';&|' '\n')

[ -n "$reason" ] && deny "$reason"
exit 0
