# Beads Workflow

This project uses **bd** (beads) for issue tracking, with [perles](https://github.com/zjrosen/perles) as the TUI. Issues are stored in `.beads/` (Dolt-backed) and tracked in git. Run `bd onboard` to get started, `bd prime` to refresh context.

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See <https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md> for details and anti-patterns.

## Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
perles

# CLI commands for agents (use these instead)
bd ready              # Show issues ready to work (no blockers)
bd list --status=open # All open issues
bd show <id>          # Full issue details with dependencies
bd create --title="..." --type=task --priority=2
bd update <id> --claim  # Claim work (assignee + in_progress)
bd close <id> --reason="Completed"
bd close <id1> <id2>  # Close multiple issues at once
bd prime              # Refresh Beads context
```

## Workflow Pattern

1. **Start**: Run `bd ready` to find actionable work
2. **Claim**: Use `bd update <id> --claim`
3. **Work**: Implement the task, including the task's own Final Step checklist
4. **Complete**: Use `bd close <id>`
5. **Commit**: Commit `.beads/` changes on a feature branch at session end (bd auto-exports `.beads/issues.jsonl`) — see the git policy in `AGENTS.md`

## Key Concepts

- **Dependencies**: Issues can block other issues. `bd ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `bd dep add <issue> <depends-on>` to add dependencies

## Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md or ad hoc memory files
- Create new issues with `bd create` when you discover tasks; use descriptive titles and appropriate priority/type
- Update status as you work (in_progress → closed)
- The `beads` skill at `.agents/skills/beads/SKILL.md` (project) or `~/.agents/skills/beads/SKILL.md` (global) has further workflow guidance

## Session Completion

Subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** — create beads for anything needing follow-up
2. **Run quality gates** (if code changed) — tests, linters, builds
3. **Update issue status** — close finished work, update in-progress items
4. **Git**: follow the git policy in `AGENTS.md` — feature branch, PR; never push main. Report status and proposed commands; wait for approval before committing/pushing.
5. **Hand off** — summarize changes, validation, issue status, and any blocked sync/commit/push step

If a required sync or push is blocked, stop and report the exact command and error.
