# Agent Instructions

Progressive disclosure: this file holds only always-on rules. Workflows live in linked files — read them when the task touches that area.

## Git Policy (always on)

- **Never commit or push to `main`** unless the user explicitly says it's fine.
- All work goes on **feature branches**. Completed work is pushed to a feature branch and a **PR is opened for review**.
- Do not commit or push at all without clear authority from the current user request.

## Workflows

- **Issue tracking (beads/bd)**: [docs/workflows/beads.md](docs/workflows/beads.md) — required reading before claiming or closing any task. Quick start: `bd ready` → `bd update <id> --claim` → work → `bd close <id>`.
