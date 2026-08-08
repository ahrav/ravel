# ravel

Distributed, local-first runtime for autonomous engineering campaigns.

A transient fleet of machines collaboratively investigates objectives, generates and
evaluates work, challenges results, and converges on validated outputs.

```text
Generator proposes.
Oracle measures.
Judge interprets.
Controller decides.
```

- Local-first: every node runs the same Rust binary with a local SQLite projection.
- Distributed: shared object storage (S3) is the durable log, artifact store, and narrow coordination authority.
- No permanent coordinator, no consensus system, no always-online requirement.

See [docs/mvp-outline.md](docs/mvp-outline.md) for the working plan and MVP spec.

Task tracking uses [beads](https://github.com/steveyegge/beads) (`bd`) with [beadsviewer](https://github.com/Dicklesworthstone/beads_viewer) (`bv`).
