import { execFileSync } from "node:child_process"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent"

// Policy: never commit or push to main without explicit user approval.
// Delegates to the shared guard used by Claude Code, Codex, and opencode.
const GUARD = join(dirname(fileURLToPath(import.meta.url)), "..", "..", ".agents", "hooks", "block-main.sh")

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event) => {
    if (event.toolName !== "bash") return
    const cmd = String((event.input as { command?: string }).command ?? "")
    if (!/commit|push/.test(cmd)) return
    try {
      execFileSync(GUARD, ["--cmd", cmd], { timeout: 15000 })
    } catch (e: any) {
      if (e?.status === 2) return { block: true, reason: String(e.stdout ?? "Blocked: main-branch policy") }
      // Guard missing or broken: fail open; this is a guardrail, not a security boundary.
    }
  })
}
