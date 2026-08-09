import { execFileSync } from "node:child_process"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import type { Plugin } from "@opencode-ai/plugin"

// Policy: never commit or push to main without explicit user approval.
// Delegates to the shared guard used by Claude Code, Codex, and pi.
const GUARD = join(dirname(fileURLToPath(import.meta.url)), "..", "..", ".agents", "hooks", "block-main.sh")

export const MainBranchGuard: Plugin = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    if (input.tool !== "bash") return
    const cmd = output?.args?.command
    if (typeof cmd !== "string" || !/commit|push/.test(cmd)) return
    try {
      execFileSync(GUARD, ["--cmd", cmd, "--cwd", output?.args?.workdir ?? directory], { timeout: 15000 })
    } catch (e: any) {
      if (e?.status === 2) throw new Error(String(e.stdout ?? "Blocked: main-branch policy"))
      // Guard missing or broken: fail open; this is a guardrail, not a security boundary.
    }
  },
})
