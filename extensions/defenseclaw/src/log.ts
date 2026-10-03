/**
 * Routine DefenseClaw plugin diagnostics.
 *
 * OpenClaw also loads plugins inside its interactive terminal UI, where a
 * stdout line is drawn over the chat screen and its input box (GAP-1454),
 * and inside its CLI commands (`openclaw models list`, `openclaw config
 * get`), where the lines land above the command's own output and break
 * scripted use (GAP-1737). Routine lines therefore print only in the
 * OpenClaw gateway service (or another host process) whose stdout is not a
 * terminal, which is the gateway log, or when DEFENSECLAW_DEBUG=1.
 * Warnings and errors keep using console.warn / console.error.
 */
export function logInfo(message: string): void {
  if (process.env.DEFENSECLAW_DEBUG === "1" || (!process.stdout?.isTTY && !isOpenClawClientProcess())) {
    console.log(message);
  }
}

/**
 * OpenClaw names its processes: `openclaw-gateway` for the gateway,
 * `openclaw-tui` for the terminal UI and `openclaw` for a CLI command.
 * Everything except the gateway is a client the user is reading.
 */
export function isOpenClawClientProcess(title: string = process.title): boolean {
  const name = title.trim().split(/\s+/)[0] ?? "";
  return (name === "openclaw" || name.startsWith("openclaw-")) && name !== "openclaw-gateway";
}
