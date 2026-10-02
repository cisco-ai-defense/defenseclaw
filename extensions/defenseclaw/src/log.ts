/**
 * Routine DefenseClaw plugin diagnostics.
 *
 * OpenClaw also loads plugins inside its interactive terminal UI, where a
 * stdout line is drawn over the chat screen and its input box (GAP-1454).
 * Routine lines therefore print only when stdout is not a terminal (the
 * gateway service log) or when DEFENSECLAW_DEBUG=1. Warnings and
 * errors keep using console.warn / console.error.
 */
export function logInfo(message: string): void {
  if (process.env.DEFENSECLAW_DEBUG === "1" || !process.stdout?.isTTY) {
    console.log(message);
  }
}
