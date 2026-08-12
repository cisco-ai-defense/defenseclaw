// Suggest a fix when someone fat-fingers a command on first run (`s-gw statu`,
// `s-gw secrets list`). Kept out of cli.ts so it can be unit-tested without importing
// the CLI entry point, which runs main() on import.

// The full vocabulary of top-level + two-word commands.
export const KNOWN_COMMANDS = [
  "init",
  "setup",
  "status",
  "start",
  "stop",
  "doctor",
  "update check",
  "update plan",
  "update install",
  "console",
  "help",
  "app open",
  "app app-path",
  "app install",
  "guard status",
  "guard run",
  "run",
  "service install",
  "service start",
  "service stop",
  "service status",
  "service uninstall",
  "menubar open",
  "menubar install",
  "menubar start",
  "menubar stop",
  "menubar status",
  "menubar uninstall",
  "menubar app-path",
  "helper open",
  "helper app-path",
  "unlock status",
  "unlock keychain set",
  "unlock keychain delete",
  "unlock keychain repair",
  "secret add",
  "secret add-1password",
  "secret list",
  "secret delete",
  "onepassword status",
  "onepassword import",
  "onepassword capture",
  "aws plan",
  "aws request",
  "aws run",
  "approval settings",
  "approval set",
  "approval grants",
  "approval revoke",
  "approval clear",
  "scan-file",
  "agent list",
  "agent status",
  "agent install",
  "agent uninstall",
  "agent show",
  "agent mcp-snippet",
  "agent codeguard-plan",
  "request env-command",
  "requests",
  "requests cleanup",
  "store backups",
  "approve",
  "deny",
  "execute",
  "execute-next"
];

export function unknownCommandMessage(command: string[]): string {
  const typed = command.join(" ");
  const suggestions = suggestCommands(command);
  const tail = suggestions.length
    ? ` Did you mean: ${suggestions.map((s) => `s-gw ${s}`).join(", ")}? Run \`s-gw help\` for all commands.`
    : " Run `s-gw help` to see all commands.";
  return `Unknown command: ${typed}.${tail}`;
}

// Suggest the closest known commands to what was typed. We match on the whole phrase
// and on the first word (so a trailing positional arg the user typed can't drown out
// the verb match), then fall back to listing a known noun's subcommands.
export function suggestCommands(command: string[], limit = 3): string[] {
  const typed = command.join(" ").trim().toLowerCase();
  if (!typed) {
    return [];
  }

  const first = (command[0] || "").toLowerCase();

  // Score each candidate by the better of: full-phrase distance, or first-word distance
  // against the candidate's own first word. The latter means `aproove <id>` still maps to
  // `approve` even though the trailing arg inflates the phrase distance.
  const scored = KNOWN_COMMANDS.map((candidate) => {
    const phraseDistance = editDistance(typed, candidate);
    const wordDistance = first ? editDistance(first, candidate.split(" ")[0]) : phraseDistance;
    return { candidate, distance: Math.min(phraseDistance, wordDistance) };
  }).sort((a, b) => a.distance - b.distance);

  // Threshold tracks the shorter of the typed verb / full phrase so short typos
  // (`statu`) still match without a one-word verb matching everything.
  const threshold = Math.max(2, Math.ceil(Math.min(typed.length, Math.max(first.length, 1)) / 3) + 1);
  const best = scored[0]?.distance ?? Infinity;
  if (best <= threshold) {
    // Keep only suggestions within 1 edit of the best match so a clear winner
    // (`deny` for `deni`) isn't diluted by weaker, coincidental matches.
    return scored
      .filter((entry) => entry.distance <= Math.min(threshold, best + 1))
      .map((entry) => entry.candidate)
      .slice(0, limit);
  }

  // No close match — if the noun is real, list its subcommands so a user who typed
  // `s-gw secret` (forgetting `add`/`list`) still gets pointed the right way.
  if (first) {
    const sameNoun = KNOWN_COMMANDS.filter((candidate) => candidate.split(" ")[0] === first && candidate !== first);
    if (sameNoun.length) {
      return sameNoun.slice(0, limit);
    }
  }

  return [];
}

// Plain Levenshtein. Small command set, runs once on an error path — clarity over cleverness.
function editDistance(a: string, b: string): number {
  const rows = a.length + 1;
  const cols = b.length + 1;
  const dist = Array.from({ length: rows }, () => new Array<number>(cols).fill(0));
  for (let i = 0; i < rows; i += 1) {
    dist[i][0] = i;
  }
  for (let j = 0; j < cols; j += 1) {
    dist[0][j] = j;
  }

  for (let i = 1; i < rows; i += 1) {
    for (let j = 1; j < cols; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dist[i][j] = Math.min(dist[i - 1][j] + 1, dist[i][j - 1] + 1, dist[i - 1][j - 1] + cost);
    }
  }

  return dist[rows - 1][cols - 1];
}
