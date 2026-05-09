// Hero terminal-demo connector list. Lives outside the React tree so
// both <HeroLockup> (which drives the rotation) and <TerminalDemo>
// (which renders the per-connector block) can import it without
// creating a circular dependency. Order matches /docs/connectors so
// the rotation reads the same as the docs nav.
//
// Setup aliases verified against docs/setup/guardrail/aliases/:
//   - proxies (OpenClaw, ZeptoClaw) → defenseclaw setup guardrail
//   - hooks  → defenseclaw setup {claude-code|codex|hermes|cursor|
//                                  windsurf|geminicli|copilot}

export interface ConnectorBlock {
  id: string;
  label: string;
  // Setup command for the typed prompt line.
  command: string;
  // Lowercase id used in the "Active connector set to <id>
  // (claw.mode=<id>)" line. Mirrors the keys in
  // data/capability-matrix.json.
  modeId: string;
}

export const TERMINAL_CONNECTORS: ConnectorBlock[] = [
  { id: 'openclaw',   label: 'OpenClaw',           command: 'defenseclaw setup guardrail',   modeId: 'openclaw' },
  { id: 'zeptoclaw',  label: 'ZeptoClaw',          command: 'defenseclaw setup guardrail',   modeId: 'zeptoclaw' },
  { id: 'claudecode', label: 'Claude Code',        command: 'defenseclaw setup claude-code', modeId: 'claudecode' },
  { id: 'codex',      label: 'Codex',              command: 'defenseclaw setup codex',       modeId: 'codex' },
  { id: 'hermes',     label: 'Hermes',             command: 'defenseclaw setup hermes',      modeId: 'hermes' },
  { id: 'cursor',     label: 'Cursor',             command: 'defenseclaw setup cursor',      modeId: 'cursor' },
  { id: 'windsurf',   label: 'Windsurf',           command: 'defenseclaw setup windsurf',    modeId: 'windsurf' },
  { id: 'geminicli',  label: 'Gemini CLI',         command: 'defenseclaw setup geminicli',   modeId: 'geminicli' },
  { id: 'copilot',    label: 'GitHub Copilot CLI', command: 'defenseclaw setup copilot',     modeId: 'copilot' },
];
