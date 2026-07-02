import { copyFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

const require = createRequire(import.meta.url);
const packageRoot = dirname(require.resolve('@lobehub/icons-static-svg/package.json'));
const targetRoot = join(process.cwd(), 'public', 'connector-icons');

const icons: Record<string, string> = {
  'antigravity-color.svg': 'antigravity.svg',
  'claudecode-color.svg': 'claudecode.svg',
  'codex-color.svg': 'codex.svg',
  'githubcopilot.svg': 'copilot.svg',
  'cursor.svg': 'cursor.svg',
  'geminicli-color.svg': 'geminicli.svg',
  'hermesagent.svg': 'hermes.svg',
  'openclaw-color.svg': 'openclaw.svg',
  'opencode.svg': 'opencode.svg',
  'openhands-color.svg': 'openhands.svg',
  'windsurf.svg': 'windsurf.svg',
};

await mkdir(targetRoot, { recursive: true });
await Promise.all(
  Object.entries(icons).map(async ([source, target]) => {
    try {
      await copyFile(join(packageRoot, 'icons', source), join(targetRoot, target));
    } catch (error) {
      throw new Error(`Failed to sync connector icon ${source} -> ${target}`, { cause: error });
    }
  }),
);

console.log(`[sync-connector-icons] synced ${Object.keys(icons).length} LobeHub icons.`);
