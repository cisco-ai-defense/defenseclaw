import { copyFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { connectorIconDefinitions } from '../data/connector-icons';

const require = createRequire(import.meta.url);
const packageRoot = dirname(require.resolve('@lobehub/icons-static-svg/package.json'));
const targetRoot = join(process.cwd(), 'public', 'connector-icons');

await mkdir(targetRoot, { recursive: true });
await Promise.all(
  Object.values(connectorIconDefinitions).map(async ({ source, target }) => {
    try {
      await copyFile(join(packageRoot, 'icons', source), join(targetRoot, target));
    } catch (error) {
      throw new Error(`Failed to sync connector icon ${source} -> ${target}`, { cause: error });
    }
  }),
);

console.log(`[sync-connector-icons] synced ${Object.keys(connectorIconDefinitions).length} LobeHub icons.`);
