// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/** Parse-check every runnable shell fence in public and supporting docs. */

import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const REPO_ROOT = resolve(process.cwd(), '..');
const DOC_ROOTS = [resolve(process.cwd(), 'content/docs'), resolve(REPO_ROOT, 'docs')];
const SHELL_FENCE = /^```(?:bash|sh|shell|zsh)(?:[^\n]*)\n([\s\S]*?)^```[ \t]*$/gm;

function listDocumentationFiles(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...listDocumentationFiles(path));
    } else if (entry.isFile() && (entry.name.endsWith('.mdx') || entry.name.endsWith('.md'))) {
      files.push(path);
    }
  }
  return files.sort();
}

const failures: string[] = [];
let snippetCount = 0;

const documentationFiles = DOC_ROOTS.flatMap(listDocumentationFiles).sort();

for (const path of documentationFiles) {
  const source = readFileSync(path, 'utf8');
  for (const match of source.matchAll(SHELL_FENCE)) {
    snippetCount += 1;
    const line = source.slice(0, match.index).split('\n').length;
    const result = spawnSync('bash', ['-n'], {
      encoding: 'utf8',
      input: match[1],
    });

    if (result.error) {
      failures.push(`${relative(process.cwd(), path)}:${line}: ${result.error.message}`);
    } else if (result.status !== 0) {
      const detail = result.stderr.trim().replaceAll('\n', ' | ');
      failures.push(`${relative(process.cwd(), path)}:${line}: ${detail}`);
    }
  }
}

if (failures.length > 0) {
  console.error('Shell snippet validation failed:');
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Validated shell syntax in ${snippetCount} documentation code fences.`);
