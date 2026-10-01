// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
// Called by TestDeepSeekPublishedBridge with an isolated, pinned npm install.
// Exercises the actual vendor bridge with a local shell/session service fixture.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const [modulePath, configPath, hookPath, dataDir] = process.argv.slice(2);
const metadata = JSON.parse(await readFile(resolve(dirname(modulePath), '../package.json'), 'utf8'));
assert.equal(metadata.name, '@deepseek-ai/dsh-hooks-claude-code');
assert.equal(metadata.version, '0.2.0-rc.2');
const { apply } = await import(pathToFileURL(modulePath).href);
const listeners = new Map();
const cleanups = [];
const payloads = [];
const agent = {
  session: { header: { id: 'session-fixture', cwd: dataDir }, append() {} },
  inject() {},
  steer() { throw new Error('DefenseClaw must not force Stop continuation'); },
};
const quote = (value) => "'" + value.replaceAll("'", "'\\''") + "'";
const ctx = {
  on(event, callback) { listeners.set(event, callback); },
  effect(factory) { cleanups.push(factory()); },
  get() { return undefined; },
  logger: { warn(message) { throw new Error(message); } },
  sessionProjections: { stateOf() { return { lastTurn: 1 }; } },
  shell: {
    resolve(request) {
      assert.equal(request.command, quote(hookPath));
      payloads.push(JSON.parse(request.stdin));
      return request;
    },
    async execute(request) {
      // Execute the admitted fixture path as one argument; never interpret the
      // payload or an arbitrary vendor command as shell source.
      const child = spawn('/bin/bash', [hookPath], {
        cwd: dataDir,
        env: { ...process.env, DEFENSECLAW_HOME: dataDir },
        stdio: ['pipe', 'pipe', 'pipe'],
        signal: request.signal,
      });
      let stdout = '', stderr = '';
      child.stdout.setEncoding('utf8').on('data', part => { stdout += part; });
      child.stderr.setEncoding('utf8').on('data', part => { stderr += part; });
      const result = new Promise((resolve, reject) => {
        child.on('error', reject);
        child.on('close', exitCode => resolve({ exitCode, stdout: { text: stdout }, stderr: { text: stderr } }));
      });
      child.stdin.end(request.stdin);
      return { result: () => result };
    },
  },
};
apply(ctx, { configPath });
const signal = AbortSignal.timeout(30000);
for (const [command, expected] of [['safe', 'allow'], ['blocked', 'deny'], ['confirm', 'ask']]) {
  let nextCalled = false;
  const exec = { agent, name: 'bash', arguments: { command, description: 'inert test fixture' }, callId: 'call-' + command, signal };
  const decision = await listeners.get('tools/pre-execute')(exec, async () => { nextCalled = true; return { kind: 'allow' }; });
  assert.equal(decision.kind, expected);
  assert.equal(nextCalled, expected === 'allow');
  const payload = payloads.at(-1);
  assert.equal(payload.hook_event_name, 'PreToolUse');
  assert.equal(payload.session_id, 'session-fixture');
  assert.equal(payload.tool_use_id, exec.callId);
  assert.deepEqual(payload.tool_input, exec.arguments);
}
const promptDecision = await listeners.get('agent/pre-step')({ agent, messages: [{ content: [{ type: 'text', text: 'blocked prompt' }] }], turn: 1, signal }, async () => { throw new Error('blocked prompt reached next'); });
assert.equal(promptDecision.kind, 'reject');
const result = await listeners.get('tools/post-execute')(
  { agent, name: 'bash', arguments: { command: 'safe' }, callId: 'call-safe', signal },
  { content: [{ type: 'text', text: 'fixture output' }], isError: true },
  async () => ({ kind: 'accept' }),
);
assert.equal(result.kind, 'accept');
assert.equal(payloads.at(-1).tool_response, 'fixture output');
assert.equal(payloads.at(-1).isError, undefined);
await listeners.get('agent/turn-stopping')({ agent, turn: 1, signal });
for (const cleanup of cleanups) await cleanup();
console.log('Published DeepSeek bridge: allow, deny, ask, prompt block, payload correlation, observational result and Stop passed.');
