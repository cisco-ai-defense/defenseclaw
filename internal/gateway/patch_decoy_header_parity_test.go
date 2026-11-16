// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestPatchDecoyHeaderNeverWeakerThanTheSinglePatch{Default,Strict,Permissive,Managed,ManagedStrict}:
// an apply_patch envelope that holds a Claude Code Write or Edit target of the
// fixture set and, before or after it, one block of a file no reader places (a
// drive-relative or home name) is judged at least as its single-header patch
// is, on every patch route (Codex apply_patch command and input, OpenCode patch
// patchText): each placed header is still read by the path and content rules,
// and the header no reader places only adds the unknown-tier finding, which
// never lowers a proven block (rel-1-0-10:GAP-1055). Before, that header
// dropped every placed change and the envelope was judged at the unknown tier
// only: alert in default, permissive and managed, where the single-header patch
// blocks. One top-level test per tier, so the -race shards can take them apart.
func TestPatchDecoyHeaderNeverWeakerThanTheSinglePatchDefault(t *testing.T) {
	patchDecoyHeaderNeverWeaker(t, "default")
}

func TestPatchDecoyHeaderNeverWeakerThanTheSinglePatchStrict(t *testing.T) {
	patchDecoyHeaderNeverWeaker(t, "strict")
}

func TestPatchDecoyHeaderNeverWeakerThanTheSinglePatchPermissive(t *testing.T) {
	patchDecoyHeaderNeverWeaker(t, "permissive")
}

func TestPatchDecoyHeaderNeverWeakerThanTheSinglePatchManaged(t *testing.T) {
	patchDecoyHeaderNeverWeaker(t, "managed")
}

func TestPatchDecoyHeaderNeverWeakerThanTheSinglePatchManagedStrict(t *testing.T) {
	patchDecoyHeaderNeverWeaker(t, "managed-strict")
}

func patchDecoyHeaderNeverWeaker(t *testing.T, tier string) {
	index := slices.IndexFunc(gap0437Packs, func(p gap0437Pack) bool { return p.name == tier })
	if index < 0 {
		t.Fatalf("no tier %q in gap0437Packs", tier)
	}
	p := gap0437Packs[index]
	all := shapeParityCases(t)
	cases := all[:0]
	for _, c := range all {
		if strings.HasPrefix(c.id, "wincred/") && (c.tool == "Write" || c.tool == "Edit") {
			cases = append(cases, c)
		}
	}
	if len(cases) == 0 {
		t.Fatal("no wincred Write or Edit fixture cases")
	}
	codexHeaders := map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse",
		"X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract}
	cwd := t.TempDir()
	handlers := shapeParityHandlers(t, p)
	routes := func(envelope string) map[string]shapeParityCall {
		return map[string]shapeParityCall{
			"codex/command": {name: "codex", conn: "codex", event: "PreToolUse", headers: codexHeaders,
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": envelope})},
			"codex/input": {name: "codex", conn: "codex", event: "PreToolUse", headers: codexHeaders,
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"input": envelope})},
			"opencode/patchText": {name: "opencode", conn: "opencode", event: "tool.execute.before",
				body: shapeParityOpenCode(cwd, "patch", map[string]any{"patchText": envelope})},
		}
	}
	blocked := 0
	for _, c := range cases {
		str := func(key string) string { value, _ := c.args[key].(string); return value }
		// The fixture name on Windows; elsewhere the same name with forward
		// slashes, the spelling whose single-header patch a Linux or macOS
		// gateway blocks (there a backslash is a character of a file name).
		target := str("file_path")
		if runtime.GOOS != "windows" {
			target = strings.ReplaceAll(target, `\`, "/")
		}
		single := shapeParityPatch(target, str("content"))
		if c.tool == "Edit" {
			single = shapeParityUpdatePatch(target, str("old_string"), str("new_string"))
		}
		body := strings.TrimSuffix(strings.TrimPrefix(single, "*** Begin Patch\n"), "\n*** End Patch")
		decoys := map[string]string{
			"unplaced-first": "*** Begin Patch\n*** Add File: C:decoy.txt\n+x\n" + body + "\n*** End Patch",
			"unplaced-last":  "*** Begin Patch\n" + body + "\n*** Add File: ~/decoy.txt\n+x\n*** End Patch",
		}
		for route, call := range routes(single) {
			want := shapeParityHook(t, handlers[call.conn], call, p.managed)
			if want == "block" {
				blocked++
			}
			for decoy, envelope := range decoys {
				decoyCall := routes(envelope)[route]
				got := shapeParityHook(t, handlers[decoyCall.conn], decoyCall, p.managed)
				if shapeParityRank[got] < shapeParityRank[want] {
					t.Errorf("%s %s %s %s: %q, the single-header patch %q", c.id, c.tool, route, decoy, got, want)
				}
			}
		}
	}
	if blocked == 0 {
		t.Fatal("no single-header patch of the fixture targets blocks: the test no longer pins a placed block")
	}
}
