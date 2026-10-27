// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0192: setup devin --workspace rewrote the project .devin/hooks.v1.json
// with json.MarshalIndent, so the operator's JSONC comments were lost. Setup
// now edits only DefenseClaw's events: comments, foreign hook groups and a
// foreign "hooks" key keep their bytes, and the file still decodes to the
// same hook map.
func TestPatchDevinProjectHooksKeepsOperatorCommentsAndForeignHooks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".devin", "hooks.v1.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	foreignPre := `[{"matcher":"*","hooks":[{"type":"command","command":"/bin/true"}]}]`
	foreignHooks := `{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/bin/true"}]}]}`
	// PostToolUse first: the events are edited in document order.
	original := "// project hooks: keep this note\n{\n  \"PostToolUse\": [],\n  /* lint hook */\n  \"PreToolUse\": " + foreignPre +
		",\n  \"hooks\": " + foreignHooks + ", // a foreign set\n}\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "/home/u/.defenseclaw/hooks/devin-hook.sh"
	if err := patchDevinHooks(path, script); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, keep := range []string{"// project hooks: keep this note\n", "/* lint hook */", "// a foreign set", foreignHooks, `"command":"/bin/true"`} {
		if !strings.Contains(text, keep) {
			t.Fatalf("setup dropped %q:\n%s", keep, text)
		}
	}
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		t.Fatalf("result does not parse: %v\n%s", err, text)
	}
	for _, event := range devinHookEvents {
		if !devinHookGroupReferences(lastDevinGroup(cfg[event]), script) {
			t.Fatalf("%s lacks the DefenseClaw hook:\n%s", event, text)
		}
	}
	if groups, _ := cfg["PreToolUse"].([]interface{}); len(groups) != 2 {
		t.Fatalf("PreToolUse = %v; want the foreign group and DefenseClaw's", cfg["PreToolUse"])
	}
	// A second setup is a no-op edit: the same bytes.
	if err := patchDevinHooks(path, script); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(path); string(again) != text {
		t.Fatalf("re-run changed the file:\n%s\n---\n%s", text, again)
	}
}

func lastDevinGroup(raw interface{}) interface{} {
	list, _ := raw.([]interface{})
	if len(list) == 0 {
		return nil
	}
	return list[len(list)-1]
}

// GAP-1944: a project hooks.v1.json saved with a UTF-8 BOM (Windows
// PowerShell 5.1) kept neither its BOM nor its comments, because the splice
// did not scan past the BOM; and teardown rewrote the file with
// json.MarshalIndent. Both now edit only DefenseClaw's members.
func TestDevinProjectHooksSetupAndTeardownKeepABOMAndTheComments(t *testing.T) {
	for _, bom := range []string{"", "\ufeff"} {
		dir := t.TempDir()
		path := filepath.Join(dir, ".devin", "hooks.v1.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		foreignPre := `[{"matcher":"*","hooks":[{"type":"command","command":"/bin/true"}]}]`
		original := bom + "// project hooks: keep this note\n{\n  /* lint hook */\n  \"PreToolUse\": " + foreignPre + ", // foreign\n  \"Custom\": 1\n}\n"
		if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}
		script := "/home/u/.defenseclaw/hooks/devin-hook.sh"
		if err := patchDevinHooks(path, script); err != nil {
			t.Fatal(err)
		}
		set, _ := os.ReadFile(path)
		for _, keep := range []string{bom + "// project hooks: keep this note\n", "/* lint hook */", "// foreign", `"Custom": 1`} {
			if !strings.HasPrefix(string(set), bom) || !strings.Contains(string(set), keep) {
				t.Fatalf("bom=%q: setup dropped %q:\n%s", bom, keep, set)
			}
		}
		if ok, err := devinConfigReferencesHook(path, script); err != nil || !ok {
			t.Fatalf("bom=%q: setup did not register the hook (%v):\n%s", bom, err, set)
		}
		if err := removeDevinHookReferences(path, script); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(path)
		for _, keep := range []string{bom + "// project hooks: keep this note\n", "/* lint hook */", "// foreign", `"Custom": 1`} {
			if !strings.HasPrefix(string(got), bom) || !strings.Contains(string(got), keep) {
				t.Fatalf("bom=%q: teardown dropped %q:\n%s", bom, keep, got)
			}
		}
		cfg, err := readDevinJSONObject(path)
		if err != nil {
			t.Fatalf("bom=%q: teardown result does not parse: %v\n%s", bom, err, got)
		}
		if strings.Contains(string(got), "\n  \n") {
			t.Fatalf("bom=%q: teardown left blank lines:\n%s", bom, got)
		}
		if len(cfg) != 2 || cfg["Custom"] == nil {
			t.Fatalf("bom=%q: teardown left %v; want only PreToolUse and Custom:\n%s", bom, cfg, got)
		}
		if groups, _ := cfg["PreToolUse"].([]interface{}); len(groups) != 1 || devinHookGroupReferences(groups[0], script) {
			t.Fatalf("bom=%q: PreToolUse = %v; want only the foreign group", bom, cfg["PreToolUse"])
		}
	}
}
