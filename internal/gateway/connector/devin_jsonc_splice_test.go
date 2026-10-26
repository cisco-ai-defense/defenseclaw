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
	original := "// project hooks: keep this note\n{\n  /* lint hook */\n  \"PreToolUse\": " + foreignPre +
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
