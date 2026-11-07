// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// policyHoldReasonForTest is the reason of a journal row the watcher wrote
// for a policy hold of the given fields on the given copies (the watcher
// pins this shape in TestGAP0613PolicyHoldTagShape).
func policyHoldReasonForTest(fields string, copies ...string) string {
	keys := ""
	for i, copy := range copies {
		if i > 0 {
			keys += ","
		}
		keys += base64.RawURLEncoding.EncodeToString([]byte(copy))
	}
	return "quarantine failed: test [asset policy: " + fields + " copies=" + keys + "]"
}

func policyHoldCopyForTest(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func policyHoldAPIForTest(t *testing.T) (*APIServer, *audit.Store) {
	t.Helper()
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	store, _ := testStoreAndLogger(t)
	return &APIServer{scannerCfg: cfg, store: store}, store
}

// GAP-0613 review 14: two copies of one skill name are denied and stay in
// their folders; an allow rule then admits the second. The journal row is
// keyed by the name, but the hold on it was written for the first copy: a
// call that runs the admitted second copy is not refused, and every call that
// reaches the first copy, or cannot be placed, still is.
func TestGAP0613PolicyHoldOnOneCopyDoesNotRefuseTheAdmittedCopyOfTheName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the hold tag keys fold case on Windows")
	}
	api, store := policyHoldAPIForTest(t)
	root := t.TempDir()
	held := policyHoldCopyForTest(t, filepath.Join(root, "b"), "shared-name")
	admitted := policyHoldCopyForTest(t, filepath.Join(root, "c"), "shared-name")
	if err := store.SetActionFieldForConnector("skill", "shared-name", "codex", "runtime", "disable", policyHoldReasonForTest("runtime", held)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		label string
		probe skillRuntimeProbe
		block bool
	}{
		{"the admitted copy", skillRuntimeProbe{SourcePath: admitted}, false},
		{"a file of the admitted copy", skillRuntimeProbe{SourcePath: filepath.Join(admitted, "SKILL.md")}, false},
		{"the held copy", skillRuntimeProbe{SourcePath: held}, true},
		{"a file of the held copy", skillRuntimeProbe{SourcePath: filepath.Join(held, "SKILL.md")}, true},
		{"a call that names no path", skillRuntimeProbe{}, true},
		{"a call that may load either copy", skillRuntimeProbe{SourcePaths: []string{admitted, held}}, true},
		{"a path with a parent element", skillRuntimeProbe{SourcePath: admitted + "/../../b/shared-name"}, true},
	} {
		tc.probe.SkillName, tc.probe.ToolName, tc.probe.Surface, tc.probe.Matched = "shared-name", "Skill", "hook", true
		decision, matched := api.runtimeSkillAssetPolicyDecision(context.Background(), "codex", tc.probe)
		if matched != tc.block {
			t.Errorf("%s: matched=%v decision=%+v, want blocked=%v", tc.label, matched, decision, tc.block)
		}
	}
	// Control: a runtime disable no hold set refuses every copy.
	if err := store.SetActionFieldForConnector("skill", "shared-name", "codex", "runtime", "disable", "operator disabled"); err != nil {
		t.Fatal(err)
	}
	if _, matched := api.runtimeSkillAssetPolicyDecision(context.Background(), "codex", skillRuntimeProbe{
		SkillName: "shared-name", ToolName: "Skill", Surface: "hook", Matched: true, SourcePath: admitted,
	}); !matched {
		t.Error("an operator runtime disable no longer refuses the second copy")
	}
}

// The plugin install journal is read by name for every plugin call; a hold on
// one copy does not refuse the admitted copy of the name either.
func TestGAP0613PluginPolicyHoldOnOneCopyDoesNotRefuseTheAdmittedCopyOfTheName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the hold tag keys fold case on Windows")
	}
	api, store := policyHoldAPIForTest(t)
	root := t.TempDir()
	held := policyHoldCopyForTest(t, filepath.Join(root, "b"), "shared-plugin")
	admitted := policyHoldCopyForTest(t, filepath.Join(root, "c"), "shared-plugin")
	reason := policyHoldReasonForTest("install,runtime", held)
	for field, value := range map[string]string{"install": "block", "runtime": "disable"} {
		if err := store.SetActionFieldForConnector("plugin", "shared-plugin", "claudecode", field, value, reason); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		label string
		path  string
		block bool
	}{
		{"the admitted copy", admitted, false},
		{"the held copy", held, true},
		{"a call that names no path", "", true},
	} {
		_, matched := api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
			TargetType: "plugin", SkillName: "shared-plugin", Surface: "hook", Matched: true, SourcePath: tc.path,
		})
		if matched != tc.block {
			t.Errorf("%s: matched=%v, want blocked=%v", tc.label, matched, tc.block)
		}
	}
	// Control: an install block no hold set refuses every copy.
	if err := store.SetActionFieldForConnector("plugin", "shared-plugin", "claudecode", "install", "block", "operator blocked"); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearActionFieldForConnector("plugin", "shared-plugin", "claudecode", "runtime"); err != nil {
		t.Fatal(err)
	}
	if _, matched := api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
		TargetType: "plugin", SkillName: "shared-plugin", Surface: "hook", Matched: true, SourcePath: admitted,
	}); !matched {
		t.Error("an operator install block no longer refuses the second copy")
	}
}
