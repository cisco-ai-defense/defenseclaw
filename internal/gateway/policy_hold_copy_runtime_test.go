// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// A link to the held copy, to a folder below it or to a file in it still
// reaches the protected files. Each is resolved before it is compared, so the
// runtime hold refuses every one, for a skill and for a plugin; a link to the
// admitted copy of the name runs.
func TestPolicyHoldRefusesLinksIntoTheHeldCopy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the hold tag keys fold case on Windows")
	}
	for _, targetType := range []string{"skill", "plugin"} {
		t.Run(targetType, func(t *testing.T) {
			api, store := policyHoldAPIForTest(t)
			root := t.TempDir()
			name, connector := "shared-"+targetType, "codex"
			if targetType == "plugin" {
				connector = "claudecode"
			}
			held := policyHoldCopyForTest(t, filepath.Join(root, "held"), name)
			admitted := policyHoldCopyForTest(t, filepath.Join(root, "admitted"), name)
			if err := os.MkdirAll(filepath.Join(held, "nested"), 0o700); err != nil {
				t.Fatal(err)
			}
			links := map[string]string{
				"folder-alias": held,
				"nested-alias": filepath.Join(held, "nested"),
				"file-alias":   filepath.Join(held, "SKILL.md"),
				"ok-alias":     admitted,
			}
			for alias, target := range links {
				if err := os.Symlink(target, filepath.Join(root, alias)); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			reason := policyHoldReasonForTest("install,runtime", held)
			for field, value := range map[string]string{"install": "block", "runtime": "disable"} {
				if err := store.SetActionFieldForConnector(targetType, name, connector, field, value, reason); err != nil {
					t.Fatal(err)
				}
			}
			for label, path := range map[string]string{
				"held folder": held, "held file": filepath.Join(held, "SKILL.md"),
				"link to the held folder": filepath.Join(root, "folder-alias"),
				"link to a nested folder": filepath.Join(root, "nested-alias"),
				"link to a held file":     filepath.Join(root, "file-alias"),
				"file below a held link":  filepath.Join(root, "folder-alias", "SKILL.md"),
			} {
				decision, matched := api.runtimeSkillAssetPolicyDecision(context.Background(), connector, skillRuntimeProbe{
					TargetType: targetType, SkillName: name, ToolName: "Skill", Surface: "hook", Matched: true, SourcePath: path,
				})
				if !matched {
					t.Errorf("%s: protected path allowed: %+v", label, decision)
				}
			}
			if decision, matched := api.runtimeSkillAssetPolicyDecision(context.Background(), connector, skillRuntimeProbe{
				TargetType: targetType, SkillName: name, ToolName: "Skill", Surface: "hook", Matched: true, SourcePath: filepath.Join(root, "ok-alias"),
			}); matched {
				t.Errorf("link to the admitted copy refused: %+v", decision)
			}
		})
	}
}

// The gateway may be unable to traverse the private folder of a held copy. The
// admitted copy of the name still runs in the balanced tier, with a warning
// and an audit row; the strict tier and a managed deployment keep the hold. A
// path through the private folder stays held in every tier.
func TestPolicyHoldCopyThatCannotBeInspectedDoesNotRefuseTheAdmittedCopy(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions as a non-root user")
	}
	for _, tc := range []struct {
		name        string
		strict      bool
		admittedRun bool
	}{{"balanced", false, true}, {"strict tier", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			private := filepath.Join(root, "private-home")
			held := policyHoldCopyForTest(t, private, "shared-name")
			admitted := policyHoldCopyForTest(t, filepath.Join(root, "admitted"), "shared-name")
			alias := filepath.Join(root, "alias")
			if err := os.Symlink(held, alias); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			if tc.strict {
				cfg.Guardrail.RulePackDir = filepath.Join(t.TempDir(), "strict")
			}
			store, logger := testStoreAndLogger(t)
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
			if err := store.SetActionFieldForConnector("skill", "shared-name", "codex", "runtime", "disable", policyHoldReasonForTest("runtime", held)); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(private, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(private, 0o700) })
			if _, err := os.Lstat(held); err == nil {
				t.Skip("this test needs an unprivileged process")
			}
			probe := func(path string) bool {
				_, matched := api.runtimeSkillAssetPolicyDecision(context.Background(), "codex", skillRuntimeProbe{
					SkillName: "shared-name", ToolName: "Skill", Surface: "hook", Matched: true, SourcePath: path,
				})
				return matched
			}
			if got := probe(admitted); got == tc.admittedRun {
				t.Errorf("admitted copy refused = %v, want %v", got, !tc.admittedRun)
			}
			if !probe(held) || !probe(alias) {
				t.Error("a path through the private folder was allowed")
			}
			events, err := store.ListEvents(50)
			if err != nil {
				t.Fatal(err)
			}
			audited := false
			for _, event := range events {
				audited = audited || (event.Action == string(audit.ActionAssetPolicy) && strings.Contains(event.Details, "policy-hold-unknown-copy"))
			}
			if audited != tc.admittedRun {
				t.Errorf("audit row for the unknown held copy = %v, want %v", audited, tc.admittedRun)
			}
		})
	}
}

// Secure Client keeps the journal decision of main: a runtime disable row
// that a policy hold wrote before a profile change refuses every path.
func TestPolicyHoldSecureClientKeepsTheJournalDecision(t *testing.T) {
	root := t.TempDir()
	held := policyHoldCopyForTest(t, filepath.Join(root, "held"), "shared-name")
	admitted := policyHoldCopyForTest(t, filepath.Join(root, "admitted"), "shared-name")
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Enterprise.Profile = "secure_client"
	if !cfg.SecureClientIntegration() {
		t.Fatal("test setup: Secure Client profile inactive")
	}
	store, _ := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, store: store}
	if err := store.SetActionFieldForConnector("skill", "shared-name", "codex", "runtime", "disable", policyHoldReasonForTest("runtime", held)); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionFieldForConnector("plugin", "shared-name", "claudecode", "runtime", "disable", policyHoldReasonForTest("runtime", held)); err != nil {
		t.Fatal(err)
	}
	if decision, matched := api.runtimeSkillAssetPolicyDecision(context.Background(), "codex", skillRuntimeProbe{
		SkillName: "shared-name", ToolName: "Skill", Surface: "hook", Matched: true, SourcePath: admitted,
	}); !matched {
		t.Errorf("Secure Client journal decision changed to allow: %+v", decision)
	}
	if decision, matched := api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
		TargetType: "plugin", SkillName: "shared-name", ToolName: "Skill", Surface: "hook", Matched: true, SourcePath: admitted,
	}); !matched {
		t.Errorf("Secure Client plugin journal decision changed to allow: %+v", decision)
	}
}

// A skill_path field names the path a call runs. A link that sits in the held
// copy, a link that passes through one and a hard link to a held file are the
// protected copy in every profile (balanced, strict, managed standalone); the
// admitted copy of the name, named through the same field, runs.
func TestPolicyHoldRefusesNamedLinksAndHardLinksOfTheHeldCopyInEveryProfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links need privileges on Windows")
	}
	for _, profile := range []string{"balanced", "strict", "managed-standalone"} {
		t.Run(profile, func(t *testing.T) {
			api, store := policyHoldAPIForTest(t)
			switch profile {
			case "strict":
				api.scannerCfg.Guardrail.RulePackDir = filepath.Join(t.TempDir(), "strict")
			case "managed-standalone":
				api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
				api.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
			}
			root := t.TempDir()
			name := "shared-skill"
			held := policyHoldCopyForTest(t, filepath.Join(root, "held"), name)
			admitted := policyHoldCopyForTest(t, filepath.Join(root, "admitted"), name)
			outward := filepath.Join(held, "outward-link")
			if err := os.Symlink(filepath.Join(admitted, "SKILL.md"), outward); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			viaLink := filepath.Join(root, "via-link")
			if err := os.Symlink(outward, viaLink); err != nil {
				t.Fatal(err)
			}
			hard := filepath.Join(root, "hard-link")
			if err := os.Link(filepath.Join(held, "SKILL.md"), hard); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
			hardAdmitted := filepath.Join(root, "hard-admitted")
			if err := os.Link(filepath.Join(admitted, "SKILL.md"), hardAdmitted); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
			if err := store.SetActionFieldForConnector("skill", name, "codex", "runtime", "disable", policyHoldReasonForTest("runtime", held)); err != nil {
				t.Fatal(err)
			}
			blocked := func(path string) bool {
				probe := skillProbeFromFields("Skill", map[string]interface{}{"skill_name": name, "skill_path": path}, nil)
				if probe.SourcePath != path || !probe.Matched {
					t.Fatalf("the hook field parser did not keep the named path %s: %+v", path, probe)
				}
				_, matched := api.runtimeSkillAssetPolicyDecision(context.Background(), "codex", probe)
				return matched
			}
			for label, path := range map[string]string{
				"the held file":                     filepath.Join(held, "SKILL.md"),
				"a link in the held copy":           outward,
				"a link to a link in the held copy": viaLink,
				"a hard link to the held file":      hard,
			} {
				if !blocked(path) {
					t.Errorf("%s: the protected path was allowed", label)
				}
			}
			for label, path := range map[string]string{
				"the admitted file":                filepath.Join(admitted, "SKILL.md"),
				"a hard link to the admitted file": hardAdmitted,
			} {
				if blocked(path) {
					t.Errorf("%s: the ordinary path was refused", label)
				}
			}
		})
	}
}
