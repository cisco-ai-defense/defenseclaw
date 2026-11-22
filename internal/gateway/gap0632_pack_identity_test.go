// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// posixShellOperand spells a native path as one POSIX shell operand. A
// Windows path with backslashes, unquoted, is read by a POSIX shell as escape
// sequences and names a different (relative) file, and a path with a space or
// an apostrophe splits or breaks the command; single quotes keep the native
// spelling literal and an embedded apostrophe is closed, escaped and reopened.
func posixShellOperand(path string) string {
	return "\x27" + strings.ReplaceAll(path, "\x27", "\x27\\\x27\x27") + "\x27"
}

func TestGAP0632PosixShellOperandIsOneLiteralWord(t *testing.T) {
	for _, path := range []string{
		`/tmp/plain/.defenseclaw/config.yaml`,
		`/tmp/with space/.defenseclaw/config.yaml`,
		"/tmp/o\x27neil/.defenseclaw/config.yaml",
		"/tmp/a \x27b\x27 c/.defenseclaw/config.yaml",
		"C:\\Users\\o\x27neil home\\.defenseclaw\\config.yaml",
	} {
		file, err := syntax.NewParser().Parse(strings.NewReader("echo marker > "+posixShellOperand(path)), "")
		if err != nil {
			t.Fatalf("%q: spelling is not valid shell: %v", path, err)
		}
		fields, err := expand.Fields(&expand.Config{}, file.Stmts[0].Redirs[0].Word)
		if err != nil || len(fields) != 1 || fields[0] != path {
			t.Fatalf("operand for %q reads back as %q (err %v)", path, fields, err)
		}
	}
}

func TestGAP0632QuotedStateOperandBlocksUnderUnusualHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "o\x27neil home")
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Dir(state), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(state, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	generation := mustCompileRulePackGeneration(cloneRuleCategories(defaultRuleCategories()))
	for _, command := range []struct {
		name, text string
		block      bool
	}{
		{"redirect to state", "echo marker > " + posixShellOperand(state), true},
		{"state operand with expanded output", "truncate -s 0 " + posixShellOperand(state) + " > out-*.txt", true},
		{"ordinary project file", "echo marker > " + posixShellOperand(filepath.Join(project, "notes.txt")), false},
	} {
		t.Run(command.name, func(t *testing.T) {
			findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
				Input:     actionfacts.Input{Tool: "Bash", Command: command.text, CWD: project, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
				Connector: "codex", EnforcementCapable: true, generation: generation,
			})
			finding := findingWithID(findings, "tamper.detector_state_write")
			if got := finding != nil && finding.contributesToEnforcement(); got != command.block {
				t.Fatalf("state protection=%t, want %t; findings=%v", got, command.block, FindingStrings(findings))
			}
		})
	}
}

func TestGAP0632PinnedPackIdentityKeepsStateProtection(t *testing.T) {
	root := guardrailPoliciesRoot(t)
	home := t.TempDir()
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Dir(state), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(state, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chain, ok := guardrail.ToolChainDefinitionByID(guardrail.ToolChainPrivilegeDiscoveryThenElevation)
	if !ok {
		t.Fatal("missing built-in chain definition")
	}
	chainMask := chain.Step1Bit | chain.Step2Bit | chain.Step3Bit | chain.Step4Bit | chain.MutationBit

	// tier is each row's hook tier, stated literally: a pack's tier comes
	// from its own tier field (manifest posture, else tiers.yaml tier),
	// never from its folder name; a legacy copy that names no tier keeps
	// strict in a folder named strict and is default elsewhere
	// (rel-1-0-10:GAP-1562 owner ruling). legacy drops the manifest; bare
	// also drops tiers.yaml (a copy older than the tier table).
	rows := []struct {
		name, source, folder, selected, tier string
		copy, legacy, bare, disabled         bool
	}{
		{name: "shipped strict", source: "strict", tier: "strict"},
		{name: "pinned strict copy", source: "strict", folder: "strict", copy: true, tier: "strict"},
		{name: "renamed strict copy", source: "strict", folder: "operator-pack", copy: true, tier: "strict"},
		{name: "pinned older strict copy", source: "strict", folder: "operator-pack", copy: true, legacy: true, tier: "strict"},
		{name: "bare strict copy named strict", source: "strict", folder: "strict", copy: true, legacy: true, bare: true, tier: "strict"},
		{name: "bare strict copy renamed", source: "strict", folder: "operator-pack", copy: true, legacy: true, bare: true, tier: "default"},
		{name: "strict copy with rule disabled", source: "strict", folder: "operator-pack", copy: true, disabled: true, tier: "strict"},
		{name: "shipped default", source: "default", tier: "default"},
		{name: "pinned default copy", source: "default", folder: "strict", copy: true, tier: "default"},
		{name: "older default copy named strict", source: "default", folder: "operator-pack", selected: "strict", copy: true, legacy: true, tier: "default"},
		{name: "shipped permissive", source: "permissive", tier: "permissive"},
		{name: "pinned permissive copy", source: "permissive", folder: "strict", copy: true, tier: "permissive"},
		{name: "bare permissive copy named permissive", source: "permissive", folder: "permissive", copy: true, legacy: true, bare: true, tier: "default"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			dir := filepath.Join(root, row.source)
			cfg := &config.Config{PolicyDir: filepath.Dir(root)}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Enabled = true
			cfg.Guardrail.RulePack = row.source
			if row.disabled {
				cfg.Guardrail.Rules.Disable = []string{"tamper.detector_state_write"}
			}
			if row.copy {
				dir = filepath.Join(t.TempDir(), row.folder)
				if err := os.CopyFS(dir, os.DirFS(filepath.Join(root, row.source))); err != nil {
					t.Fatal(err)
				}
				if row.legacy {
					if err := os.Remove(filepath.Join(dir, guardrail.PackManifestFile)); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
				}
				if row.bare {
					if err := os.Remove(filepath.Join(dir, "tiers.yaml")); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
				}
				pin, err := guardrail.RulePackDigest(dir)
				if err != nil {
					t.Fatal(err)
				}
				selected := row.selected
				if selected == "" {
					selected = "operator"
				}
				cfg.Guardrail.RulePack = selected
				cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{
					selected: {Path: dir, Digest: "sha256:" + pin},
				}
			}
			t.Cleanup(func() { pendingPackPostures.Delete(dir); packPostures.Delete(dir) })
			pack, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "global")
			if err != nil {
				t.Fatal(err)
			}
			generation, err := compileRulePackCategories(pack)
			if err != nil {
				t.Fatal(err)
			}
			buildThresholdTable(cfg, nil)
			wantTier := row.tier
			if got := cfg.HookPolicyTierForConnector("codex"); got != wantTier {
				t.Errorf("hook policy tier = %q, want %q", got, wantTier)
			}
			chainProjection := toolChainProjectionForPolicyPosture(cfg, "codex", guardrail.ToolChainProjection{
				DetectionStepMask: chainMask,
			})
			wantChain := uint64(0)
			if wantTier == "strict" {
				wantChain = chainMask
			}
			if chainProjection.DetectionStepMask != wantChain {
				t.Errorf("chain posture mask = %d, want %d", chainProjection.DetectionStepMask, wantChain)
			}
			if row.copy && wantTier == row.source {
				shipped := ConfigThresholds(&config.Config{PolicyDir: filepath.Dir(root), Guardrail: config.GuardrailConfig{RulePack: row.source}}, "")
				copied := resolveThresholds(cfg, "")
				if copied.Block != shipped.Block || copied.Alert != shipped.Alert {
					t.Errorf("copied pack levels = %+v, shipped = %+v", copied, shipped)
				}
			}
			for _, command := range []struct {
				name, text string
				block      bool
			}{
				{"protected state", "echo marker > " + posixShellOperand(state), true},
				{"home variable state", `printf marker > "$HOME/.defenseclaw/config.yaml"`, true},
				{"value variable state", `printf "$X" > "$HOME"/.defenseclaw/config.yaml`, true},
				{"tilde state", "printf marker >> ~/.defenseclaw/config.yaml", true},
				{"literal home state", "printf marker > " + posixShellOperand(filepath.Join(home, ".defenseclaw", "config.yaml")), true},
				{"state operand with expanded output", "truncate -s 0 " + posixShellOperand(state) + " > out-*.txt", true},
				{"ordinary project file", "echo marker > " + posixShellOperand(filepath.Join(project, "notes.txt")), false},
				{"ordinary expanded output", "printf marker > out-*.txt", false},
				{"state path mention", `printf '%s\n' "$HOME/.defenseclaw/config.yaml" > notes.txt`, false},
			} {
				t.Run(command.name, func(t *testing.T) {
					findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
						Input:     actionfacts.Input{Tool: "Bash", Command: command.text, CWD: project, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
						Connector: "codex", EnforcementCapable: true, generation: generation,
						// The hook's tier decides the severity of a proven state
						// write: a block in strict, a HIGH alert elsewhere
						// (GAP-0747 owner tiering 2026-11-15T15:20Z).
						StrictPolicy: cfg.HookPolicyTierForConnector("codex") == "strict",
					})
					strict := cfg.HookPolicyTierForConnector("codex") == "strict"
					if got := singleProfileActionForFindings(cfg, "codex", findings, false, true) == guardrailActionBlock; got != (command.block && strict) {
						t.Fatalf("tier %q: block=%t, want %t; findings=%v", cfg.HookPolicyTierForConnector("codex"), got, command.block && strict, FindingStrings(findings))
					}
					if command.block && !strict {
						if problem := gap0747DefaultTierCheck(findings, true); problem != "" {
							t.Fatalf("outside strict: %s; findings=%v", problem, FindingStrings(findings))
						}
					}
				})
			}
		})
	}
}

func TestGAP0632StateProtectionSurvivesRulePackRemoval(t *testing.T) {
	categories := cloneRuleCategories(defaultRuleCategories())
	for index := range categories {
		categories[index].Rules = slices.DeleteFunc(categories[index].Rules, func(rule PatternRule) bool {
			return rule.ID == "tamper.detector_state_write"
		})
	}
	generation := mustCompileRulePackGeneration(categories)
	for _, homeName := range []string{"home", "home with space"} {
		t.Run(homeName, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), homeName)
			state := filepath.Join(home, ".defenseclaw", "config.yaml")
			if err := os.MkdirAll(filepath.Dir(state), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(state, []byte("guardrail: {}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
				Input:     actionfacts.Input{Tool: "Bash", Command: "echo marker > " + posixShellOperand(state), CWD: home, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
				Connector: "codex", EnforcementCapable: true, generation: generation,
			})
			if finding := findingWithID(findings, "tamper.detector_state_write"); finding == nil || !finding.contributesToEnforcement() {
				t.Fatalf("state protection missing after pack rule removal: %v", FindingStrings(findings))
			}
		})
	}
}

func TestGAP0632StructuredStateProtectionSurvivesRulePackRemoval(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Dir(state), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(state, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project, "state-link")
	linkErr := os.Symlink(state, link)
	if linkErr != nil && runtime.GOOS != "windows" {
		t.Fatal(linkErr)
	}
	categories := cloneRuleCategories(defaultRuleCategories())
	for index := range categories {
		categories[index].Rules = slices.DeleteFunc(categories[index].Rules, func(rule PatternRule) bool {
			return rule.ID == "tamper.detector_state_write"
		})
	}
	generation := mustCompileRulePackGeneration(categories)
	ordinary := filepath.Join(project, "notes.txt")
	for _, row := range []struct {
		name, tool, target string
		args               func(string) map[string]string
		block              bool
	}{
		{"patch state", "apply_patch", state, func(p string) map[string]string {
			return map[string]string{"command": "*** Begin Patch\n*** Update File: " + p + "\n@@\n-old\n+new\n*** End Patch\n"}
		}, true},
		{"patch state link", "apply_patch", link, func(p string) map[string]string {
			return map[string]string{"command": "*** Begin Patch\n*** Update File: " + p + "\n@@\n-old\n+new\n*** End Patch\n"}
		}, true},
		{"patch ordinary", "apply_patch", ordinary, func(p string) map[string]string {
			return map[string]string{"command": "*** Begin Patch\n*** Update File: " + p + "\n@@\n-old\n+new\n*** End Patch\n"}
		}, false},
		{"large write state", "Write", state, func(p string) map[string]string {
			return map[string]string{"file_path": p, "content": strings.Repeat("x", 65<<10)}
		}, true},
		{"large write state link", "Write", link, func(p string) map[string]string {
			return map[string]string{"file_path": p, "content": strings.Repeat("x", 65<<10)}
		}, true},
		{"large write ordinary", "Write", ordinary, func(p string) map[string]string {
			return map[string]string{"file_path": p, "content": strings.Repeat("x", 65<<10)}
		}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if row.target == link && linkErr != nil {
				t.Skip("file links unavailable on this host")
			}
			args, err := json.Marshal(row.args(row.target))
			if err != nil {
				t.Fatal(err)
			}
			findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
				Input:     actionfacts.Input{Tool: row.tool, Args: args, CWD: project, ActiveHome: home},
				Connector: "codex", EnforcementCapable: true, generation: generation,
			})
			finding := findingWithID(findings, "tamper.detector_state_write")
			if got := finding != nil && finding.contributesToEnforcement(); got != row.block {
				t.Fatalf("state finding = %t, want %t; findings=%v", got, row.block, FindingStrings(findings))
			}
		})
	}
}
