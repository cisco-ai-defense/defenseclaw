// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGAP1006JunctionParentKeepsStateVerdict(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native junction lookup")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{filepath.Join(home, ".ssh"), state, filepath.Join(state, "policies"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(state, "config.yaml"), filepath.Join(state, "policies", "default.yaml"),
		filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "notes.txt")} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	decoy := filepath.Join(cwd, ".defenseclaw")
	if err := os.MkdirAll(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(decoy, "config.yaml"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(cwd, "jx")
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, state).CombinedOutput(); err != nil {
			t.Fatalf("mklink: %v %s", err, out)
		}
	} else if err := os.Symlink(state, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	nat, fwd := home, filepath.ToSlash(home)
	q := func(p string) string { return "'" + p + "'" }
	targets := []struct{ id, path string }{
		{"lkDirect", q(fwd + "/project/jx/config.yaml")}, {"lkDirectN", q(nat + `\project\jx\config.yaml`)},
		{"lkDots", q(fwd + "/project/jx/../.defenseclaw/config.yaml")}, {"lkDotsN", q(nat + `\project\jx\..\.defenseclaw\config.yaml`)},
		{"lkDotsMix", q(fwd + `/project/jx\..\.defenseclaw/config.yaml`)}, {"lkDotsRel", "jx/../.defenseclaw/config.yaml"},
		{"decoyFwd", q(fwd + "/project/.defenseclaw/config.yaml")}, {"decoyNat", q(nat + `\project\.defenseclaw\config.yaml`)},
	}
	forms := []struct{ id, f string }{
		{"gt", "echo x > %s"}, {"gtgt", "echo x >> %s"}, {"tee", "echo x | tee %s"}, {"c24", "/opt/tools/add-key notes.txt > %s"},
		{"decoy-then", "echo y > " + q(fwd+"/project/.defenseclaw/config.yaml") + "; echo x > %s"},
		{"decoyN-then", "echo y > " + q(nat+`\project\.defenseclaw\config.yaml`) + "; echo x > %s"},
	}

	env := boundedEnv{home: home, cwd: cwd}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for _, tg := range targets {
			if tg.id != "lkDots" && tg.id != "lkDotsMix" && tg.id != "lkDotsN" {
				continue
			}
			for _, fm := range forms {
				if !strings.HasPrefix(fm.id, "decoy") {
					continue
				}
				for _, tool := range []string{"Bash", "PowerShell"} {
					if tool == "Bash" && tg.id == "lkDotsN" {
						continue
					}
					t.Run(tier.name+"/"+tg.id+"/"+fm.id+"/"+tool, func(t *testing.T) {
						got, _ := boundedDecideClaudeCode(t, api, env, boundedLaneCall{tool: tool, input: map[string]any{"command": fmt.Sprintf(fm.f, tg.path)}})
						if got != "block" {
							t.Errorf("state write action %s", got)
						}
					})
				}
			}
		}
	}
}

func TestGAP1006UnresolvableNativeLookupDoesNotUseCleanedKey(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native separators")
	}
	root := t.TempDir()
	native := root + string(filepath.Separator) + "missing" + string(filepath.Separator) + ".." + string(filepath.Separator) + "ordinary.txt"
	spelling := filepath.ToSlash(native)
	targets := map[string]string{filepath.Clean(native): "decoy"}
	if _, ok := clientWriteTarget(targets, spelling); ok {
		t.Fatal("unresolved path matched a lexical decoy")
	}
	// Resolve a real direct operand without requiring it to exist as a file.
	direct := filepath.Join(root, "ordinary.txt")
	targets = map[string]string{direct: direct}
	if got, ok := clientWriteTarget(targets, filepath.ToSlash(direct)); !ok || got != direct {
		t.Fatal("direct spelling lost")
	}
}

// Native map keys retain the operand even when its target has a different
// physical name. This preserves GAP-0982 across links and junctions.
func TestGAP0982NativeAliasKeepsOperandKey(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native separators and junction")
	}
	root := t.TempDir()
	real := filepath.Join(root, "actual")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(real, "config.yaml")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := exec.Command("cmd", "/c", "mklink", "/J", alias, real).Run(); err != nil {
		t.Fatal("junction creation failed")
	}
	native := filepath.Join(alias, "config.yaml")
	spelling := filepath.ToSlash(native)
	targets := map[string]string{native: target}
	if got, ok := clientWriteTarget(targets, spelling); !ok || got != target {
		t.Fatal("native alias operand entry lost")
	}
	// An answer recorded for a different operand is not this alias's entry.
	if _, ok := clientWriteTarget(map[string]string{target: target}, spelling); ok {
		t.Fatal("different operand key matched")
	}
}
