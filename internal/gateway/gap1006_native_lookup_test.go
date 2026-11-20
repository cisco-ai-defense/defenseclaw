// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// firstClientWriteTarget is clientWriteTargets for one spelling of an operand
// written that way.
func firstClientWriteTarget(targets map[string]string, spelling string) (string, bool) {
	if found := clientWriteTargets(targets, spelling, spelling); len(found) > 0 {
		return found[0], true
	}
	return "", false
}

// gap1006Fixture is a home with the DefenseClaw state, an ordinary
// project/.defenseclaw folder, and project/jx, a junction (a link on POSIX)
// to the state.
func gap1006Fixture(t *testing.T) (home, cwd string) {
	t.Helper()
	home = t.TempDir()
	cwd = filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	decoy := filepath.Join(cwd, ".defenseclaw")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(state, "policies"), decoy} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(state, "config.yaml"), filepath.Join(state, "policies", "default.yaml"),
		filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "notes.txt"), filepath.Join(decoy, "config.yaml")} {
		if err := os.WriteFile(file, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
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
	return home, cwd
}

// gap1006ManagedDecide judges one call for a managed hook peer whose gateway
// reads the write targets from the hook client's map, as a managed install
// does (the peer home, the client map in the context).
func gap1006ManagedDecide(t *testing.T, home, cwd, posture, tool, command string) string {
	action, _ := gap1006ManagedDecideFull(t, home, cwd, posture, tool, command)
	return action
}

// gap1006ManagedDecideFull is gap1006ManagedDecide and whether the verdict
// also carries another tamper or persistence rule beside the state write.
func gap1006ManagedDecideFull(t *testing.T, home, cwd, posture, tool, command string) (string, bool) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
		"tool_name": tool, "tool_input": map[string]any{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	installToolCallCorpusProfileConnector(t, "claudecode", posture)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	if resolved, decoded := hookpaths.Decode(hookpaths.Resolve(body)); decoded {
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, resolved)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	rt := claudeCodeHookProfileRuntime(connector.HookProfile{Name: "claudecode"})
	res := rt.Evaluate(api, ctx, agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse"}, body, payload)
	return res.Action, gap0747OtherTamperFinding(res.Findings)
}

// TestGAP1006JunctionParentKeepsStateVerdict: a write through a junction
// followed by .. reaches the DefenseClaw state, after the same call wrote an
// ordinary file at the operand's lexically cleaned spelling. The managed
// gateway looks the operand up by its exact key first and never by a cleaned
// spelling, so the state write is a HIGH alert in the managed default pack and
// blocks in the managed strict pack (GAP-0747 tiering); the ordinary write alone stays allowed
// (rel-1-0-10:GAP-1006). The unmanaged tiers read no client map
// (rel-1-0-10:GAP-1007, a follow-up).
func TestGAP1006JunctionParentKeepsStateVerdict(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the native-spelling lookup is Windows only; TestClientWriteTargetsNeverRespellACleanedOperand runs everywhere")
	}
	home, cwd := gap1006Fixture(t)
	nat, fwd := home, filepath.ToSlash(home)
	q := func(p string) string { return "'" + p + "'" }
	targets := []struct{ id, path string }{
		{"lkDots", q(fwd + "/project/jx/../.defenseclaw/config.yaml")},
		{"lkDotsN", q(nat + `\project\jx\..\.defenseclaw\config.yaml`)},
		{"lkDotsMix", q(fwd + `/project/jx\..\.defenseclaw/config.yaml`)},
	}
	firsts := []struct{ id, f string }{
		{"decoy-then", "echo y > " + q(fwd+"/project/.defenseclaw/config.yaml") + "; echo x > %s"},
		{"decoyN-then", "echo y > " + q(nat+`\project\.defenseclaw\config.yaml`) + "; echo x > %s"},
	}
	cells := 0
	for _, posture := range []string{"default", "strict"} {
		for _, tg := range targets {
			for _, fm := range firsts {
				for _, tool := range []string{"Bash", "PowerShell"} {
					// The 20 cells of GAP-1006: the Bash cell of the
					// all-backslash spelling kept its block.
					if tg.id == "lkDotsN" && tool == "Bash" {
						continue
					}
					cells++
					name := posture + "/" + tg.id + "/" + fm.id + "/" + tool
					// A proven state write blocks in the strict pack and is a
					// HIGH alert in the default one (GAP-0747 owner tiering
					// 2026-11-15T15:20Z).
					want := gap0747WantAction(posture == "strict")
					if got := gap1006ManagedDecide(t, home, cwd, posture, tool, fmt.Sprintf(fm.f, tg.path)); got != want {
						t.Errorf("%s: managed state write action %s, want %s", name, got, want)
					}
				}
			}
		}
		for _, tool := range []string{"Bash", "PowerShell"} {
			for _, decoy := range []string{q(fwd + "/project/.defenseclaw/config.yaml"), q(nat + `\project\.defenseclaw\config.yaml`)} {
				if got := gap1006ManagedDecide(t, home, cwd, posture, tool, "echo x > "+decoy); got == "block" {
					t.Errorf("%s/%s: the ordinary project file write alone blocked", posture, tool)
				}
			}
		}
	}
	if cells != 20 {
		t.Fatalf("%d managed cells, want the 20 of GAP-1006", cells)
	}
	t.Logf("GAP1006 managed state-write cells checked: %d", cells)
}

// TestClientWriteTargetsNeverRespellACleanedOperand: the exact key of the
// operand as written answers before any other spelling, and an operand with
// a .. component is respelled only as written (rel-1-0-10:GAP-1006).
func TestClientWriteTargetsNeverRespellACleanedOperand(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The POSIX reading spells the operand with forward slashes; the
		// client keyed the ordinary file the call wrote first natively.
		root := t.TempDir()
		written := filepath.ToSlash(filepath.Join(root, "jx")) + "/../config.yaml"
		cleaned := filepath.ToSlash(filepath.Join(root, "config.yaml"))
		targets := map[string]string{written: "state", filepath.FromSlash(cleaned): "decoy"}
		if found := clientWriteTargets(targets, written, cleaned, written, cleaned); len(found) == 0 || found[0] != "state" {
			t.Fatalf("the exact key of the operand as written must answer first: %v", found)
		}
		delete(targets, written)
		if found := clientWriteTargets(targets, written, cleaned, written, cleaned); len(found) != 0 {
			t.Fatalf("a cleaned spelling of a .. operand matched another file: %v", found)
		}
	}
	for _, path := range []string{`a\..\b`, "a/../b", `a\b/..`, ".."} {
		if !hasDotDotSegment(path) {
			t.Errorf("hasDotDotSegment(%q) = false", path)
		}
	}
	for _, path := range []string{`a\b`, "a/b..", "..a/b", ""} {
		if hasDotDotSegment(path) {
			t.Errorf("hasDotDotSegment(%q) = true", path)
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
	if _, ok := firstClientWriteTarget(targets, spelling); ok {
		t.Fatal("unresolved path matched a lexical decoy")
	}
	// Resolve a real direct operand without requiring it to exist as a file.
	direct := filepath.Join(root, "ordinary.txt")
	targets = map[string]string{direct: direct}
	if got, ok := firstClientWriteTarget(targets, filepath.ToSlash(direct)); !ok || got != direct {
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
	if got, ok := firstClientWriteTarget(targets, spelling); !ok || got != target {
		t.Fatal("native alias operand entry lost")
	}
	// An answer recorded for a different operand is not this alias's entry.
	if _, ok := firstClientWriteTarget(map[string]string{target: target}, spelling); ok {
		t.Fatal("different operand key matched")
	}
}
