// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// gap1633Tar writes a tar archive at path that holds the members.
func gap1633Tar(t *testing.T, path string, members ...string) {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, member := range members {
		if err := w.WriteHeader(&tar.Header{Name: member, Mode: 0o600, Size: 5, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("x: 1\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// rel-1-0-10 GAP-1633: on a Windows hook host the agent's shell is
// PowerShell (Codex shell_command and Bash, the Claude Code PowerShell
// tool). A native tar, unzip or 7z call whose folder is spelled the Windows
// way (C:\Users\u\.defenseclaw, $env:USERPROFILE\.defenseclaw, ~\, $HOME\,
// cmd /c ... %USERPROFILE%\) was read only with POSIX words, which drop the
// backslashes and the $env: word, so tar -xf x.tar -C
// $env:USERPROFILE\.defenseclaw was allowed with no alert in every tier while
// tar -xf x.tar -C ~/.defenseclaw was a state write. It is now the same
// state write (GAP-0747 tiers: alert in default, permissive and managed,
// block in strict and managed-strict); an extraction outside the state stays
// allowed.
//
// Each call goes through the connector's own hook evaluator with the hook
// body the agent sends, as the hook route runs it, with both Windows host
// seams set: the generic evaluator is never the route of a Claude Code or
// Codex tool call, and on a Windows host Codex runs its Bash tool in
// PowerShell (codexShellRunsPowerShell), so a Codex call judged there by the
// generic evaluator had no command to judge and took TOOL-ARGS-UNVERIFIED.
func TestGAP1633WindowsArchiveDestinationIsAStateWrite(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	previousShell := codexShellRunsPowerShell
	codexShellRunsPowerShell = true
	t.Cleanup(func() { codexShellRunsPowerShell = previousShell })
	home := t.TempDir()
	cwd := filepath.Join(home, "fcwork")
	for _, folder := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(cwd, "out")} {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "config.yaml"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	gap1633Tar(t, filepath.Join(cwd, "mark.tar"), "dccert-marker.txt")
	gap1633Tar(t, filepath.Join(cwd, "cfgarch.tar"), "config.yaml")
	gap1633Tar(t, filepath.Join(cwd, "ok.tar"), "notes.txt")
	gap1633Tar(t, filepath.Join(cwd, "homestate.tar"), ".defenseclaw/config.yaml")
	// The state root as a Windows home spells it: with backslashes. On a
	// POSIX test host the home is a POSIX path; the separator is the
	// Windows one all the same.
	state := home + `\.defenseclaw`
	if filepath.Separator == '\\' {
		state = filepath.Join(home, ".defenseclaw")
	}
	// rel-1-0-10 GAP-1634: a staged archive extracted under
	// $env:USERPROFILE is the state write alone; the link walk reads the
	// folder in PowerShell words, so the copy that stages the archive is not
	// a write a link of the extraction may lead to an SSH keys file.
	staged := `Copy-Item cfgarch.tar staged.tar; tar -xf staged.tar -C $env:USERPROFILE\.defenseclaw`
	// rel-1-0-10 GAP-1662: a listing before the call does not stage the
	// archive, a copy onto it still does.
	listedCopied := `tar -tf ok.tar; Copy-Item cfgarch.tar ok.tar; tar -xf ok.tar -C $env:USERPROFILE`
	listedCopiedPosix := `tar -tf ok.tar; cp cfgarch.tar ok.tar; tar -xf ok.tar -C ~`
	writes := []string{
		`tar -xf mark.tar -C ` + state,
		`tar.exe -xf mark.tar -C ` + state,
		`& tar -xf mark.tar -C "` + state + `"`,
		`tar -xf mark.tar -C $env:USERPROFILE\.defenseclaw`,
		`tar -xf mark.tar -C ~\.defenseclaw`,
		`tar -xf mark.tar -C $HOME\.defenseclaw`,
		`tar -x -f mark.tar -C "$env:USERPROFILE\.defenseclaw\hooks"`,
		`tar -xf cfgarch.tar -C $env:USERPROFILE\.defenseclaw`,
		`tar -xf homestate.tar -C $env:USERPROFILE`,
		`unzip -o mark.zip -d $env:USERPROFILE\.defenseclaw`,
		`7z x mark.7z "-o$env:USERPROFILE\.defenseclaw"`,
		`Expand-Archive mark.zip -DestinationPath $env:USERPROFILE\.defenseclaw`,
		`cmd /c tar -xf mark.tar -C %USERPROFILE%\.defenseclaw`,
		`cmd /c "tar -xf mark.tar -C %USERPROFILE%\.defenseclaw"`,
		staged,
		listedCopied,
		listedCopiedPosix,
		// The POSIX spelling keeps its reading.
		`tar -xf mark.tar -C ~/.defenseclaw`,
	}
	allowed := []string{
		`tar -xf ok.tar -C $env:USERPROFILE\fcwork\out`,
		`tar -xf ok.tar -C out`,
		`tar -xf ok.tar -C $env:USERPROFILE`,
		`tar -xf ok.tar -C ~\fcwork\out`,
		`cmd /c tar -xf ok.tar -C %USERPROFILE%\fcwork\out`,
		`tar -tf mark.tar`,
		`Start-Process notepad; $target = 'tar'`,
		// rel-1-0-10 GAP-1662: only a mention of the archive before the
		// call may stage it; one after it (the archive removed) is not, and
		// a listing before it writes nothing (the PowerShell reading of a
		// POSIX spelling as well).
		`tar -xf ok.tar -C $env:USERPROFILE; Remove-Item ok.tar`,
		`tar -xf ok.tar -C ~; rm ok.tar`,
		`tar -tf ok.tar; tar -xf ok.tar -C ~`,
	}
	routes := []struct{ connector, tool string }{
		{"claudecode", "PowerShell"},
		{"codex", "Bash"},
		{"codex", "shell_command"},
	}
	tiers := []struct {
		name, posture, want string
		managed             bool
	}{
		{"default", "default", "alert", false},
		{"permissive", "permissive", "alert", false},
		{"strict", "strict", "block", false},
		{"managed", "default", "alert", true},
		{"managed-strict", "strict", "block", true},
	}
	for _, tier := range tiers {
		for _, route := range routes {
			installToolCallCorpusProfileConnector(t, route.connector, tier.posture)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = route.connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tier.posture)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			ctx := context.Background()
			if tier.managed {
				ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
			}
			hook := hookRuntimeForProfile(api.hookProfileForRequest(ctx, route.connector))
			calls := 0
			evaluate := func(command string) (string, string) {
				calls++
				id := tier.name + "-" + route.connector + "-" + strconv.Itoa(calls)
				raw, err := json.Marshal(map[string]any{
					"session_id": "gap1633-" + id, "turn_id": "turn-1", "hook_event_name": "PreToolUse", "cwd": cwd,
					"model": "fixture-model", "tool_name": route.tool, "tool_use_id": "call-" + id,
					"tool_input": map[string]any{"command": command},
				})
				if err != nil {
					t.Fatal(err)
				}
				var payload map[string]interface{}
				if err := json.Unmarshal(raw, &payload); err != nil {
					t.Fatal(err)
				}
				args, err := json.Marshal(map[string]string{"command": command})
				if err != nil {
					t.Fatal(err)
				}
				resp, panicked := api.safeEvaluateHook(ctx, route.connector, agentHookRequest{ConnectorName: route.connector, CWD: cwd, HookEventName: "PreToolUse", ToolName: route.tool, ToolArgs: args}, raw, payload, hook)
				if panicked {
					t.Fatalf("%s %s/%s %q: hook evaluator panicked", tier.name, route.connector, route.tool, command)
				}
				return resp.Action, strings.Join(resp.Findings, "; ")
			}
			for _, command := range writes {
				action, findings := evaluate(command)
				want := tier.want
				// The listed-then-copied rows land in the home, which holds
				// .ssh: the same GAP-1634 block on every host.
				if (command == listedCopied || command == listedCopiedPosix) && action == "block" &&
					strings.Contains(findings, "persistence.ssh_authorized_keys_command") {
					want = "block"
				}
				if action != want || !strings.Contains(findings, "tamper.detector_state_write") {
					t.Errorf("%s %s/%s %q: %s [%s], want %s with tamper.detector_state_write", tier.name, route.connector, route.tool, command, action, findings, want)
				}
			}
			for _, command := range allowed {
				if action, findings := evaluate(command); action != "allow" {
					t.Errorf("%s %s/%s %q: %s [%s], want allow", tier.name, route.connector, route.tool, command, action, findings)
				}
			}
		}
	}
}
