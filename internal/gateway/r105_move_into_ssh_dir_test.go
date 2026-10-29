// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A move that renames or replaces the .ssh directory or an authorized-keys
// entry (mv x/authorized_keys ~/.ssh, mv -t, through a link to ~/.ssh, a
// move into ~/.ssh, a move of ~/.ssh itself) blocks on a managed gateway
// that cannot read the home, as on OSS: the user-side hook sends the
// reading as the action decision (GAP-2581). Moves elsewhere, and the
// GAP-2559 move onto a link to the keys file, stay allowed.
func TestR105MoveIntoSSHDirectoryBlocksOnManaged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root")
	}
	type probeRow struct{ id, want, command string }
	rows := []probeRow{
		{"N01", "block", "mv -t ~/.ssh x/authorized_keys"},
		{"N02", "block", "mv x/rc ~/.ssh"},
		{"N03", "block", "mv x/authorized_keys2 ~/.ssh"},
		{"N04", "block", "mv x/authorized_keys $HOME/.ssh"},
		{"N05", "block", "mv -f x/authorized_keys ~/.ssh"},
		{"N06", "block", "mv x/authorized_keys ~/.ssh/"},
		{"N07", "block", "mv x/authorized_keys ~/.ssh/authorized_keys"},
		{"K01", "block", "mv x/authorized_keys ~/.ssh"},
		{"K02", "block", "mv x/authorized_keys ../../.ssh/"},
		{"K03", "block", "mv x/authorized_keys {E}/s"},
		{"K04", "block", "mv --target-directory={E}/s x/authorized_keys"},
		{"N10", "block", "mv x/settings.json ~/.ssh"},
		{"N11", "block", "mv ~/.ssh/authorized_keys ~/w/p/ak.old"},
		{"K18", "block", "mv ~/.ssh ~/ssh.bak"},
		{"B01", "allow", "mv x/authorized_keys src"},
		{"B02", "allow", "mv x/authorized_keys ~/keys"},
		{"B03", "allow", "mv x/settings.json src/"},
		{"B04", "allow", "mv a.txt b.txt"},
		{"B05", "allow", "mv -t src a.txt README.md"},
		{"B06", "allow", "mv a.txt {E}/k"},
		{"B07", "allow", "cd src && mv a.go b.go"},
	}
	for _, mode := range []string{"managed", "managed-extvisible", "oss"} {
		for _, connector := range []string{"claudecode", "codex"} {
			installDefaultProfileConnector(t, connector)
			for _, row := range rows {
				home := filepath.Join(t.TempDir(), "home")
				ext := filepath.Join(t.TempDir(), "ext")
				cwd := filepath.Join(home, "w", "p")
				state := filepath.Join(home, ".defenseclaw")
				dot := filepath.Join(home, "dot")
				for _, dir := range []string{state, filepath.Join(state, "hooks"), dot, filepath.Join(home, ".ssh"), filepath.Join(home, "keys"),
					filepath.Join(cwd, "x"), filepath.Join(cwd, "src"), filepath.Join(home, ".claude"), filepath.Join(home, ".codex"), filepath.Join(cwd, "build", "out"), ext} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				files := []string{filepath.Join(dot, "dc.yaml"), filepath.Join(dot, "other.yaml"), filepath.Join(dot, "hx.sh"),
					filepath.Join(home, "keys", "ak"), filepath.Join(cwd, "a.txt"), filepath.Join(cwd, "README.md"),
					filepath.Join(cwd, "x", "authorized_keys"), filepath.Join(cwd, "src", "a.go"), filepath.Join(cwd, "x", "rc"), filepath.Join(cwd, "x", "authorized_keys2"), filepath.Join(cwd, "x", "config.yaml"), filepath.Join(cwd, "x", "settings.json"), filepath.Join(cwd, "x", "hooks.json")}
				if true {
					files = append(files, filepath.Join(state, "config.yaml"))
				}
				if false {
					files = append(files, filepath.Join(home, ".ssh", "authorized_keys"))
				}
				for _, name := range files {
					if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				links := map[string]string{
					filepath.Join(state, "hooks", "hx.sh"): filepath.Join(dot, "hx.sh"),
					filepath.Join(ext, "y"):                state,
					filepath.Join(ext, "s"):                filepath.Join(home, ".ssh"),
					filepath.Join(ext, "k"):                filepath.Join(home, ".ssh", "authorized_keys"),
					filepath.Join(ext, "k2"):               filepath.Join(home, "keys", "ak"),
					filepath.Join(ext, "kd"):               filepath.Join(home, ".ssh"),
					filepath.Join(ext, "kdd"):              filepath.Join(ext, "s"),
				}
				if true {
					links[filepath.Join(home, ".ssh", "authorized_keys")] = filepath.Join(home, "keys", "ak")
				}
				if false {
					links[filepath.Join(state, "config.yaml")] = filepath.Join(dot, "dc.yaml")
				}
				for link, target := range links {
					if err := os.Symlink(target, link); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("HOME", home)
				command := strings.NewReplacer("{E}", ext).Replace(row.command)
				payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
					"tool_name": "Bash", "tool_input": map[string]string{"command": command}})
				targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
				if !ok {
					t.Fatalf("%s %s %s: client map does not decode", mode, connector, row.id)
				}
				protected := mode != "oss"
				var hidden []string
				if protected {
					hidden = append(hidden, filepath.Dir(home))
					if mode == "managed" {
						hidden = append(hidden, filepath.Dir(ext))
					}
				}
				for _, dir := range hidden {
					if err := os.Chmod(dir, 0); err != nil {
						t.Fatal(err)
					}
				}
				cwds := []string{cwd}
				if protected {
					cwds = append(cwds, "")
				}
				for _, gatewayCWD := range cwds {
					input := actionfacts.Input{Tool: "Bash", Command: command, CWD: gatewayCWD, ActiveHome: home,
						DialectHint: actionfacts.DialectPOSIX}
					request := trustedActionRequest{Input: input, Connector: connector, EnforcementCapable: true,
						ProtectedHomeHook: protected, ResolvedWriteTargets: targets}
					findings := dispatchTrustedAction(t.Context(), request)
					action := buildVerdict(findings, "tool_call").Action
					ids := []string{}
					for _, f := range findings {
						ids = append(ids, f.RuleID)
					}
					c := "set"
					if gatewayCWD == "" {
						c = "empty"
					}
					if string(action) != row.want {
						t.Errorf("%s %s cwd=%s %s %q: action %s want %s (%s)", mode, connector, c, row.id, command, action, row.want, strings.Join(ids, ","))
					}
				}
				for _, dir := range hidden {
					if err := os.Chmod(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
}
