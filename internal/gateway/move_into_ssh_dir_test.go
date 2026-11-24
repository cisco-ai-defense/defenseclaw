// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
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
	// needs names the link fixtures a row reads: "s" ({E}/s, a directory
	// link to ~/.ssh), "k" ({E}/k, a link to the keys file), "keys"
	// (~/.ssh/authorized_keys, itself a link to keys/ak) and "sj" (a junction
	// to ~/.ssh). A Limited Windows token cannot make symbolic links: a row
	// that needs one skips there (the elevated run keeps it), every other row
	// runs, and the junction rows run on every Windows token (GAP-2158).
	type probeRow struct {
		id, want, command string
		needs             []string
	}
	rows := []probeRow{
		{"N01", "block", "mv -t ~/.ssh x/authorized_keys", nil},
		{"N02", "block", "mv x/rc ~/.ssh", nil},
		{"N03", "block", "mv x/authorized_keys2 ~/.ssh", nil},
		{"N04", "block", "mv x/authorized_keys $HOME/.ssh", nil},
		{"N05", "block", "mv -f x/authorized_keys ~/.ssh", nil},
		{"N06", "block", "mv x/authorized_keys ~/.ssh/", nil},
		{"N07", "block", "mv x/authorized_keys ~/.ssh/authorized_keys", []string{"keys"}},
		{"K01", "block", "mv x/authorized_keys ~/.ssh", nil},
		{"K02", "block", "mv x/authorized_keys ../../.ssh/", nil},
		{"K03", "block", "mv x/authorized_keys {E}/s", []string{"s"}},
		{"K04", "block", "mv --target-directory={E}/s x/authorized_keys", []string{"s"}},
		{"N10", "block", "mv x/settings.json ~/.ssh", nil},
		{"N11", "block", "mv ~/.ssh/authorized_keys ~/w/p/ak.old", []string{"keys"}},
		{"K18", "block", "mv ~/.ssh ~/ssh.bak", nil},
		{"B01", "allow", "mv x/authorized_keys src", nil},
		{"B02", "allow", "mv x/authorized_keys ~/keys", nil},
		{"B03", "allow", "mv x/settings.json src/", nil},
		{"B04", "allow", "mv a.txt b.txt", nil},
		{"B05", "allow", "mv -t src a.txt README.md", nil},
		{"B06", "allow", "mv a.txt {E}/k", []string{"k"}},
		{"B07", "allow", "cd src && mv a.go b.go", nil},
	}
	if runtime.GOOS == "windows" {
		rows = append(rows,
			probeRow{"K03J", "block", "mv x/authorized_keys {E}/sj", []string{"sj"}},
			probeRow{"K04J", "block", "mv --target-directory={E}/sj x/authorized_keys", []string{"sj"}})
	}
	for _, mode := range []string{"managed", "managed-extvisible", "oss"} {
		for _, connector := range []string{"claudecode", "codex"} {
			installDefaultProfileConnector(t, connector)
			for _, row := range rows {
				if runtime.GOOS == "windows" && row.id == "B06" {
					// A Windows gateway follows the link the move lands on
					// (ext/k -> authorized_keys) and blocks: the safe side of
					// the GAP-2559 link-entry reading, which is POSIX-only
					// (native preflight, T11 integrator note in classifier-c.md).
					continue
				}
				t.Run(mode+"/"+connector+"/"+row.id, func(t *testing.T) {
					checkR105MoveRow(t, mode, connector, row.id, row.want, row.command, row.needs)
				})
			}
		}
	}
}

// checkR105MoveRow judges one row of TestR105MoveIntoSSHDirectoryBlocksOnManaged
// in one mode and connector.
func checkR105MoveRow(t *testing.T, mode, connector, id, want, rowCommand string, needs []string) {
	t.Helper()
	row := struct{ id, want, command string }{id, want, rowCommand}
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
	files = append(files, filepath.Join(state, "config.yaml"))
	for _, name := range files {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The fixtures in a fixed order: kdd links to s.
	made := map[string]testenv.LinkFixture{}
	for _, link := range []struct{ name, link, target string }{
		{"hx", filepath.Join(state, "hooks", "hx.sh"), filepath.Join(dot, "hx.sh")},
		{"y", filepath.Join(ext, "y"), state},
		{"s", filepath.Join(ext, "s"), filepath.Join(home, ".ssh")},
		{"k", filepath.Join(ext, "k"), filepath.Join(home, ".ssh", "authorized_keys")},
		{"k2", filepath.Join(ext, "k2"), filepath.Join(home, "keys", "ak")},
		{"kd", filepath.Join(ext, "kd"), filepath.Join(home, ".ssh")},
		{"kdd", filepath.Join(ext, "kdd"), filepath.Join(ext, "s")},
		{"keys", filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, "keys", "ak")},
	} {
		made[link.name] = testenv.TrySymlink(t, link.target, link.link)
	}
	for _, need := range needs {
		if need == "sj" {
			testenv.Junction(t, filepath.Join(home, ".ssh"), filepath.Join(ext, "sj"))
			continue
		}
		made[need].Require(t)
	}
	t.Setenv("HOME", home)
	command := strings.NewReplacer("{E}", filepath.ToSlash(ext)).Replace(row.command)
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
