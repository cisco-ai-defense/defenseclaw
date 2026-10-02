// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

// sandboxManifestCommand describes one sandbox subcommand for the Python
// stub parity check (track G2) and for this golden test.
type sandboxManifestCommand struct {
	Path  string                 `json:"path"`
	Use   string                 `json:"use"`
	Short string                 `json:"short"`
	Flags []sandboxManifestFlagJ `json:"flags,omitempty"`
}

type sandboxManifestFlagJ struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Type      string `json:"type"`
	Default   string `json:"default,omitempty"`
}

func sandboxManifest(root *cobra.Command) []sandboxManifestCommand {
	var out []sandboxManifestCommand
	var walk func(c *cobra.Command, path string)
	walk = func(c *cobra.Command, path string) {
		for _, sub := range c.Commands() {
			if sub.Hidden || sub.Name() == "help" {
				continue
			}
			p := strings.TrimSpace(path + " " + sub.Name())
			m := sandboxManifestCommand{Path: p, Use: sub.Use, Short: sub.Short}
			sub.Flags().VisitAll(func(f *pflag.Flag) {
				if f.Name == "help" {
					return
				}
				m.Flags = append(m.Flags, sandboxManifestFlagJ{Name: f.Name, Shorthand: f.Shorthand, Type: f.Value.Type(), Default: f.DefValue})
			})
			sort.Slice(m.Flags, func(i, j int) bool { return m.Flags[i].Name < m.Flags[j].Name })
			out = append(out, m)
			walk(sub, p)
		}
	}
	walk(root, "sandbox")
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// TestSandboxCommandManifest pins the `sandbox` command tree (commands,
// flags, defaults). The Python Click stubs mirror it; regenerate with
// DEFENSECLAW_UPDATE_GOLDEN=1 after an intended change.
func TestSandboxCommandManifest(t *testing.T) {
	got, err := json.MarshalIndent(sandboxManifest(sandboxCmd), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "sandbox_commands.json")
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s (DEFENSECLAW_UPDATE_GOLDEN=1 writes it): %v", golden, err)
	}
	// A Windows checkout gives the golden CRLF line endings.
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("the sandbox command tree changed; update %s with DEFENSECLAW_UPDATE_GOLDEN=1 and the Python stubs", golden)
	}
}

// TestSandboxCommandTreeCoversThePlan guards the planned commands
// independently of the regenerable golden manifest.
func TestSandboxCommandTreeCoversThePlan(t *testing.T) {
	var paths []string
	for _, m := range sandboxManifest(sandboxCmd) {
		paths = append(paths, strings.TrimPrefix(m.Path, "sandbox "))
	}
	for _, want := range []string{
		"setup", "doctor", "run", "list", "status", "connect", "exec", "stop", "start", "delete", "logs", "activity",
		"undo", "review", "approvals", "approve", "reject", "unblock", "pull", "policy show", "policy explain",
		"policy suggest", "policy allow", "policy block", "pack list", "pack show", "pack validate", "image build",
		"image list", "image prune", "image rm", "enable", "disable", "teardown",
	} {
		if !slices.Contains(paths, want) {
			t.Errorf("sandbox %s is missing", want)
		}
	}
	for _, path := range []string{"list", "status", "approvals", "doctor"} {
		cmd, _, err := sandboxCmd.Find(strings.Fields(path))
		if err != nil || cmd.Flags().Lookup("output") == nil {
			t.Errorf("sandbox %s has no --output", path)
		}
		if err == nil && cmd.Flags().Lookup("json") == nil {
			t.Errorf("sandbox %s has no --json (GAP-1247)", path)
		}
	}
}

func TestSandboxRunArgs(t *testing.T) {
	run, _, err := sandboxCmd.Find([]string{"run"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		cmd     func() *cobra.Command
		argv    []string
		wantErr string
		dashed  []string
	}{
		{newSandboxRunCmd, []string{"claude"}, "", nil},
		{newSandboxRunCmd, []string{"claude", "--copy", "--", "-p", "fix it"}, "", []string{"-p", "fix it"}},
		{newSandboxRunCmd, []string{}, "name the harness", nil},
		{newSandboxRunCmd, []string{"claude", "extra"}, "pass harness arguments after --", nil},
		{newSandboxExecCmd, []string{"box", "--", "ls", "-la"}, "", []string{"ls", "-la"}},
		{newSandboxExecCmd, []string{"box", "ls"}, "exec <name> -- <command>", nil},
	} {
		cmd := c.cmd()
		if err := cmd.ParseFlags(c.argv); err != nil {
			t.Fatalf("%v: %v", c.argv, err)
		}
		args := cmd.Flags().Args()
		err := cmd.Args(cmd, args)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%v: %v", c.argv, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%v: err = %v, want %q", c.argv, err, c.wantErr)
		case c.dashed != nil && !slices.Equal(args[cmd.ArgsLenAtDash():], c.dashed):
			t.Errorf("%v: harness args = %v", c.argv, args[cmd.ArgsLenAtDash():])
		}
	}
	if run.Flags().Lookup("prompt").Shorthand != "p" || run.Flags().Lookup("detach").Shorthand != "d" {
		t.Error("run lost its -p/-d shorthands")
	}
}

// TestSandboxRunHelpNamesEveryHarness pins that `run --help` names every
// harness the way the command line takes it (sandboxcli.HarnessArg), and
// that the Python stub's `run` help is the same text (manual test R2-73).
func TestSandboxRunHelpNamesEveryHarness(t *testing.T) {
	run, _, err := sandboxCmd.Find([]string{"run"})
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Join(strings.Fields(run.Long), " ")
	for _, h := range harness.Names() {
		spec, _ := harness.Get(h)
		name := sandboxcli.HarnessArg(spec)
		if !regexp.MustCompile(`[ (]` + regexp.QuoteMeta(name) + `[ ,)]`).MatchString(long) {
			t.Errorf("run --help does not name %s (%s):\n%s", name, spec.DisplayName, long)
		}
		if got, err := sandboxcli.ResolveHarness(name); err != nil || got.Name != spec.Name {
			t.Errorf("run %s resolves to %v, %v; want %s", name, got, err, spec.Name)
		}
	}
	// Certification AG-MAC-F8: Antigravity is named as image build names
	// it, and the help says its command works too.
	if !strings.Contains(long, "omnigent or antigravity (its command, agy, works too;") {
		t.Errorf("run --help does not name antigravity with agy:\n%s", long)
	}
	if stub := pythonStubLong(t, "run"); stub != long {
		t.Errorf("the Python stub's run help differs from the Go one:\n stub: %s\n   go: %s", stub, long)
	}
}

// pythonStubLong is the long help of the Python stub of a sandbox command
// (cli/defenseclaw/commands/cmd_sandbox.py), its string literals joined
// and its whitespace collapsed.
func pythonStubLong(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "cli", "defenseclaw", "commands", "cmd_sandbox.py"))
	if err != nil {
		t.Fatal(err)
	}
	src := strings.ReplaceAll(string(data), "\r\n", "\n") // CRLF on a Windows checkout
	i := strings.Index(src, `("`+path+`",),`)
	if i < 0 {
		t.Fatalf("cmd_sandbox.py has no stub for %s", path)
	}
	j := strings.Index(src[i:], "long=(\n")
	if j < 0 {
		t.Fatalf("the %s stub has no long=( … ) help", path)
	}
	var b strings.Builder
	for _, line := range strings.Split(src[i+j+len("long=(\n"):], "\n") {
		line = strings.TrimSpace(line)
		if line == ")," {
			break
		}
		if len(line) >= 2 && line[0] == '\'' && line[len(line)-1] == '\'' {
			// A Python single-quoted string: the same text in Go quotes.
			line = strconv.Quote(strings.ReplaceAll(line[1:len(line)-1], `\'`, `'`))
		}
		s, err := strconv.Unquote(line)
		if err != nil {
			t.Fatalf("the %s stub's help line %q is not a plain string literal: %v", path, line, err)
		}
		b.WriteString(s)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// The Python stubs of the commands whose help says how a Mac differs (every
// run works on a copy, which review previews and --yes leaves in the
// sandbox; setup and doctor handle the MicroVM driver) carry the Go help.
func TestSandboxStubHelpIsTheGoHelp(t *testing.T) {
	for _, path := range []string{"setup", "doctor", "run", "review"} {
		cmd, _, err := sandboxCmd.Find([]string{path})
		if err != nil {
			t.Fatal(err)
		}
		if stub, long := pythonStubLong(t, path), strings.Join(strings.Fields(cmd.Long), " "); stub != long {
			t.Errorf("the Python stub's %s help differs from the Go one:\n stub: %s\n   go: %s", path, stub, long)
		}
	}
	for _, path := range []string{"run", "connect"} {
		cmd, _, _ := sandboxCmd.Find([]string{path})
		if usage := cmd.Flags().Lookup("yes").Usage; !strings.Contains(usage, "copy: leave them in the sandbox for pull") {
			t.Errorf("sandbox %s --yes: %q does not say what a copy's end does", path, usage)
		}
	}
}

// sandboxPreRun refuses, before any command runs, a machine sandboxes do
// not run on: Windows, and a Mac without Apple silicon, where OpenShell's
// MicroVM driver does not run. Teardown still runs on such a Mac: it
// removes what an earlier setup left there.
func TestSandboxHostRefusal(t *testing.T) {
	const windows = "OpenShell sandboxes run on Linux and macOS only; Windows and WSL2 are not supported"
	for _, c := range []struct {
		goos, goarch string
		cleanup      bool
		want         string
	}{
		{"linux", "amd64", false, ""}, {"linux", "arm64", false, ""}, {"darwin", "arm64", false, ""},
		{"darwin", "amd64", false, "OpenShell sandboxes do not run on this machine: "},
		{"darwin", "amd64", true, ""},
		{"windows", "amd64", false, windows}, {"windows", "amd64", true, windows},
	} {
		err := sandboxHostRefusal(c.goos, c.goarch, c.cleanup)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s/%s: %v", c.goos, c.goarch, err)
		case c.want != "" && (err == nil || !strings.HasPrefix(err.Error(), c.want)):
			t.Errorf("%s/%s: %v, want %q", c.goos, c.goarch, err, c.want)
		case c.goos == "darwin" && err != nil && (!strings.Contains(err.Error(), "Apple silicon") || strings.Contains(err.Error(), "openshell: ") ||
			!strings.Contains(err.Error(), "`defenseclaw sandbox teardown` still removes")):
			t.Errorf("%s/%s: %v does not say why and what still runs", c.goos, c.goarch, err)
		}
	}
	if teardown, _, _ := sandboxCmd.Find([]string{"teardown"}); teardown.Annotations[sandboxConfigOptional] != "true" {
		t.Fatal("sandbox teardown is no longer the command a Mac without Apple silicon still runs")
	}
}

// Every command that can ask a question takes --yes, the answer the
// no-terminal refusal points to; nothing points to --non-interactive, which
// only setup takes (manual test L6).
func TestSandboxCommandsThatAskTakeYes(t *testing.T) {
	for _, path := range []string{"delete", "undo", "teardown", "doctor", "setup", "stop", "run", "connect", "image rm"} {
		cmd, _, err := sandboxCmd.Find(strings.Fields(path))
		if err != nil {
			t.Fatalf("sandbox %s: %v", path, err)
		}
		if f := cmd.Flags().Lookup("yes"); f == nil || f.Shorthand != "y" {
			t.Errorf("sandbox %s asks questions but takes no --yes/-y", path)
		}
	}
	msg := sandboxcli.ErrNoTerminal.Error()
	if strings.Contains(msg, "--non-interactive") || !strings.Contains(msg, "--yes") {
		t.Fatalf("ErrNoTerminal = %q", msg)
	}
}

var (
	// hintLiteral is a Go string literal.
	hintLiteral = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	// hintFormat is a fmt hint whose %s is CommandName: "`%s start %s`".
	hintFormat = regexp.MustCompile("`%s ([^`]*)`")
)

// sandboxHints returns every `defenseclaw sandbox …` suggestion in the
// sandboxcli sources: the string literals after CommandName on its line
// (the first one holds the command's words), or a fmt verb standing for it.
func sandboxHints(t *testing.T) map[string][]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "openshell", "sandboxcli", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("sandboxcli sources: %v", err)
	}
	hints := map[string][]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "CommandName") || strings.HasPrefix(strings.TrimSpace(line), "//") || strings.Contains(line, "const CommandName") {
				continue
			}
			where := fmt.Sprintf("%s:%d", filepath.Base(f), n+1)
			for _, seg := range strings.Split(line, "CommandName")[1:] {
				var lits []string
				for _, m := range hintLiteral.FindAllStringSubmatch(seg, -1) {
					lits = append(lits, m[1])
				}
				if len(lits) > 0 && strings.HasPrefix(lits[0], " ") {
					hints[where+" "+strings.Join(lits, "…")] = lits
				}
			}
			for _, m := range hintFormat.FindAllStringSubmatch(line, -1) {
				hints[where+" "+m[1]] = []string{" " + m[1]}
			}
		}
	}
	return hints
}

// Every command a sandbox message suggests exists, and so do the flags it
// names: the hints are what users type next (manual test M13).
func TestSandboxHintsNameCommandsThatExist(t *testing.T) {
	hints := sandboxHints(t)
	if len(hints) < 30 {
		t.Fatalf("found only %d hints; the scan is broken", len(hints))
	}
	for where, lits := range hints {
		cmd := sandboxCmd
		for _, word := range strings.Fields(lits[0]) {
			word = strings.Trim(word, "`(),;.")
			var next *cobra.Command
			for _, sub := range cmd.Commands() {
				if sub.Name() == word {
					next = sub
				}
			}
			if next == nil {
				break
			}
			cmd = next
		}
		if cmd == sandboxCmd {
			t.Errorf("%s: suggests `defenseclaw sandbox%s`, which is no command", where, lits[0])
			continue
		}
		for _, lit := range lits {
			for _, tok := range strings.FieldsFunc(lit, func(r rune) bool { return r == ' ' || r == '|' || r == '`' || r == '(' || r == ')' }) {
				if !strings.HasPrefix(tok, "-") || tok == "-" || tok == "--" || strings.HasPrefix(tok, "--help") {
					continue
				}
				name := strings.TrimLeft(strings.SplitN(tok, "=", 2)[0], "-")
				var f *pflag.Flag
				if strings.HasPrefix(tok, "--") {
					f = cmd.Flags().Lookup(name)
				} else if len(name) == 1 {
					f = cmd.Flags().ShorthandLookup(name)
				}
				if f == nil {
					t.Errorf("%s: suggests `%s %s`, which takes no %s", where, cmd.CommandPath(), tok, tok)
				}
			}
		}
	}
}

// `sandbox pack list|show|validate` work on a fresh DEFENSECLAW_HOME with no
// config.yaml: an administrator reads a digest before pinning it (manual
// test L11). Other commands still need the configuration, and a broken one
// is reported.
func TestSandboxPackCommandsWithoutAConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sandbox commands refuse Windows before they read config.yaml")
	}
	prev := cfg
	t.Cleanup(func() { cfg = prev })
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	for _, path := range []string{"pack list", "pack show", "pack validate"} {
		cmd, _, err := sandboxCmd.Find(strings.Fields(path))
		if err != nil {
			t.Fatal(err)
		}
		cfg = nil
		if err := sandboxPreRun(cmd, nil); err != nil {
			t.Fatalf("sandbox %s without config.yaml: %v", path, err)
		}
		if cfg == nil || cfg.OpenShell.PackDir != filepath.Join(home, "policies", "sandbox") {
			t.Fatalf("sandbox %s: cfg = %+v", path, cfg)
		}
	}
	list, _, _ := sandboxCmd.Find([]string{"list"})
	if err := sandboxPreRun(list, nil); err == nil {
		t.Fatal("sandbox list ran without a configuration")
	}
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("version: [not yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	show, _, _ := sandboxCmd.Find([]string{"pack", "show"})
	if err := sandboxPreRun(show, nil); err == nil {
		t.Fatal("a broken config.yaml was ignored")
	}
}

// GAP-1247: --json is the same as --output json.
func TestSandboxJSONFlagSelectsJSONOutput(t *testing.T) {
	cmd := &cobra.Command{Use: "x"}
	out := outputFlag(cmd)
	if err := cmd.Flags().Parse([]string{"--json"}); err != nil {
		t.Fatal(err)
	}
	if *out != "json" {
		t.Fatalf("--json gave output %q", *out)
	}
}
