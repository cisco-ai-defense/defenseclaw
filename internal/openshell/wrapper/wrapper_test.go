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

package wrapper

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var claude = Wrap{Command: "claude", Harness: "claude"}
var codex = Wrap{Command: "codex", Harness: "codex"}

// echoArgs is a stub harness or launcher that prints its arguments.
const echoArgs = "#!/bin/sh\nprintf '%s:' \"$STUB\"; for a in \"$@\"; do printf '[%s]' \"$a\"; done; echo\n"

func TestParseShell(t *testing.T) {
	for in, want := range map[string]Shell{"bash": Bash, "/bin/zsh": Zsh, "/usr/local/bin/fish": Fish, " zsh ": Zsh} {
		if got, err := ParseShell(in); err != nil || got != want {
			t.Errorf("ParseShell(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "sh", "/bin/tcsh", "powershell"} {
		if _, err := ParseShell(in); err == nil {
			t.Errorf("ParseShell(%q) accepted", in)
		}
	}
}

func TestRCPath(t *testing.T) {
	for _, c := range []struct {
		shell Shell
		env   map[string]string
		want  string
	}{
		{Bash, nil, "/home/u/.bashrc"},
		{Zsh, nil, "/home/u/.zshrc"},
		{Zsh, map[string]string{"ZDOTDIR": "/home/u/.config/zsh"}, "/home/u/.config/zsh/.zshrc"},
		{Zsh, map[string]string{"ZDOTDIR": "relative"}, "/home/u/.zshrc"},
		{Fish, nil, "/home/u/.config/fish/config.fish"},
		{Fish, map[string]string{"XDG_CONFIG_HOME": "/x"}, "/x/fish/config.fish"},
	} {
		got, err := RCPath(c.shell, "/home/u", func(k string) string { return c.env[k] })
		if err != nil || got != c.want {
			t.Errorf("RCPath(%s, %v) = %q, %v; want %q", c.shell, c.env, got, err, c.want)
		}
	}
	if _, err := RCPath(Bash, "home", nil); err == nil {
		t.Error("relative home accepted")
	}
}

func TestEnableDisableRoundTrip(t *testing.T) {
	for _, sh := range Shells {
		t.Run(string(sh), func(t *testing.T) {
			rc := filepath.Join(t.TempDir(), "rc")
			original := "export PATH=$HOME/bin:$PATH\nalias ll='ls -l'"
			writeScript(t, rc, original, 0o640)
			bin := "/opt/defense claw/bin/defenseclaw-gateway"
			if ch, err := Enable(sh, rc, bin, claude); err != nil || !ch.Changed {
				t.Fatalf("enable claude = %+v, %v", ch, err)
			}
			if ch, err := Enable(sh, rc, bin, claude); err != nil || ch.Changed {
				t.Fatalf("enable claude again = %+v, %v; want no change", ch, err)
			}
			if _, err := Enable(sh, rc, bin, codex); err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(rc)
			text := string(data)
			if !strings.HasPrefix(text, original+"\n\n"+BeginMarker+"\n") || strings.Count(text, BeginMarker) != 1 || strings.Count(text, EndMarker) != 1 {
				t.Fatalf("want the user's content first and exactly one block:\n%s", text)
			}
			if b, err := Read(rc); err != nil || b.Binary != bin || strings.Join(b.Commands(), ",") != "claude,codex" {
				t.Fatalf("Read = %+v, %v", b, err)
			}
			if info, _ := os.Stat(rc); info.Mode().Perm() != 0o640 {
				t.Fatalf("mode = %v, want the original 0640", info.Mode().Perm())
			}
			if ch, err := Disable(sh, rc, "claude"); err != nil || !ch.Changed || ch.Block.Has("claude") || !ch.Block.Has("codex") {
				t.Fatalf("disable claude = %+v, %v", ch, err)
			}
			if ch, err := Disable(sh, rc, "claude"); err != nil || ch.Changed {
				t.Fatalf("disable claude again = %+v, %v; want no change", ch, err)
			}
			if _, err := Disable(sh, rc, "codex"); err != nil {
				t.Fatal(err)
			}
			if data, _ = os.ReadFile(rc); string(data) != original+"\n" {
				t.Fatalf("after removing every wrapper rc = %q, want the original content", data)
			}
		})
	}
}

// TestEditMissingAndSymlinkedRC: Enable creates a missing rc file (and its
// folders) with 0644, Disable of a missing one creates nothing, and a
// symlinked rc (dotfile managers) is edited at its target. Scan finds the
// blocks of the home's rc files.
func TestEditMissingAndSymlinkedRC(t *testing.T) {
	dir := t.TempDir()
	noenv := func(string) string { return "" }
	if got := Scan(dir, noenv); len(got) != 0 {
		t.Fatalf("scan of an empty home = %+v", got)
	}
	fish := filepath.Join(dir, ".config", "fish", "config.fish")
	if ch, err := Enable(Fish, fish, "/usr/bin/dc", claude); err != nil || !ch.Changed {
		t.Fatalf("enable = %+v, %v", ch, err)
	}
	if data, _ := os.ReadFile(fish); !strings.HasPrefix(string(data), BeginMarker) {
		t.Fatalf("rc = %q", data)
	}
	if info, _ := os.Stat(fish); info.Mode().Perm() != 0o644 {
		t.Fatalf("new rc mode = %v", info.Mode().Perm())
	}
	bashrc := filepath.Join(dir, ".bashrc")
	if ch, err := Disable(Bash, bashrc, "claude"); err != nil || ch.Changed {
		t.Fatalf("disable = %+v, %v", ch, err)
	}
	if _, err := os.Stat(bashrc); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("disable created the rc file")
	}

	real := filepath.Join(dir, "dotfiles", "zshrc")
	writeScript(t, real, "setopt autocd\n", 0o644)
	link := filepath.Join(dir, ".zshrc")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Enable(Zsh, link, "/usr/bin/dc", claude); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the rc symlink was replaced")
	}
	if data, _ := os.ReadFile(real); !strings.Contains(string(data), BeginMarker) {
		t.Fatal("the block did not land in the symlink target")
	}
	if got := Scan(dir, noenv); len(got) != 2 || got[0].Shell != Zsh || got[1].Shell != Fish || !got[0].Block.Has("claude") {
		t.Fatalf("scan = %+v", got)
	}
}

// TestRefusesDamagedMarkersAndUnsafeInput: an rc file with damaged markers
// is left untouched, and nothing unquoted reaches the rendered block.
func TestRefusesDamagedMarkersAndUnsafeInput(t *testing.T) {
	for name, content := range map[string]string{
		"begin only": "a\n" + BeginMarker + "\nclaude() {\n",
		"end only":   EndMarker + "\n",
		"two blocks": BeginMarker + "\n" + EndMarker + "\n" + BeginMarker + "\n" + EndMarker + "\n",
		"reversed":   EndMarker + "\n" + BeginMarker + "\n",
	} {
		rc := filepath.Join(t.TempDir(), "rc")
		writeScript(t, rc, content, 0o644)
		if _, err := Enable(Bash, rc, "/usr/bin/dc", claude); !errors.Is(err, ErrMalformedBlock) {
			t.Errorf("%s: enable = %v, want ErrMalformedBlock", name, err)
		}
		if data, _ := os.ReadFile(rc); string(data) != content {
			t.Errorf("%s: a damaged rc file was modified", name)
		}
	}
	if _, err := Render(Bash, Block{Binary: "relative/bin", Wraps: []Wrap{claude}}); err == nil {
		t.Error("relative binary accepted")
	}
	if _, err := Render(Bash, Block{Binary: "/bin/dc", Wraps: []Wrap{{Command: "rm -rf", Harness: "claude"}}}); err == nil {
		t.Error("unsafe command name accepted")
	}
	if _, err := Enable(Bash, filepath.Join(t.TempDir(), "rc"), "/bin/dc", Wrap{Command: "claude;x", Harness: "claude"}); err == nil {
		t.Error("unsafe wrap accepted")
	}
	if got, err := Render(Bash, Block{Binary: "/bin/dc"}); err != nil || got != "" {
		t.Errorf("empty block = %q, %v", got, err)
	}
}

// stubs writes the sandbox launcher stub and a native harness stub.
func stubs(t *testing.T) (bin, native string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	dir := t.TempDir()
	bin = filepath.Join(dir, "dc gateway")
	writeScript(t, bin, strings.Replace(echoArgs, `"$STUB"`, "sandbox", 1), 0o755)
	native = filepath.Join(dir, "bin", "claude")
	writeScript(t, native, strings.Replace(echoArgs, `"$STUB"`, "native", 1), 0o755)
	return bin, native
}

const sandboxed = "sandbox:[sandbox][run][claude][--]"

// TestPOSIXWrapperBehaviour runs the generated bash function against stub
// binaries: it must call the sandbox, pass arguments through verbatim, run
// the harness natively when bypassed or nested, and exit 127 without
// running it natively when the launcher is gone.
func TestPOSIXWrapperBehaviour(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	bin, native := stubs(t)
	rc := filepath.Join(t.TempDir(), "rc")
	if _, err := Enable(Bash, rc, bin, claude); err != nil {
		t.Fatal(err)
	}
	run := func(script string, extraEnv ...string) (string, error) {
		cmd := exec.Command(bash, "--norc", "-c", `. "$1"; `+script, "x", rc)
		cmd.Env = append([]string{"PATH=" + filepath.Dir(native) + ":/usr/bin:/bin"}, extraEnv...)
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	for _, tc := range []struct{ env, want string }{
		{"", sandboxed + "[-p][two words][it's]"},
		{EnvBypass + "=1", "native:[-p][two words][it's]"},
		{"DEFENSECLAW_SANDBOX_ID=sb-1", "native:[-p][two words][it's]"},
	} {
		if got, err := run(`claude -p "two words" "it's"`, tc.env); err != nil || got != tc.want {
			t.Errorf("env %q: %q, %v; want %q", tc.env, got, err, tc.want)
		}
	}
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	out, err := run("claude")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 127 || !strings.Contains(out, "launcher is missing") || strings.Contains(out, "native") {
		t.Errorf("missing binary = %v: %s; want exit 127 with a notice and no native run", err, out)
	}
}

func TestFishWrapperSyntax(t *testing.T) {
	fish, err := exec.LookPath("fish")
	if err != nil {
		t.Skip("fish not installed")
	}
	rc := filepath.Join(t.TempDir(), "config.fish")
	if _, err := Enable(Fish, rc, "/usr/bin/defenseclaw-gateway", claude); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(fish, "--no-execute", rc).CombinedOutput(); err != nil {
		t.Fatalf("fish --no-execute: %v: %s", err, out)
	}
}

// TestPOSIXWrapperOverridesAliases: an alias of the harness defined before
// the block (Claude Code's installer writes one) would break the function
// definition, and one defined after it (an installer appending to the rc
// file) is expanded before functions are looked up when the command is
// typed; either way the harness would run natively while the wrapper looks
// enabled. The block removes the first and drops the second before the
// first prompt of an interactive shell, keeps the exit status the prompt
// shows, and does not pile up hooks when the rc file is sourced again.
func TestPOSIXWrapperOverridesAliases(t *testing.T) {
	bin, native := stubs(t)
	// Typed as an interactive user would: a command, the status a prompt
	// hook must keep, the rc file sourced twice more (the hooks it then
	// registers are counted), and the command again.
	input := "claude -p x\nfalse\necho \"status=$?\"\n. \"$DC_RC\"; . \"$DC_RC\"; HOOKS\nclaude -p y\necho \"hooks=$DC_HOOKS\"\nexit\n"
	for _, tc := range []struct {
		shell Shell
		// hooks prints how often the hook is registered.
		hooks string
		args  func(rc string) ([]string, []string)
	}{
		{Bash, `DC_HOOKS=$(printf %s "$PROMPT_COMMAND" | grep -o __defenseclaw_unalias | wc -l | tr -d " ")`, func(rc string) ([]string, []string) {
			return []string{"--noprofile", "--rcfile", rc, "-i"}, nil
		}},
		{Zsh, `DC_HOOKS=${#${(M)precmd_functions:#__defenseclaw_unalias}}`, func(rc string) ([]string, []string) {
			return []string{"-d", "-i"}, []string{"ZDOTDIR=" + filepath.Dir(rc)}
		}},
	} {
		sh, err := exec.LookPath(string(tc.shell))
		if err != nil {
			t.Logf("%s not installed", tc.shell)
			continue
		}
		rcDir := t.TempDir()
		rc := filepath.Join(rcDir, ".zshrc")
		writeScript(t, rc, "alias claude='"+native+" --from-alias'\n", 0o644)
		if _, err := Enable(tc.shell, rc, bin, claude); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(rc, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("alias claude='" + native + "'\n")
		_ = f.Close()
		args, env := tc.args(rc)
		cmd := exec.Command(sh, args...)
		cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + rcDir, "TERM=dumb", "DC_RC=" + rc}, env...)
		cmd.Stdin = strings.NewReader(strings.Replace(input, "HOOKS", tc.hooks, 1))
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s -i: %v\n%s", tc.shell, err, stderr.String())
		}
		got := stdout.String()
		for _, want := range []string{sandboxed + "[-p][x]", "status=1", sandboxed + "[-p][y]", "hooks=1"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: output lacks %q:\n%s\nstderr:\n%s", tc.shell, want, got, stderr.String())
			}
		}
		if strings.Contains(got, "native") {
			t.Errorf("%s: an alias ran the harness natively:\n%s", tc.shell, got)
		}
	}
}

func writeScript(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}
