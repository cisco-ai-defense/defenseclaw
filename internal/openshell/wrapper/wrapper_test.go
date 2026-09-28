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

func TestParseShell(t *testing.T) {
	for in, want := range map[string]Shell{"bash": Bash, "/bin/zsh": Zsh, "/usr/local/bin/fish": Fish, " zsh ": Zsh} {
		got, err := ParseShell(in)
		if err != nil || got != want {
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
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	cases := []struct {
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
	}
	for _, c := range cases {
		env = c.env
		got, err := RCPath(c.shell, "/home/u", getenv)
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
			dir := t.TempDir()
			rc := filepath.Join(dir, "rc")
			original := "export PATH=$HOME/bin:$PATH\nalias ll='ls -l'"
			if err := os.WriteFile(rc, []byte(original), 0o640); err != nil {
				t.Fatal(err)
			}
			bin := "/opt/defense claw/bin/defenseclaw-gateway"

			ch, err := Enable(sh, rc, bin, claude)
			if err != nil || !ch.Changed {
				t.Fatalf("enable claude = %+v, %v", ch, err)
			}
			ch, err = Enable(sh, rc, bin, claude)
			if err != nil || ch.Changed {
				t.Fatalf("enable claude again = %+v, %v; want no change", ch, err)
			}
			if _, err := Enable(sh, rc, bin, codex); err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(rc)
			text := string(data)
			if !strings.HasPrefix(text, original+"\n\n"+BeginMarker+"\n") {
				t.Fatalf("rc does not keep the user's content first:\n%s", text)
			}
			if strings.Count(text, BeginMarker) != 1 || strings.Count(text, EndMarker) != 1 {
				t.Fatalf("want exactly one block:\n%s", text)
			}
			b, err := Read(rc)
			if err != nil || b.Binary != bin || strings.Join(b.Commands(), ",") != "claude,codex" {
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
			data, _ = os.ReadFile(rc)
			if string(data) != original+"\n" {
				t.Fatalf("after removing every wrapper rc = %q, want the original content", data)
			}
		})
	}
}

func TestEnableCreatesMissingFileAndDirectories(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".config", "fish", "config.fish")
	ch, err := Enable(Fish, rc, "/usr/bin/defenseclaw-gateway", claude)
	if err != nil || !ch.Changed {
		t.Fatalf("enable = %+v, %v", ch, err)
	}
	data, err := os.ReadFile(rc)
	if err != nil || !strings.HasPrefix(string(data), BeginMarker) {
		t.Fatalf("rc = %q, %v", data, err)
	}
	if info, _ := os.Stat(rc); info.Mode().Perm() != 0o644 {
		t.Fatalf("new rc mode = %v", info.Mode().Perm())
	}
}

func TestDisableMissingFileIsNoop(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".bashrc")
	if ch, err := Disable(Bash, rc, "claude"); err != nil || ch.Changed {
		t.Fatalf("disable = %+v, %v", ch, err)
	}
	if _, err := os.Stat(rc); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("disable created the rc file")
	}
}

func TestEditFollowsSymlinkedRC(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "dotfiles", "zshrc")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("setopt autocd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, ".zshrc")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Enable(Zsh, link, "/usr/bin/defenseclaw-gateway", claude); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the rc symlink was replaced")
	}
	data, _ := os.ReadFile(real)
	if !strings.Contains(string(data), BeginMarker) {
		t.Fatal("the block did not land in the symlink target")
	}
}

func TestDamagedMarkersRefused(t *testing.T) {
	for name, content := range map[string]string{
		"begin only": "a\n" + BeginMarker + "\nclaude() {\n",
		"end only":   EndMarker + "\n",
		"two blocks": BeginMarker + "\n" + EndMarker + "\n" + BeginMarker + "\n" + EndMarker + "\n",
		"reversed":   EndMarker + "\n" + BeginMarker + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			rc := filepath.Join(t.TempDir(), "rc")
			if err := os.WriteFile(rc, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Enable(Bash, rc, "/usr/bin/dc", claude); !errors.Is(err, ErrMalformedBlock) {
				t.Fatalf("enable = %v, want ErrMalformedBlock", err)
			}
			if data, _ := os.ReadFile(rc); string(data) != content {
				t.Fatal("a damaged rc file was modified")
			}
		})
	}
}

func TestRenderRefusesUnsafeInput(t *testing.T) {
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

func TestScan(t *testing.T) {
	home := t.TempDir()
	getenv := func(string) string { return "" }
	if got := Scan(home, getenv); len(got) != 0 {
		t.Fatalf("scan of an empty home = %+v", got)
	}
	if _, err := Enable(Zsh, filepath.Join(home, ".zshrc"), "/usr/bin/dc", codex); err != nil {
		t.Fatal(err)
	}
	got := Scan(home, getenv)
	if len(got) != 1 || got[0].Shell != Zsh || !got[0].Block.Has("codex") {
		t.Fatalf("scan = %+v", got)
	}
}

// TestPOSIXWrapperBehaviour runs the generated bash function against stub
// binaries: it must call the sandbox, pass arguments through verbatim, and
// run the harness natively when bypassed or nested.
func TestPOSIXWrapperBehaviour(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "dc gateway")
	writeScript(t, bin, "#!/bin/sh\nprintf 'sandbox:'; for a in \"$@\"; do printf '[%s]' \"$a\"; done; echo\n")
	native := filepath.Join(dir, "bin")
	if err := os.MkdirAll(native, 0o755); err != nil {
		t.Fatal(err)
	}
	writeScript(t, filepath.Join(native, "claude"), "#!/bin/sh\nprintf 'native:'; for a in \"$@\"; do printf '[%s]' \"$a\"; done; echo\n")
	rc := filepath.Join(dir, "rc")
	if _, err := Enable(Bash, rc, bin, claude); err != nil {
		t.Fatal(err)
	}
	run := func(extraEnv ...string) string {
		cmd := exec.Command(bash, "--norc", "-c", `. "$1"; claude -p "two words" "it's"`, "x", rc)
		cmd.Env = append([]string{"PATH=" + native + ":/usr/bin:/bin"}, extraEnv...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("bash: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if got := run(); got != "sandbox:[sandbox][run][claude][--][-p][two words][it's]" {
		t.Errorf("wrapped call = %q", got)
	}
	if got := run(EnvBypass + "=1"); got != "native:[-p][two words][it's]" {
		t.Errorf("bypassed call = %q", got)
	}
	if got := run("DEFENSECLAW_SANDBOX_ID=sb-1"); got != "native:[-p][two words][it's]" {
		t.Errorf("nested call = %q", got)
	}
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, "--norc", "-c", `. "$1"; claude`, "x", rc)
	cmd.Env = []string{"PATH=" + native + ":/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 127 || !strings.Contains(string(out), "launcher is missing") {
		t.Errorf("missing binary = %v: %s; want exit 127 with a notice and no native run", err, out)
	}
	for _, sh := range []string{"zsh"} {
		if p, err := exec.LookPath(sh); err == nil {
			zrc := filepath.Join(dir, "zrc")
			if _, err := Enable(Zsh, zrc, "/usr/bin/dc", claude); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(p, "-n", zrc).CombinedOutput(); err != nil {
				t.Errorf("zsh -n: %v: %s", err, out)
			}
		}
	}
}

// TestPOSIXWrapperReplacesAlias: an alias of the harness defined earlier in
// the rc file (Claude Code's installer writes one) must neither break the
// function definition nor keep running the harness natively.
func TestPOSIXWrapperReplacesAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "dc")
	writeScript(t, bin, "#!/bin/sh\nprintf 'sandbox:'; for a in \"$@\"; do printf '[%s]' \"$a\"; done; echo\n")
	native := filepath.Join(dir, "native-claude")
	writeScript(t, native, "#!/bin/sh\necho native\n")
	for _, tc := range []struct {
		shell Shell
		bin   string
		// prelude makes a non-interactive shell expand aliases.
		prelude string
		args    []string
	}{
		{Bash, "bash", "shopt -s expand_aliases\n", []string{"--norc", "-c"}},
		{Zsh, "zsh", "", []string{"-f", "-c"}},
	} {
		sh, err := exec.LookPath(tc.bin)
		if err != nil {
			t.Logf("%s not installed", tc.bin)
			continue
		}
		for _, alias := range []string{native, native + " --from-alias"} {
			rc := filepath.Join(t.TempDir(), "rc")
			writeScript(t, rc, tc.prelude+"alias claude='"+alias+"'\n")
			if _, err := Enable(tc.shell, rc, bin, claude); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(sh, append(tc.args, `. "$1" && claude -p x`, "x", rc)...)
			cmd.Env = []string{"PATH=/usr/bin:/bin"}
			out, err := cmd.CombinedOutput()
			if got := strings.TrimSpace(string(out)); err != nil || got != "sandbox:[sandbox][run][claude][--][-p][x]" {
				t.Errorf("%s with alias %q: %v: %q", tc.bin, alias, err, got)
			}
		}
	}
}

// TestPOSIXWrapperDropsAliasDefinedLater: an alias of the harness defined
// after the block (an installer appending to the rc file) is expanded
// before functions are looked up when the command is typed, so it would
// run the harness natively while the wrapper looks enabled. The block
// drops it again before the first prompt of an interactive shell, keeps
// the exit status the prompt shows, and does not pile up hooks when the rc
// file is sourced again.
func TestPOSIXWrapperDropsAliasDefinedLater(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "dc")
	writeScript(t, bin, "#!/bin/sh\nprintf 'sandbox:'; for a in \"$@\"; do printf '[%s]' \"$a\"; done; echo\n")
	native := filepath.Join(dir, "native-claude")
	writeScript(t, native, "#!/bin/sh\necho native\n")
	// Typed as an interactive user would: a command, the status a prompt
	// hook must keep, the rc file sourced twice more (the hooks it then
	// registers are counted), and the command again.
	input := "claude -p x\nfalse\necho \"status=$?\"\n. \"$DC_RC\"; . \"$DC_RC\"; HOOKS\nclaude -p y\necho \"hooks=$DC_HOOKS\"\nexit\n"
	for _, tc := range []struct {
		shell Shell
		bin   string
		// hooks prints how often the hook is registered.
		hooks string
		args  func(rc string) ([]string, []string)
	}{
		{Bash, "bash", `DC_HOOKS=$(printf %s "$PROMPT_COMMAND" | grep -o __defenseclaw_unalias | wc -l | tr -d " ")`, func(rc string) ([]string, []string) {
			return []string{"--noprofile", "--rcfile", rc, "-i"}, nil
		}},
		{Zsh, "zsh", `DC_HOOKS=${#${(M)precmd_functions:#__defenseclaw_unalias}}`, func(rc string) ([]string, []string) {
			return []string{"-d", "-i"}, []string{"ZDOTDIR=" + filepath.Dir(rc)}
		}},
	} {
		sh, err := exec.LookPath(tc.bin)
		if err != nil {
			t.Logf("%s not installed", tc.bin)
			continue
		}
		rcDir := t.TempDir()
		rc := filepath.Join(rcDir, ".zshrc")
		if _, err := Enable(tc.shell, rc, bin, claude); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(rc, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("alias claude='" + native + "'\n")
		_ = f.Close()
		in := strings.Replace(input, "HOOKS", tc.hooks, 1)
		args, env := tc.args(rc)
		cmd := exec.Command(sh, args...)
		cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + rcDir, "TERM=dumb", "DC_RC=" + rc}, env...)
		cmd.Stdin = strings.NewReader(in)
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s -i: %v\n%s", tc.bin, err, stderr.String())
		}
		got := stdout.String()
		for _, want := range []string{"sandbox:[sandbox][run][claude][--][-p][x]", "status=1", "sandbox:[sandbox][run][claude][--][-p][y]", "hooks=1"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: output lacks %q:\n%s\nstderr:\n%s", tc.bin, want, got, stderr.String())
			}
		}
		if strings.Contains(got, "native") {
			t.Errorf("%s: an alias defined after the block ran the harness natively:\n%s", tc.bin, got)
		}
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

func writeScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}
