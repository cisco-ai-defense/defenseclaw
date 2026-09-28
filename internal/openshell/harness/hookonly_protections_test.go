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

package harness

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// yamlCheckStub stands in for a harness interpreter's `-I -c <script> FILE`
// YAML check: it exits 3 for a file with a non-empty secrets or a non-local
// server key on one line, as the real check does for the parsed document.
const yamlCheckStub = "#!/bin/sh\n/usr/bin/grep -qE '^secrets: *[^ ]|^server: *[^ l]' \"$4\" && exit 3\nexit 0\n"

func writeExecutable(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestPythonLaunchersDropStartupVariables starts each Python harness's
// launcher with the interpreter start-up variables an agent could export
// from a login shell's start-up file: none may reach the harness, whose uv
// entry point runs Python without -I (PYTHONPATH alone would import a
// planted sitecustomize module).
func TestPythonLaunchersDropStartupVariables(t *testing.T) {
	planted := t.TempDir()
	env := []string{
		"PYTHONPATH=" + planted, "PYTHONHOME=" + planted, "PYTHONSTARTUP=" + planted + "/startup.py",
		"PYTHONUSERBASE=" + planted, "PYTHONPYCACHEPREFIX=" + planted, "PYTHONWARNINGS=ignore::planted.Warning",
		"PYTHONBREAKPOINT=planted.hook", "PYTHONINSPECT=1", "PYTHONSAFEPATH=",
	}
	for _, spec := range []*Spec{Hermes, OpenHands, OmniGent} {
		t.Run(spec.Name, func(t *testing.T) {
			l := newHookOnlyLauncher(t, spec)
			home := t.TempDir()
			got := l.run(t, home, append([]string{"HOME=" + home}, env...))
			if got.exit != 0 || got.record == "" {
				t.Fatalf("exit %d: %s", got.exit, got.output)
			}
			if strings.Contains(got.record, "PYENV ") {
				t.Fatalf("Python start-up variables reached %s:\n%s", spec.Name, got.record)
			}
		})
	}
}

func TestHermesLauncherRefusesSafeModePrefixes(t *testing.T) {
	l := newHookOnlyLauncher(t, Hermes)
	home := t.TempDir()
	// Hermes' parsers (top level and chat) resolve each of these to
	// --safe-mode.
	for _, args := range [][]string{
		{"--sa"}, {"--saf"}, {"--safe"}, {"--safe-"}, {"--safe-mo"}, {"--safe-mode"}, {"--safe-mode=1"},
		{"chat", "--safe", "-q", "hi"}, {"--safe", "chat"},
	} {
		got := l.run(t, home, []string{"HOME=" + home}, args...)
		if got.exit != 2 || got.record != "" || !strings.Contains(got.output, "safe mode") {
			t.Errorf("%q: exit %d record %q output %q", args, got.exit, got.record, got.output)
		}
	}
	// Not prefixes of --safe-mode: --s is ambiguous in the parser, --save
	// and --skills are other options.
	for _, args := range [][]string{{"--s"}, {"--save"}, {"--skills", "x"}, {"chat", "-q", "be safe"}} {
		if got := l.run(t, home, []string{"HOME=" + home}, args...); got.exit != 0 || got.record == "" {
			t.Errorf("%q refused: exit %d %s", args, got.exit, got.output)
		}
	}
}

func TestHermesLauncherPinsHome(t *testing.T) {
	l := newHookOnlyLauncher(t, Hermes)
	home := t.TempDir()
	got := l.run(t, home, []string{"HOME=" + home, "HERMES_HOME=/tmp/elsewhere", "HERMES_PYTHON_SRC_ROOT=/tmp/src",
		"HERMES_LAZY_INSTALL_TARGET=/tmp/lazy", "HERMES_ENABLE_PROJECT_PLUGINS=1"})
	for _, want := range []string{"ENV HERMES_HOME=" + home + "/.hermes\n", "ENV HERMES_PYTHON_SRC_ROOT=\n", "ENV HERMES_LAZY_INSTALL_TARGET=\n"} {
		if got.exit != 0 || !strings.Contains(got.record, want) {
			t.Fatalf("exit %d, record lacks %q:\n%s%s", got.exit, want, got.record, got.output)
		}
	}
}

// utf16LE encodes s the way Notepad's "Unicode" does: a BOM, then UTF-16LE.
func utf16LE(s string) []byte {
	out := []byte{0xff, 0xfe}
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// TestHermesLauncherRefusesHomeCode plants, in the Hermes home and a profile,
// what Hermes loads at start from its workload-writable home: .env files
// that switch the hooks off or move the managed scope (Hermes loads them
// over the process environment, after stripping NULs and splitting glued
// KEY=VALUE pairs, as utf-8, latin-1 or UTF-16), Python plugins it imports
// whatever plugins.enabled says, and secret sources that set variables
// before the managed .env applies.
func TestHermesLauncherRefusesHomeCode(t *testing.T) {
	type planting struct {
		file string // relative to the Hermes home
		data []byte
		dir  bool
		// refusal is what the launcher must say; empty: it must start.
		refusal string
	}
	cases := map[string]planting{
		"env safe mode":          {file: ".env", data: []byte("HERMES_SAFE_MODE=1\n"), refusal: ".env sets HERMES_SAFE_MODE"},
		"env managed dir":        {file: ".env", data: []byte("export HERMES_MANAGED_DIR=/tmp/x\n"), refusal: "sets HERMES_MANAGED_DIR"},
		"env home":               {file: ".env", data: []byte("HERMES_HOME=/tmp/x\n"), refusal: "sets HERMES_HOME"},
		"env project plugins":    {file: ".env", data: []byte("HERMES_ENABLE_PROJECT_PLUGINS=true\n"), refusal: "sets HERMES_ENABLE_PROJECT_PLUGINS"},
		"env python path":        {file: ".env", data: []byte("PYTHONPATH=/tmp/x\n"), refusal: "sets PYTHONPATH"},
		"env glued pair":         {file: ".env", data: []byte("OPENAI_API_KEY=sk-xHERMES_SAFE_MODE=1\n"), refusal: "sets HERMES_SAFE_MODE"},
		"env nul padded":         {file: ".env", data: []byte("HERMES_\x00MANAGED_DIR=/tmp/x\n"), refusal: "sets HERMES_MANAGED_DIR"},
		"env utf-16":             {file: ".env", data: utf16LE("HERMES_MANAGED_DIR=/tmp/x\n"), refusal: "sets HERMES_MANAGED_DIR"},
		"op env":                 {file: ".op.env", data: []byte("HERMES_MANAGED_DIR=/tmp/x\n"), refusal: ".op.env sets HERMES_MANAGED_DIR"},
		"profile env":            {file: "profiles/work/.env", data: []byte("HERMES_SAFE_MODE=1\n"), refusal: "profiles/work/.env sets HERMES_SAFE_MODE"},
		"env directory":          {file: ".env", dir: true, refusal: ".env is not a readable regular file"},
		"api keys":               {file: ".env", data: []byte("OPENAI_API_KEY=sk-x\nHERMES_MAX_ITERATIONS=40\nHELLO_WORLD_SIZE=3\n")},
		"exported loader path":   {file: ".env", data: []byte("export LD_PRELOAD=/tmp/x.so\n"), refusal: "sets LD_PRELOAD"},
		"quoted python key":      {file: ".env", data: []byte("'PYTHONSTARTUP'=/tmp/x.py\n"), refusal: "sets PYTHONSTARTUP"},
		"model provider plugin":  {file: "plugins/model-providers/planted/__init__.py", data: []byte("x = 1\n"), refusal: "plugins/model-providers/planted/__init__.py is a Hermes plugin"},
		"memory provider plugin": {file: "plugins/planted/__init__.py", data: []byte("class MemoryProvider: pass\n"), refusal: "is a Hermes plugin"},
		"profile plugin":         {file: "profiles/work/plugins/model-providers/p/__init__.py", data: []byte("x = 1\n"), refusal: "is a Hermes plugin"},
		"plugin state":           {file: "plugins/hermes-achievements/state.json", data: []byte("{}\n")},
		"secret sources":         {file: "config.yaml", data: []byte("secrets: {onepassword: {map: {HERMES_MANAGED_DIR: op://v/i/f}}}\n"), refusal: "config.yaml has a secrets section"},
		"profile secret sources": {file: "profiles/work/config.yaml", data: []byte("secrets: {onepassword: {}}\n"), refusal: "has a secrets section"},
		"redaction setting":      {file: "config.yaml", data: []byte("security:\n  redact_secrets: true\n")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			stubs := t.TempDir()
			l := newHookOnlyLauncherWith(t, Hermes, map[string]string{
				shellQuote(hermesTool.interpreter()): writeExecutable(t, filepath.Join(stubs, "python"), yamlCheckStub),
			})
			home := t.TempDir()
			target := filepath.Join(home, ".hermes", filepath.FromSlash(tc.file))
			if tc.dir {
				writeFile(t, filepath.Join(target, "x"), []byte("x\n"))
			} else {
				writeFile(t, target, tc.data)
			}
			got := l.run(t, home, []string{"HOME=" + home}, "chat", "-q", "hi")
			if tc.refusal == "" {
				if got.exit != 0 || got.record == "" {
					t.Fatalf("refused: exit %d %s", got.exit, got.output)
				}
				return
			}
			if got.exit != 2 || got.record != "" || !strings.Contains(got.output, "refusing to start Hermes: ") || !strings.Contains(got.output, tc.refusal) {
				t.Fatalf("exit %d record %q output %q, want a refusal saying %q", got.exit, got.record, got.output, tc.refusal)
			}
		})
	}
	// A plugin reached through a symbolic link is still found.
	t.Run("linked plugin", func(t *testing.T) {
		l := newHookOnlyLauncher(t, Hermes)
		home, elsewhere := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(elsewhere, "p", "__init__.py"), []byte("x = 1\n"))
		if err := os.MkdirAll(filepath.Join(home, ".hermes", "plugins"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(home, ".hermes", "plugins", "model-providers")); err != nil {
			t.Fatal(err)
		}
		if got := l.run(t, home, []string{"HOME=" + home}); got.exit != 2 || got.record != "" {
			t.Fatalf("exit %d record %q output %q", got.exit, got.record, got.output)
		}
	})
}

// TestUserTierLaunchersRefuseNonFileHooks replaces the user hooks file of
// the harnesses that read hooks only from HOME with a directory. `mv -f`
// would move the restored file inside it and exit 0, and the harness would
// start without DefenseClaw's hooks; the launcher must refuse instead.
func TestUserTierLaunchersRefuseNonFileHooks(t *testing.T) {
	if _, err := exec.LookPath("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	for _, tc := range []struct {
		spec *Spec
		rel  string
	}{
		{OpenHands, ".openhands/hooks.json"},
		{Antigravity, ".gemini/config/hooks.json"},
	} {
		t.Run(tc.spec.Name, func(t *testing.T) {
			l := newHookOnlyLauncher(t, tc.spec)
			home, work := t.TempDir(), t.TempDir()
			hooks := filepath.Join(home, filepath.FromSlash(tc.rel))
			writeFile(t, filepath.Join(hooks, "kept"), []byte("x\n"))
			got := l.run(t, work, []string{"HOME=" + home})
			if got.exit != 2 || got.record != "" || !strings.Contains(got.output, hooks+" is not a regular file") {
				t.Fatalf("exit %d record %q output %q", got.exit, got.record, got.output)
			}
			if entries, _ := os.ReadDir(hooks); len(entries) != 1 {
				t.Fatalf("the launcher wrote into the directory: %v", entries)
			}
			// Put back as a file, the hooks are restored and the harness
			// starts.
			if err := os.RemoveAll(hooks); err != nil {
				t.Fatal(err)
			}
			if got := l.run(t, work, []string{"HOME=" + home}); got.exit != 0 || got.record == "" {
				t.Fatalf("after removing the directory: exit %d %s", got.exit, got.output)
			}
			if raw, _ := os.ReadFile(hooks); string(raw) != `{"reviewed":true}`+"\n" {
				t.Fatalf("hooks = %q", raw)
			}
		})
	}
}

func TestHookOnlyBypassArgs(t *testing.T) {
	for _, tc := range []struct {
		name          string
		spec          *Spec
		args          []string
		kept, dropped []string
	}{
		{"hermes yolo prefixes", Hermes,
			[]string{"--y", "--yo", "--yol", "--yolo", "-m", "m"}, []string{"-m", "m"}, []string{"--y", "--yo", "--yol", "--yolo"}},
		{"hermes other options", Hermes,
			[]string{"--yes", "--yolo-extra", "--", "--yolo"}, []string{"--yes", "--yolo-extra", "--", "--yolo"}, nil},
		{"openhands approve prefixes", OpenHands,
			[]string{"--a", "--always", "--always-approve", "--y", "--yolo", "--ll", "--llm-approve", "-t", "x"},
			[]string{"-t", "x"}, []string{"--a", "--always", "--always-approve", "--y", "--yolo", "--ll", "--llm-approve"}},
		{"openhands ambiguous", OpenHands, []string{"--l", "--headless"}, []string{"--l", "--headless"}, nil},
		{"agy go flags", Antigravity,
			[]string{"--dangerously-skip-permissions", "-dangerously-skip-permissions", "--dangerously-skip-permissions=true", "-dangerously-skip-permissions=1", "-p", "x"},
			[]string{"-p", "x"}, []string{"--dangerously-skip-permissions", "-dangerously-skip-permissions", "--dangerously-skip-permissions=true", "-dangerously-skip-permissions=1"}},
		{"agy false and bogus values", Antigravity,
			[]string{"--dangerously-skip-permissions=false", "--dangerously-skip-permissions=yes", "--dangerously-skip"},
			[]string{"--dangerously-skip-permissions=false", "--dangerously-skip-permissions=yes", "--dangerously-skip"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kept, dropped := tc.spec.BypassArgs(tc.args)
			if !reflect.DeepEqual(kept, tc.kept) || !reflect.DeepEqual(dropped, tc.dropped) {
				t.Fatalf("kept %q dropped %q, want %q / %q", kept, dropped, tc.kept, tc.dropped)
			}
		})
	}
}

// TestOmniGentLaunchArgvModel: the sandbox agent names no model, so a
// credential profile either brings its default or the caller passes one.
func TestOmniGentLaunchArgvModel(t *testing.T) {
	got, err := OmniGent.LaunchArgv(LaunchOptions{Mode: Headless, Prompt: "p", CredentialProfile: profiles.BedrockMantleOpenAIID})
	if err != nil || !reflect.DeepEqual(got, []string{OmniGentLauncherPath, "run", "-p", "p", "--model", omnigentMantleModel}) {
		t.Fatalf("mantle argv = %q, %v", got, err)
	}
	got, err = OmniGent.LaunchArgv(LaunchOptions{Mode: Interactive, CredentialProfile: profiles.BedrockMantleOpenAIID, Args: []string{"--model=openai.gpt-oss-120b"}})
	if err != nil || !reflect.DeepEqual(got, []string{OmniGentLauncherPath, "run", "--model=openai.gpt-oss-120b"}) {
		t.Fatalf("mantle argv with a model = %q, %v", got, err)
	}
	if _, err := OmniGent.LaunchArgv(LaunchOptions{Mode: Interactive, CredentialProfile: profiles.OpenAIID}); err == nil || !strings.Contains(err.Error(), "--model") {
		t.Fatalf("openai without a model: %v", err)
	}
	if got, err := OmniGent.LaunchArgv(LaunchOptions{Mode: Interactive, CredentialProfile: profiles.OpenAIID, Args: []string{"--model", "gpt-5-mini"}}); err != nil || got[len(got)-1] != "gpt-5-mini" {
		t.Fatalf("openai with a model = %q, %v", got, err)
	}
	env, err := OmniGent.Env(EnvOptions{Artifacts: artifactsFor(t, OmniGent), CredentialProfile: profiles.BedrockMantleOpenAIID, BedrockRegion: "eu-west-1"})
	if err != nil || env["OPENAI_BASE_URL"] != "https://bedrock-mantle.eu-west-1.api.aws/v1" {
		t.Fatalf("mantle env = %v, %v", env, err)
	}
}

func TestOmniGentLauncherKeepsTheLocalServer(t *testing.T) {
	stubs := t.TempDir()
	l := newHookOnlyLauncherWith(t, OmniGent, map[string]string{
		shellQuote(omnigentTool.interpreter()): writeExecutable(t, filepath.Join(stubs, "python"), yamlCheckStub),
	})
	home, project := t.TempDir(), t.TempDir()
	for _, args := range [][]string{{"run", "--server", "http://127.0.0.1:7000"}, {"run", "--server=https://x.example"}, {"host", "--server", "http://h"}} {
		if got := l.run(t, project, []string{"HOME=" + home}, args...); got.exit != 2 || got.record != "" || !strings.Contains(got.output, "names another server") {
			t.Errorf("%q: exit %d record %q output %q", args, got.exit, got.record, got.output)
		}
	}
	for _, args := range [][]string{{"run", "--server", "local"}, {"run", "--server="}} {
		if got := l.run(t, project, []string{"HOME=" + home}, args...); got.exit != 0 || got.record == "" {
			t.Errorf("%q refused: %s", args, got.output)
		}
	}
	cfg := filepath.Join(project, ".omnigent", "config.yaml")
	writeFile(t, cfg, []byte("server: http://127.0.0.1:7000\n"))
	if got := l.run(t, project, []string{"HOME=" + home}, "run"); got.exit != 2 || got.record != "" || !strings.Contains(got.output, cfg+" sets server") {
		t.Fatalf("project server: exit %d record %q output %q", got.exit, got.record, got.output)
	}
	writeFile(t, cfg, []byte("server: local\nmodel: m\n"))
	if got := l.run(t, project, []string{"HOME=" + home}, "run"); got.exit != 0 || got.record == "" {
		t.Fatalf("project config with a local server refused: %s", got.output)
	}
}

// yamlInterpreter returns a system Python with PyYAML to stand in for a
// harness's pinned interpreter, so the launchers' YAML checks run for real.
func yamlInterpreter(t *testing.T) string {
	t.Helper()
	const py = "/usr/bin/python3"
	if err := exec.Command(py, "-I", "-c", "import yaml").Run(); err != nil {
		t.Skipf("%s with PyYAML is required: %v", py, err)
	}
	return py
}

// yamlKeyCases are YAML documents for the key key, as the harnesses' loaders
// read them: the key spelled plainly, with an escape in a double-quoted key
// and folded across lines in an explicit one (every one decodes to key), a
// document the loaders cannot parse, one that is not UTF-8, and documents
// that must start (value is what the key carries in the refused ones).
func yamlKeyCases(key, value string) map[string]struct {
	data    string
	refusal string
} {
	escaped := `"\x` + fmt.Sprintf("%02x", key[0]) + key[1:] + `"`
	half := len(key) / 2
	folded := "? \"" + key[:half] + "\\\n  " + key[half:] + "\"\n: " + value + "\n"
	return map[string]struct {
		data    string
		refusal string
	}{
		"plain key":     {data: key + ": " + value + "\n", refusal: "set"},
		"escaped key":   {data: escaped + ": " + value + "\n", refusal: "set"},
		"folded key":    {data: folded, refusal: "set"},
		"not yaml":      {data: key + ": [\n", refusal: "not a YAML file"},
		"not utf-8":     {data: "model: \xff\xfe\n", refusal: "not a YAML file"},
		"other keys":    {data: "model: m\n"},
		"comments only": {data: "# " + key + ": " + value + "\n"},
		"empty":         {data: ""},
	}
}

// TestOmniGentLauncherReadsTheProjectServerAsOmniGentDoes runs the project
// config check with a real YAML loader: a server key the loader decodes from
// escapes or folded lines must be refused like a plain one, and a file it
// cannot parse must be refused rather than let through unchecked.
func TestOmniGentLauncherReadsTheProjectServerAsOmniGentDoes(t *testing.T) {
	py := yamlInterpreter(t)
	l := newHookOnlyLauncherWith(t, OmniGent, map[string]string{shellQuote(omnigentTool.interpreter()): py})
	for name, tc := range yamlKeyCases("server", "http://127.0.0.1:7000") {
		t.Run(name, func(t *testing.T) {
			home, project := t.TempDir(), t.TempDir()
			cfg := filepath.Join(project, ".omnigent", "config.yaml")
			writeFile(t, cfg, []byte(tc.data))
			got := l.run(t, project, []string{"HOME=" + home}, "run")
			if tc.refusal == "" {
				if got.exit != 0 || got.record == "" {
					t.Fatalf("refused: exit %d %s", got.exit, got.output)
				}
				return
			}
			want := cfg + " sets server"
			if tc.refusal != "set" {
				want = cfg + " is " + tc.refusal
			}
			if got.exit != 2 || got.record != "" || !strings.Contains(got.output, want) {
				t.Fatalf("exit %d record %q output %q, want a refusal saying %q", got.exit, got.record, got.output, want)
			}
		})
	}
	t.Run("local server", func(t *testing.T) {
		home, project := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(project, ".omnigent", "config.yaml"), []byte(`"\x73erver": local`+"\n"))
		if got := l.run(t, project, []string{"HOME=" + home}, "run"); got.exit != 0 || got.record == "" {
			t.Fatalf("refused: exit %d %s", got.exit, got.output)
		}
	})
}

// TestHermesLauncherReadsSecretsAsHermesDoes runs the secrets check with a
// real YAML loader, in the Hermes home and in a profile.
func TestHermesLauncherReadsSecretsAsHermesDoes(t *testing.T) {
	py := yamlInterpreter(t)
	l := newHookOnlyLauncherWith(t, Hermes, map[string]string{shellQuote(hermesTool.interpreter()): py})
	for name, tc := range yamlKeyCases("secrets", "{onepassword: {map: {HERMES_MANAGED_DIR: op://v/i/f}}}") {
		for _, rel := range []string{"config.yaml", "profiles/work/config.yaml"} {
			t.Run(name+" "+rel, func(t *testing.T) {
				home := t.TempDir()
				cfg := filepath.Join(home, ".hermes", filepath.FromSlash(rel))
				writeFile(t, cfg, []byte(tc.data))
				got := l.run(t, home, []string{"HOME=" + home}, "chat", "-q", "hi")
				if tc.refusal == "" {
					if got.exit != 0 || got.record == "" {
						t.Fatalf("refused: exit %d %s", got.exit, got.output)
					}
					return
				}
				want := cfg + " has a secrets section"
				if tc.refusal != "set" {
					want = cfg + " is " + tc.refusal
				}
				if got.exit != 2 || got.record != "" || !strings.Contains(got.output, "refusing to start Hermes: "+want) {
					t.Fatalf("exit %d record %q output %q, want a refusal saying %q", got.exit, got.record, got.output, want)
				}
			})
		}
	}
	t.Run("empty secrets section", func(t *testing.T) {
		home := t.TempDir()
		writeFile(t, filepath.Join(home, ".hermes", "config.yaml"), []byte(`"\x73ecrets": {}`+"\n"))
		if got := l.run(t, home, []string{"HOME=" + home}, "chat", "-q", "hi"); got.exit != 0 || got.record == "" {
			t.Fatalf("refused: exit %d %s", got.exit, got.output)
		}
	})
}

// TestOmniGentLauncherReusesOnlyItsOwnServer records processes the way
// OmniGent does in ~/.omnigent and requires the launcher to stop, and stop
// reusing, every one that is not the pinned OmniGent started with the
// DefenseClaw configuration, and to leave its own alone.
func TestOmniGentLauncherReusesOnlyItsOwnServer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the guard reads /proc")
	}
	bash, err := filepath.EvalSymlinks("/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	// The pinned interpreter is bash here: an "OmniGent" process is bash
	// running a script named omnigent.cli, so its argv reads
	// [bash -m omnigent.cli server ...].
	stubs := t.TempDir()
	py := filepath.Join(stubs, "python")
	if err := os.Symlink(bash, py); err != nil {
		t.Fatal(err)
	}
	l := newHookOnlyLauncherWith(t, OmniGent, map[string]string{shellQuote(omnigentTool.interpreter()): py})
	scripts := t.TempDir()
	writeExecutable(t, filepath.Join(scripts, "omnigent.cli"), "sleep 30\n")
	start := func(env []string, args ...string) int {
		t.Helper()
		cmd := exec.Command(bash, append([]string{"-m", "omnigent.cli"}, args...)...)
		cmd.Dir = scripts
		cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, env...)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
		// Wait for bash to have read its environment and argv.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if raw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", cmd.Process.Pid)); strings.Contains(string(raw), "omnigent.cli") {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		return cmd.Process.Pid
	}
	ours := []string{"OMNIGENT_CONFIG_HOME=" + connector.OmnigentSandboxConfigHome}
	for _, tc := range []struct {
		name string
		env  []string
		args []string
		// pidfile records the process as the local server on a port it
		// does not listen on; otherwise it is recorded as a host daemon.
		pidfile bool
		// portHeld makes the test listen on that port itself.
		portHeld bool
		foreign  bool
	}{
		{name: "own daemon", env: ours, args: []string{"server"}},
		{name: "no configuration home", args: []string{"server"}, foreign: true},
		{name: "other configuration home", env: []string{"OMNIGENT_CONFIG_HOME=/tmp/elsewhere"}, args: []string{"server"}, foreign: true},
		{name: "python path", env: append([]string{"PYTHONPATH=/tmp/x"}, ours...), args: []string{"server"}, foreign: true},
		{name: "other config file", env: ours, args: []string{"server", "--config", "/tmp/x.yaml"}, foreign: true},
		{name: "own config file", env: ours, args: []string{"server", "--config", connector.OmnigentSandboxConfigPath}},
		// Nothing listens on the recorded port yet: a server still starting,
		// which OmniGent does not reuse before it answers /health.
		{name: "server still starting", env: ours, args: []string{"server"}, pidfile: true},
		// Another process holds the recorded port.
		{name: "server port held by another process", env: ours, args: []string{"server"}, pidfile: true, portHeld: true, foreign: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			pid := start(tc.env, tc.args...)
			record := filepath.Join(home, ".omnigent", "daemons", "local.json")
			if tc.pidfile {
				port := 1
				if tc.portHeld {
					l, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer l.Close()
					port = l.Addr().(*net.TCPAddr).Port
				}
				record = filepath.Join(home, ".omnigent", "local_server.pid")
				writeFile(t, record, []byte(strconv.Itoa(pid)+"\n"+strconv.Itoa(port)+"\n"))
			} else {
				raw, _ := json.Marshal(map[string]interface{}{"pid": pid, "target": "local", "mode": "local"})
				writeFile(t, record, raw)
			}
			got := l.run(t, home, []string{"HOME=" + home}, "run", "-p", "hi")
			if got.exit != 0 {
				t.Fatalf("exit %d: %s", got.exit, got.output)
			}
			stopped := strings.Contains(got.record, "ARG stop\nARG --force\n")
			_, statErr := os.Stat(record)
			if tc.foreign {
				if !stopped || !os.IsNotExist(statErr) || !strings.Contains(got.output, "not started with DefenseClaw's configuration") {
					t.Fatalf("foreign process kept: stopped %t record %v\n%s%s", stopped, statErr, got.record, got.output)
				}
			} else if stopped || statErr != nil {
				t.Fatalf("own process stopped %t, record %v:\n%s", stopped, statErr, got.record)
			}
			if !strings.Contains(got.record, "ARG run\nARG -p\nARG hi\n") {
				t.Fatalf("OmniGent never started:\n%s", got.record)
			}
		})
	}
}
