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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The launchers of the hook-only harnesses (Hermes, OpenHands, Antigravity
// and OmniGent) and what they refuse to start with.

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

// yamlCheckStub stands in for a harness interpreter's `-I -c <script> FILE`
// YAML check: it exits 3 for a file with a non-empty secrets or a non-local
// server key on one line, as the real check does for the parsed document.
const yamlCheckStub = "#!/bin/sh\n/usr/bin/grep -qE '^secrets: *[^ ]|^server: *[^ l]' \"$4\" && exit 3\nexit 0\n"

// newYAMLCheckedLauncher is newLauncher with the Hermes or OmniGent
// launcher's pinned interpreter, which runs its YAML checks, replaced by py
// (yamlCheckStub when empty). Other launchers are left as they are.
func newYAMLCheckedLauncher(t *testing.T, spec *Spec, py string) testLauncher {
	t.Helper()
	var interpreter string
	switch spec {
	case Hermes:
		interpreter = hermesTool.interpreter()
	case OmniGent:
		interpreter = omnigentTool.interpreter()
	default:
		return newLauncher(t, spec)
	}
	if py == "" {
		py = writeExecutable(t, filepath.Join(t.TempDir(), "python"), yamlCheckStub)
	}
	return newLauncher(t, spec, shellQuote(interpreter), py)
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
// that must start (value is what the key carries in the refused ones, and a
// local or empty value in an escaped key starts too).
func yamlKeyCases(key, value, allowed string) map[string]struct{ data, refusal string } {
	escaped := `"\x` + fmt.Sprintf("%02x", key[0]) + key[1:] + `"`
	half := len(key) / 2
	return map[string]struct{ data, refusal string }{
		"plain key":     {key + ": " + value + "\n", "set"},
		"escaped key":   {escaped + ": " + value + "\n", "set"},
		"folded key":    {"? \"" + key[:half] + "\\\n  " + key[half:] + "\"\n: " + value + "\n", "set"},
		"not yaml":      {key + ": [\n", "not a YAML file"},
		"not utf-8":     {"model: \xff\xfe\n", "not a YAML file"},
		"other keys":    {"model: m\n", ""},
		"comments only": {"# " + key + ": " + value + "\n", ""},
		"empty":         {"", ""},
		"allowed value": {escaped + ": " + allowed + "\n", ""},
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
	cases := map[string]struct {
		file string // relative to the Hermes home; a trailing / plants a directory
		data []byte
		// refusal is what the launcher must say; empty: it must start.
		refusal string
	}{
		"env safe mode":          {".env", []byte("HERMES_SAFE_MODE=1\n"), ".env sets HERMES_SAFE_MODE"},
		"env managed dir":        {".env", []byte("export HERMES_MANAGED_DIR=/tmp/x\n"), "sets HERMES_MANAGED_DIR"},
		"env home":               {".env", []byte("HERMES_HOME=/tmp/x\n"), "sets HERMES_HOME"},
		"env project plugins":    {".env", []byte("HERMES_ENABLE_PROJECT_PLUGINS=true\n"), "sets HERMES_ENABLE_PROJECT_PLUGINS"},
		"env python path":        {".env", []byte("PYTHONPATH=/tmp/x\n"), "sets PYTHONPATH"},
		"env glued pair":         {".env", []byte("OPENAI_API_KEY=sk-xHERMES_SAFE_MODE=1\n"), "sets HERMES_SAFE_MODE"},
		"env nul padded":         {".env", []byte("HERMES_\x00MANAGED_DIR=/tmp/x\n"), "sets HERMES_MANAGED_DIR"},
		"env utf-16":             {".env", utf16LE("HERMES_MANAGED_DIR=/tmp/x\n"), "sets HERMES_MANAGED_DIR"},
		"op env":                 {".op.env", []byte("HERMES_MANAGED_DIR=/tmp/x\n"), ".op.env sets HERMES_MANAGED_DIR"},
		"profile env":            {"profiles/work/.env", []byte("HERMES_SAFE_MODE=1\n"), "profiles/work/.env sets HERMES_SAFE_MODE"},
		"env directory":          {".env/", nil, ".env is not a readable regular file"},
		"api keys":               {".env", []byte("OPENAI_API_KEY=sk-x\nHERMES_MAX_ITERATIONS=40\nHELLO_WORLD_SIZE=3\n"), ""},
		"exported loader path":   {".env", []byte("export LD_PRELOAD=/tmp/x.so\n"), "sets LD_PRELOAD"},
		"quoted python key":      {".env", []byte("'PYTHONSTARTUP'=/tmp/x.py\n"), "sets PYTHONSTARTUP"},
		"model provider plugin":  {"plugins/model-providers/planted/__init__.py", []byte("x = 1\n"), "plugins/model-providers/planted/__init__.py is a Hermes plugin"},
		"memory provider plugin": {"plugins/planted/__init__.py", []byte("class MemoryProvider: pass\n"), "is a Hermes plugin"},
		"profile plugin":         {"profiles/work/plugins/model-providers/p/__init__.py", []byte("x = 1\n"), "is a Hermes plugin"},
		"plugin state":           {"plugins/hermes-achievements/state.json", []byte("{}\n"), ""},
		"secret sources":         {"config.yaml", []byte("secrets: {onepassword: {map: {HERMES_MANAGED_DIR: op://v/i/f}}}\n"), "config.yaml has a secrets section"},
		"profile secret sources": {"profiles/work/config.yaml", []byte("secrets: {onepassword: {}}\n"), "has a secrets section"},
		"redaction setting":      {"config.yaml", []byte("security:\n  redact_secrets: true\n"), ""},
		// A plugin reached through a symbolic link is still found.
		"linked plugin": {"plugins/model-providers", nil, "is a Hermes plugin"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			l := newYAMLCheckedLauncher(t, Hermes, "")
			target := filepath.Join(l.dir, ".hermes", filepath.FromSlash(tc.file))
			switch {
			case name == "linked plugin":
				elsewhere := t.TempDir()
				writeFile(t, filepath.Join(elsewhere, "p", "__init__.py"), []byte("x = 1\n"))
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(elsewhere, target); err != nil {
					t.Fatal(err)
				}
			case strings.HasSuffix(tc.file, "/"):
				writeFile(t, filepath.Join(target, "x"), []byte("x\n"))
			default:
				writeFile(t, target, tc.data)
			}
			r := l.run(t, "", nil, "chat", "-q", "hi")
			if tc.refusal == "" {
				if r.exit != 0 || !r.started() {
					t.Fatalf("refused: exit %d %s", r.exit, r.output)
				}
			} else if r.exit != 2 || r.started() || !strings.Contains(r.output, "refusing to start Hermes: ") || !strings.Contains(r.output, tc.refusal) {
				t.Fatalf("exit %d started %t output %q, want a refusal saying %q", r.exit, r.started(), r.output, tc.refusal)
			}
		})
	}
}

// TestYAMLChecksReadKeysAsTheHarnessesDo runs the OmniGent project server
// check and the Hermes secrets check (in the home and in a profile) with a
// real YAML loader: a key the loader decodes from escapes or folded lines
// must be refused like a plain one, and a file it cannot parse must be
// refused rather than let through unchecked.
func TestYAMLChecksReadKeysAsTheHarnessesDo(t *testing.T) {
	py := yamlInterpreter(t)
	for _, tc := range []struct {
		spec             *Spec
		rel, key, value  string
		allowed          string
		setRefusal, lead string
		cwdIsProject     bool
	}{
		{spec: OmniGent, rel: ".omnigent/config.yaml", key: "server", value: "http://127.0.0.1:7000", allowed: "local",
			setRefusal: " sets server", cwdIsProject: true},
		{spec: Hermes, rel: ".hermes/config.yaml", key: "secrets", value: "{onepassword: {map: {HERMES_MANAGED_DIR: op://v/i/f}}}", allowed: "{}",
			setRefusal: " has a secrets section", lead: "refusing to start Hermes: "},
		{spec: Hermes, rel: ".hermes/profiles/work/config.yaml", key: "secrets", value: "{onepassword: {}}", allowed: "{}",
			setRefusal: " has a secrets section", lead: "refusing to start Hermes: "},
	} {
		for name, c := range yamlKeyCases(tc.key, tc.value, tc.allowed) {
			t.Run(tc.spec.Name+" "+tc.rel+" "+name, func(t *testing.T) {
				l := newYAMLCheckedLauncher(t, tc.spec, py)
				root := l.dir
				if tc.cwdIsProject {
					root = t.TempDir()
				}
				cfg := filepath.Join(root, filepath.FromSlash(tc.rel))
				writeFile(t, cfg, []byte(c.data))
				r := l.run(t, root, nil, "run")
				if c.refusal == "" {
					if r.exit != 0 || !r.started() {
						t.Fatalf("refused: exit %d %s", r.exit, r.output)
					}
					return
				}
				want := tc.lead + cfg + tc.setRefusal
				if c.refusal != "set" {
					want = tc.lead + cfg + " is " + c.refusal
				}
				if r.exit != 2 || r.started() || !strings.Contains(r.output, want) {
					t.Fatalf("exit %d output %q, want a refusal saying %q", r.exit, r.output, want)
				}
			})
		}
	}
}

// TestOmniGentLauncherKeepsTheProjectOnTheLocalServer: a server key in the
// project's .omnigent/config.yaml would run the session on a server the
// image does not configure.
func TestOmniGentLauncherKeepsTheProjectOnTheLocalServer(t *testing.T) {
	l := newYAMLCheckedLauncher(t, OmniGent, "")
	project := t.TempDir()
	cfg := filepath.Join(project, ".omnigent", "config.yaml")
	writeFile(t, cfg, []byte("server: http://127.0.0.1:7000\n"))
	if r := l.run(t, project, nil, "run"); r.exit != 2 || r.started() || !strings.Contains(r.output, cfg+" sets server") {
		t.Fatalf("project server: exit %d output %q", r.exit, r.output)
	}
	writeFile(t, cfg, []byte("server: local\nmodel: m\n"))
	if r := l.run(t, project, nil, "run"); r.exit != 0 || !r.started() {
		t.Fatalf("project config with a local server refused: %s", r.output)
	}
}

// TestOpenHandsLauncher: the user hooks are restored from the canonical copy
// at every start, and a project hooks file (also one OPENHANDS_WORK_DIR
// points at), a symlinked ~/.openhands or a missing canonical copy stop the
// launcher.
func TestOpenHandsLauncher(t *testing.T) {
	l := newLauncher(t, OpenHands)
	project := t.TempDir()
	hooks := filepath.Join(l.dir, ".openhands", "hooks.json")
	writeFile(t, hooks, []byte(`{}`))
	canonical := filepath.Join(l.dir, filepath.FromSlash(connector.OpenHandsSandboxCanonicalHooksPath))
	want, _ := os.ReadFile(canonical)
	if r := l.run(t, project, nil, "--headless", "-t", "p"); r.exit != 0 || !r.started() {
		t.Fatalf("exit %d: %s", r.exit, r.output)
	}
	if raw, _ := os.ReadFile(hooks); len(want) == 0 || string(raw) != string(want) {
		t.Fatalf("user hooks not restored: %q", raw)
	}
	writeFile(t, filepath.Join(project, ".openhands", "hooks.json"), []byte(`{}`))
	if r := l.run(t, project, nil); r.exit != 2 || r.started() || !strings.Contains(r.output, "would replace DefenseClaw's hooks") {
		t.Fatalf("project hooks: exit %d output %q", r.exit, r.output)
	}
	elsewhere := t.TempDir()
	if r := l.run(t, elsewhere, []string{"OPENHANDS_WORK_DIR=" + project}); r.exit != 2 || r.started() {
		t.Fatalf("OPENHANDS_WORK_DIR project hooks: exit %d", r.exit)
	}
	// A symlinked hooks directory is refused rather than written through.
	linked := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(linked, ".openhands")); err != nil {
		t.Fatal(err)
	}
	if r := l.run(t, elsewhere, []string{"HOME=" + linked}); r.exit != 2 || r.started() {
		t.Fatalf("symlinked ~/.openhands: exit %d", r.exit)
	}
	if err := os.Remove(canonical); err != nil {
		t.Fatal(err)
	}
	if r := l.run(t, elsewhere, nil); r.exit != 2 || r.started() {
		t.Fatalf("no canonical hooks: exit %d", r.exit)
	}
}

// TestAntigravityLauncher: the user hooks are restored, and the Gemini key
// selects agy's gemini model provider in settings the launcher otherwise
// leaves alone.
func TestAntigravityLauncher(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	l := newLauncher(t, Antigravity)
	workspace := t.TempDir()
	settings := filepath.Join(l.dir, ".gemini", "antigravity-cli", "settings.json")
	writeFile(t, settings, []byte(`{"theme":"dark"}`))
	r := l.run(t, workspace, []string{"GEMINI_API_KEY=openshell:resolve:env:v6_GEMINI_API_KEY"}, "-p", "hi")
	if r.exit != 0 || !slices.Equal(r.last().args, []string{"-p", "hi"}) {
		t.Fatalf("exit %d argv %q: %s", r.exit, r.last().args, r.output)
	}
	want, _ := os.ReadFile(filepath.Join(l.dir, filepath.FromSlash(connector.AntigravitySandboxCanonicalHooksPath)))
	if raw, _ := os.ReadFile(filepath.Join(l.dir, ".gemini", "config", "hooks.json")); len(want) == 0 || string(raw) != string(want) {
		t.Fatalf("user hooks not restored: %q", raw)
	}
	var cfg map[string]interface{}
	raw, _ := os.ReadFile(settings)
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg["modelProvider"] != "gemini" || cfg["theme"] != "dark" {
		t.Fatalf("settings = %s", raw)
	}
	writeFile(t, settings, []byte(`{"theme":"dark"}`))
	if r := l.run(t, workspace, nil); r.exit != 0 {
		t.Fatalf("exit %d", r.exit)
	}
	if raw, _ := os.ReadFile(settings); string(raw) != `{"theme":"dark"}` {
		t.Fatalf("settings rewritten without a key: %s", raw)
	}
}

// jsonEscape spells s with a JSON \u escape for every character.
func jsonEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, "%cu%04x", 0x5c, r)
	}
	return b.String()
}

// TestAntigravityLauncherRefusesReusedHookKeys plants hooks files agy reads
// besides the restored global one, each reusing a DefenseClaw hook key the
// way agy's JSON reader decodes it (literally, with \u escapes, in another
// letter case, in a file with comments), in the working directory, in
// --add-dir directories and in plugins. Each must stop the launcher, while
// hooks files with keys of their own (JSON escapes in their commands
// included) still start agy.
func TestAntigravityLauncherRefusesReusedHookKeys(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	prefix := connector.AntigravitySandboxHookKeyPrefix
	key := prefix + "pretooluse"
	escaped := jsonEscape(prefix[:1]) + key[1:]
	doc := func(k string) string { return `{"` + k + `":{"PreToolUse":[]}}` }
	for name, tc := range map[string]struct {
		rel     string // under the workspace (w/), the --add-dir directory (a/) or HOME (h/)
		data    string
		args    []string
		refused bool
	}{
		"literal key":            {"w/.agents/hooks.json", doc(key), nil, true},
		"escaped key":            {"w/.agents/hooks.json", doc(escaped), nil, true},
		"fully escaped key":      {"w/.agents/hooks.json", doc(jsonEscape(key)), nil, true},
		"upper-case key":         {"w/.agents/hooks.json", doc(strings.ToUpper(key)), nil, true},
		"second document":        {"w/.agents/hooks.json", doc("lint") + "\n" + doc(escaped), nil, true},
		"commented literal key":  {"w/.agents/hooks.json", "{\n  // mine\n  \"" + key + "\": {\"PreToolUse\": []},\n}\n", nil, true},
		"commented escape":       {"w/.agents/hooks.json", "{\n  // mine\n  \"" + escaped + "\": {\"PreToolUse\": []},\n}\n", nil, true},
		"add-dir":                {"a/.agents/hooks.json", doc(escaped), []string{"--add-dir", "{a}"}, true},
		"add-dir inline":         {"a/.agents/hooks.json", doc(key), []string{"--add-dir={a}"}, true},
		"add-dir single dash":    {"a/.agents/hooks.json", doc(key), []string{"-add-dir", "{a}"}, true},
		"workspace plugin":       {"w/.agents/plugins/p/hooks.json", doc(escaped), nil, true},
		"add-dir plugin":         {"a/.agents/plugins/p/hooks/hooks.json", doc(key), []string{"--add-dir", "{a}"}, true},
		"user plugin":            {"h/.gemini/config/plugins/.p/hooks/hooks.json", doc(escaped), nil, true},
		"cli hooks":              {"h/.gemini/antigravity-cli/hooks.json", doc(key), nil, true},
		"own key":                {"w/.agents/hooks.json", `{"lint":{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"make lint ` + jsonEscape("&&") + ` true"}]}]}}`, nil, false},
		"commented own key":      {"w/.agents/hooks.json", "{\n  // mine\n  \"lint\": {\"PostToolUse\": []},\n}\n", nil, false},
		"add-dir without hooks":  {"a/README", "x", []string{"--add-dir", "{a}"}, false},
		"add-dir plugin own key": {"a/.agents/plugins/p/hooks.json", doc("lint"), []string{"--add-dir", "{a}"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			l := newLauncher(t, Antigravity)
			roots := map[string]string{"w": t.TempDir(), "a": t.TempDir(), "h": t.TempDir()}
			for k, dir := range roots {
				resolved, err := filepath.EvalSymlinks(dir)
				if err != nil {
					t.Fatal(err)
				}
				roots[k] = resolved
			}
			root, rel, _ := strings.Cut(tc.rel, "/")
			file := filepath.Join(roots[root], filepath.FromSlash(rel))
			writeFile(t, file, []byte(tc.data))
			args := []string{"-p", "hi"}
			for _, a := range tc.args {
				args = append(args, strings.ReplaceAll(a, "{a}", roots["a"]))
			}
			r := l.run(t, roots["w"], []string{"HOME=" + roots["h"]}, args...)
			if !tc.refused {
				if r.exit != 0 || !r.started() {
					t.Fatalf("refused: exit %d %s", r.exit, r.output)
				}
			} else if r.exit != 2 || r.started() || !strings.Contains(r.output, file+" ") || !strings.Contains(r.output, "refusing to start agy") {
				t.Fatalf("exit %d output %q, want a refusal naming %s", r.exit, r.output, file)
			}
		})
	}
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
	py := filepath.Join(t.TempDir(), "python")
	if err := os.Symlink(bash, py); err != nil {
		t.Fatal(err)
	}
	l := newYAMLCheckedLauncher(t, OmniGent, py)
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
		{name: "server port held by another process", env: ours, args: []string{"server"}, pidfile: true, portHeld: true, foreign: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			pid := start(tc.env, tc.args...)
			record := filepath.Join(home, ".omnigent", "daemons", "local.json")
			if tc.pidfile {
				port := 1
				if tc.portHeld {
					ln, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer ln.Close()
					port = ln.Addr().(*net.TCPAddr).Port
				}
				record = filepath.Join(home, ".omnigent", "local_server.pid")
				writeFile(t, record, []byte(strconv.Itoa(pid)+"\n"+strconv.Itoa(port)+"\n"))
			} else {
				raw, _ := json.Marshal(map[string]interface{}{"pid": pid, "target": "local", "mode": "local"})
				writeFile(t, record, raw)
			}
			r := l.run(t, home, []string{"HOME=" + home}, "run", "-p", "hi")
			if r.exit != 0 || !slices.Equal(r.last().args, []string{"run", "-p", "hi"}) {
				t.Fatalf("OmniGent never started: exit %d %+v\n%s", r.exit, r.calls, r.output)
			}
			stopped := len(r.calls) == 2 && slices.Equal(r.calls[0].args, []string{"stop", "--force"})
			_, statErr := os.Stat(record)
			if tc.foreign {
				if !stopped || !os.IsNotExist(statErr) || !strings.Contains(r.output, "not started with DefenseClaw's configuration") {
					t.Fatalf("foreign process kept: stopped %t record %v\n%+v\n%s", stopped, statErr, r.calls, r.output)
				}
			} else if len(r.calls) != 1 || statErr != nil {
				t.Fatalf("own process stopped, record %v:\n%+v", statErr, r.calls)
			}
		})
	}
}
