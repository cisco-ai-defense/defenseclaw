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
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// startLauncher starts launcher in cwd with args and env (PATH and HOME
// default to the system directories and home) and returns its exit code and
// output.
func startLauncher(t *testing.T, launcher, home, cwd string, env []string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(launcher, args...)
	cmd.Dir = cwd
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + home}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("launcher: %v\n%s", err, out)
	}
	return code, string(out)
}

// launcherFixture renders spec's launcher into a fresh directory, which also
// stands in for the image HOME, with the pinned binary replaced by a stub
// script (stubBody after the shebang) and the root-owned files the launcher
// reads (its artifacts and shell files below SandboxLibDir, the supervisor)
// laid out below the directory. It returns the launcher and the directory.
func launcherFixture(t *testing.T, spec *Spec, stubBody string) (string, string) {
	t.Helper()
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	dir := t.TempDir()
	writeExecutable(t, filepath.Join(dir, "stub"), "#!/bin/bash\n"+stubBody)
	script := strings.ReplaceAll(string(spec.Launcher().Data), "/usr/local/bin/"+spec.Command+" ", filepath.Join(dir, "stub")+" ")
	script = strings.ReplaceAll(script, "HOME="+connector.SandboxHomeDir+"\n", "HOME="+dir+"\n")
	script = strings.ReplaceAll(script, `"`+connector.SandboxLibDir+"/", `"`+dir+connector.SandboxLibDir+"/")
	script = strings.ReplaceAll(script, SupervisorPath, filepath.Join(dir, filepath.FromSlash(SupervisorPath)))
	for _, file := range append(artifactsFor(t, spec).Files, spec.ShellFiles()...) {
		if file.Owner != connector.SandboxOwnerRoot || !strings.HasPrefix(file.Path, connector.SandboxLibDir+"/") {
			continue
		}
		writeFile(t, filepath.Join(dir, filepath.FromSlash(file.Path)), file.Data)
		if file.Mode&0o111 != 0 {
			if err := os.Chmod(filepath.Join(dir, filepath.FromSlash(file.Path)), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeExecutable(t, filepath.Join(dir, "launch"), script)
	return filepath.Join(dir, "launch"), dir
}

// rewriteLauncher replaces old with new in a fixture launcher.
func rewriteLauncher(t *testing.T, launcher, old, new string) {
	t.Helper()
	raw, err := os.ReadFile(launcher)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), old) {
		t.Fatalf("the launcher does not run %q", old)
	}
	writeExecutable(t, launcher, strings.ReplaceAll(string(raw), old, new))
}

// recordStub stands in for a harness binary: every start appends a CALL
// line, its argv (ARG lines), its environment (ENV lines) and, for a login,
// its stdin (STDIN) to the record next to it.
const recordStub = `{ echo CALL; for a in "$@"; do printf 'ARG %s\n' "$a"; done; /usr/bin/env | sed 's/^/ENV /'
  if [ "${1:-}" = login ]; then printf 'STDIN %s\n' "$(cat)"; fi; } >>"${0%/*}/record"` + "\n"

// unset marks a variable checkEnv requires to be absent.
const unset = "<unset>"

type launcherCall struct {
	args  []string
	env   map[string]string
	stdin string
}

type launcherRun struct {
	exit   int
	output string
	calls  []launcherCall
}

func (r launcherRun) started() bool { return len(r.calls) > 0 }

// last is the last harness start (no arguments and no environment when there
// was none).
func (r launcherRun) last() launcherCall {
	if len(r.calls) == 0 {
		return launcherCall{env: map[string]string{}}
	}
	return r.calls[len(r.calls)-1]
}

// testLauncher is a launcherFixture whose harness is recordStub.
type testLauncher struct{ path, dir string }

// newLauncher renders spec's launcher with recordStub and applies the
// replacements (old, new pairs) to it.
func newLauncher(t *testing.T, spec *Spec, replace ...string) testLauncher {
	t.Helper()
	path, dir := launcherFixture(t, spec, recordStub)
	for i := 0; i+1 < len(replace); i += 2 {
		rewriteLauncher(t, path, replace[i], replace[i+1])
	}
	return testLauncher{path: path, dir: dir}
}

// run starts the launcher in cwd (the fixture directory when empty) with
// HOME the fixture directory unless env sets another.
func (l testLauncher) run(t *testing.T, cwd string, env []string, args ...string) launcherRun {
	t.Helper()
	record := filepath.Join(l.dir, "record")
	_ = os.Remove(record)
	if cwd == "" {
		cwd = l.dir
	}
	r := launcherRun{}
	r.exit, r.output = startLauncher(t, l.path, l.dir, cwd, env, args...)
	raw, _ := os.ReadFile(record)
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "CALL" {
			r.calls = append(r.calls, launcherCall{env: map[string]string{}})
			continue
		}
		if len(r.calls) == 0 {
			continue
		}
		c := &r.calls[len(r.calls)-1]
		if arg, ok := strings.CutPrefix(line, "ARG "); ok {
			c.args = append(c.args, arg)
		} else if kv, ok := strings.CutPrefix(line, "ENV "); ok {
			name, value, _ := strings.Cut(kv, "=")
			c.env[name] = value
		} else if in, ok := strings.CutPrefix(line, "STDIN "); ok {
			c.stdin = in
		}
	}
	return r
}

// checkEnv reports every variable of want the call did not get with its
// value, or got although want says unset.
func checkEnv(t *testing.T, c launcherCall, want map[string]string) {
	t.Helper()
	for name, value := range want {
		got, ok := c.env[name]
		if value == unset {
			if ok {
				t.Errorf("%s=%q reached the harness", name, got)
			}
		} else if got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

// TestLaunchersScrubTheEnvironment starts every launcher with variables an
// agent could export from a shell start-up file and requires the harness to
// get none of them: shell start-up variables (SHELLOPTS=noexec would even
// stop the stub, a bash script, from recording anything), a Node preload,
// module directory and compile cache the workload owns (Node would run them
// in place of the root-owned sources), the dynamic loader's variables
// naming an inert marker object that does not exist (glibc's loader then
// warns in each program it starts with one, and only the launcher's own bash,
// loaded before its first line runs, may see it), and for the uv-installed
// Python harnesses, whose entry points run Python without -I, the interpreter
// start-up variables. The system directories lead PATH, the DefenseClaw proxy
// replaces the caller's, and without one (a strict profile), or with a
// malformed one, the caller's proxy settings stay as they were.
func TestLaunchersScrubTheEnvironment(t *testing.T) {
	planted := t.TempDir()
	startup := filepath.Join(planted, "startup")
	writeFile(t, startup, []byte("echo sourced-startup-file\n"))
	marker := filepath.Join(planted, "dc-inert-loader-marker.so")
	const caller = "http://already:set@h:1"
	bypass := "api.anthropic.com,host.openshell.internal"
	unsetAll := func(names ...string) map[string]string {
		out := map[string]string{}
		for _, n := range names {
			out[n] = unset
		}
		return out
	}
	vectors := []struct {
		name   string
		env    []string
		want   map[string]string
		python bool
	}{
		{"shell start-up", []string{"BASH_ENV=" + startup, "ENV=" + startup, "BASHOPTS=extglob", "SHELLOPTS=noexec", "CDPATH=/tmp", "GLOBIGNORE=*"},
			unsetAll("BASH_ENV", "ENV", "BASHOPTS", "SHELLOPTS", "CDPATH", "GLOBIGNORE"), false},
		{"node", []string{"NODE_OPTIONS=--require=" + planted + "/preload.js", "NODE_PATH=" + planted, "NODE_COMPILE_CACHE=" + planted, "NODE_DISABLE_COMPILE_CACHE=0"},
			map[string]string{"NODE_OPTIONS": unset, "NODE_PATH": unset, "NODE_DISABLE_COMPILE_CACHE": "1"}, false},
		{"loader", []string{"LD_PRELOAD=" + marker, "LD_AUDIT=" + marker, "LD_LIBRARY_PATH=" + planted, "LD_BIND_NOW=1", "GCONV_PATH=" + planted},
			unsetAll("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_BIND_NOW", "GCONV_PATH"), false},
		{"python", []string{"PYTHONPATH=" + planted, "PYTHONHOME=" + planted, "PYTHONSTARTUP=" + startup, "PYTHONUSERBASE=" + planted,
			"PYTHONPYCACHEPREFIX=" + planted, "PYTHONWARNINGS=ignore::planted.Warning", "PYTHONBREAKPOINT=planted.hook", "PYTHONINSPECT=1", "PYTHONSAFEPATH="},
			nil, true},
		{"egress", []string{"HTTPS_PROXY=http://elsewhere:1", "no_proxy=*", openshell.EnvEgressURL + "=" + testEgressProxy, openshell.EnvEgressBypass + "=" + bypass},
			map[string]string{"HTTPS_PROXY": testEgressProxy, "HTTP_PROXY": testEgressProxy, "https_proxy": testEgressProxy, "http_proxy": testEgressProxy,
				"NODE_USE_ENV_PROXY": "1", "NO_PROXY": bypass, "no_proxy": bypass}, false},
		{"no egress", nil, unsetAll("HTTPS_PROXY", "https_proxy", "NODE_USE_ENV_PROXY", "NO_PROXY"), false},
		{"malformed egress", []string{"HTTPS_PROXY=" + caller, openshell.EnvEgressURL + "=http://x y@host:1"},
			map[string]string{"HTTPS_PROXY": caller, "https_proxy": unset, "NODE_USE_ENV_PROXY": unset}, false},
	}
	pythonHarness := map[string]bool{"hermes": true, "openhands": true, "omnigent": true}
	for _, name := range Names() {
		spec, _ := Get(name)
		l := newLauncher(t, spec)
		for _, v := range vectors {
			if v.python && !pythonHarness[name] {
				continue
			}
			t.Run(name+"/"+v.name, func(t *testing.T) {
				agentBin := t.TempDir()
				r := l.run(t, "", append([]string{"PATH=" + agentBin + ":/usr/bin:/bin"}, v.env...))
				if r.exit != 0 || !r.started() {
					t.Fatalf("the stub never ran: exit %d\n%s", r.exit, r.output)
				}
				want := maps.Clone(v.want)
				switch {
				case v.name == "node" && (name == "codex" || name == "copilot"):
					// Its own fixed NODE_OPTIONS silences the proxy agent's warning.
					want["NODE_OPTIONS"] = "--disable-warning=UNDICI-EHPA"
				case v.name == "egress" && name == "omnigent":
					// OmniGent's processes talk to each other over loopback.
					want["NO_PROXY"] = bypass + ",127.0.0.1,localhost,::1"
					want["no_proxy"] = want["NO_PROXY"]
				}
				c := r.last()
				checkEnv(t, c, want)
				for key := range c.env {
					if v.python && strings.HasPrefix(key, "PYTHON") {
						t.Errorf("%s reached the harness", key)
					}
				}
				if !strings.HasPrefix(c.env["PATH"], LauncherSystemPATH+":"+agentBin+":") {
					t.Errorf("PATH %q does not lead with the system directories", c.env["PATH"])
				}
				if strings.Contains(r.output, "sourced-startup-file") {
					t.Errorf("a start-up file ran:\n%s", r.output)
				}
				if v.name == "loader" && runtime.GOOS == "linux" && strings.Count(r.output, marker) > 2 {
					t.Errorf("programs the launcher started saw the loader marker:\n%s", r.output)
				}
			})
		}
	}
}

// TestLaunchersPinTheirEnvironment pins what each launcher sets, maps and
// drops for its harness: the variables that would move its configuration,
// plugins or code elsewhere, switch its hooks off or update it in place, and
// the credential names it hands on.
func TestLaunchersPinTheirEnvironment(t *testing.T) {
	const omnigentToken = "openshell:resolve:env:v3_DEFENSECLAW_SANDBOX_TOKEN"
	loopback := "host.openshell.internal,127.0.0.1,localhost,::1"
	for _, tc := range []struct {
		name string
		spec *Spec
		env  []string
		args []string
		// want is keyed by variable; a value of the fixture directory is
		// written as "{dir}".
		want map[string]string
	}{
		{"opencode", OpenCode, []string{"OPENCODE_PURE=1", "OPENCODE_TEST_MANAGED_CONFIG_DIR=/tmp/x", "OPENCODE_TEST_HOME=/tmp/y", "OPENCODE_CONFIG_CONTENT={}"},
			[]string{"run", "--auto", "hi"},
			map[string]string{"OPENCODE_PURE": unset, "OPENCODE_TEST_MANAGED_CONFIG_DIR": unset, "OPENCODE_TEST_HOME": unset,
				"OPENCODE_DISABLE_AUTOUPDATE": "1", "OPENCODE_CONFIG_CONTENT": "{}"}},
		{"copilot", Copilot, []string{"COPILOT_AUTO_UPDATE=true", "COPILOT_PKG_CACHE_HOME=/sandbox/.cache", "COPILOT_CLI_DIST_DIR=/tmp/dist",
			"COPILOT_CLI_VERSION=9.9.9", "COPILOT_CACHE_HOME=/tmp/c", "NODE_OPTIONS=--require=/tmp/preload.js"}, []string{"-p", "hi", "--yolo"},
			map[string]string{"COPILOT_AUTO_UPDATE": "false", "COPILOT_PKG_CACHE_HOME": CopilotPackageCache, "COPILOT_CLI_DIST_DIR": unset,
				"COPILOT_CLI_VERSION": unset, "COPILOT_CACHE_HOME": unset, "NODE_OPTIONS": "--disable-warning=UNDICI-EHPA"}},
		{"amp", Amp, []string{"HOME=/tmp/elsewhere", "XDG_CONFIG_HOME=/tmp/x", "AMP_DISABLE_PLUGINS=1", "AMP_PLUGIN_URI=file:///tmp/p.ts",
			"AMP_PLUGIN_SOURCE_BASE64=eA==", "AMP_SETTINGS_FILE=/tmp/s.json"}, []string{"--dangerously-allow-all", "-x", "hi"},
			map[string]string{"HOME": "{dir}", "XDG_CONFIG_HOME": unset, "AMP_DISABLE_PLUGINS": unset, "AMP_PLUGIN_URI": unset,
				"AMP_PLUGIN_SOURCE_BASE64": unset, "AMP_SETTINGS_FILE": unset, "AMP_SKIP_UPDATE_CHECK": "1"}},
		{"codex", Codex, []string{"OPENAI_API_KEY=sk-placeholder"}, []string{"exec", "--skip-git-repo-check", "prompt"},
			map[string]string{"CODEX_API_KEY": "sk-placeholder"}},
		{"hermes", Hermes, []string{"BEDROCK_MANTLE_API_KEY=openshell:resolve:env:v4_BEDROCK_MANTLE_API_KEY", "HERMES_SAFE_MODE=1",
			"HERMES_MANAGED_DIR=/tmp/empty", "HERMES_HOME=/tmp/elsewhere", "HERMES_PYTHON_SRC_ROOT=/tmp/src", "HERMES_LAZY_INSTALL_TARGET=/tmp/lazy"},
			[]string{"chat", "-q", "hi"},
			map[string]string{"HERMES_DEFENSECLAW_API_KEY": "openshell:resolve:env:v4_BEDROCK_MANTLE_API_KEY", "HERMES_ACCEPT_HOOKS": "1",
				"HERMES_SAFE_MODE": unset, "HERMES_MANAGED_DIR": unset, "HERMES_HOME": "{dir}/.hermes", "HERMES_PYTHON_SRC_ROOT": unset,
				"HERMES_LAZY_INSTALL_TARGET": unset}},
		// An explicit key wins over the profile's.
		{"hermes own key", Hermes, []string{"HERMES_DEFENSECLAW_API_KEY=mine", "OPENAI_API_KEY=other"}, nil,
			map[string]string{"HERMES_DEFENSECLAW_API_KEY": "mine"}},
		{"openhands", OpenHands, []string{"OPENAI_API_KEY=openshell:resolve:env:v5_OPENAI_API_KEY"}, []string{"--headless", "-t", "p"},
			map[string]string{"LLM_API_KEY": "openshell:resolve:env:v5_OPENAI_API_KEY", "OPENHANDS_SUPPRESS_BANNER": "1"}},
		// The runner that executes tool commands keeps the proxy settings,
		// after anything the user already passes through, and loopback
		// between OmniGent's own processes stays off the proxy.
		{"omnigent", OmniGent, []string{"DEFENSECLAW_EGRESS_URL=http://10.200.0.1:28772", "DEFENSECLAW_SANDBOX_TOKEN=" + omnigentToken,
			"OMNIGENT_CONFIG=/tmp/elsewhere.yaml", "OMNIGENT_RUNNER_ENV_PASSTHROUGH=MY_TOOL_VAR"}, []string{"run", "-p", "hi"},
			map[string]string{"OMNIGENT_CONFIG": unset, "OMNIGENT_CONFIG_HOME": connector.OmnigentSandboxConfigHome, "OMNIGENT_NO_UPDATE_CHECK": "1",
				"OMNIGENT_DEFENSECLAW_SANDBOX_TOKEN": omnigentToken, "OMNIGENT_RUNNER_ENV_PASSTHROUGH": "MY_TOOL_VAR," + omnigentRunnerProxyPassthrough,
				"HTTPS_PROXY": "http://10.200.0.1:28772", "NO_PROXY": loopback, "no_proxy": loopback}},
		// Without the egress proxy nothing extra is passed through, and a
		// token that is not placeholder-shaped is not copied.
		{"omnigent strict", OmniGent, []string{"DEFENSECLAW_SANDBOX_TOKEN=bad token"}, []string{"run"},
			map[string]string{"OMNIGENT_RUNNER_ENV_PASSTHROUGH": unset, "HTTPS_PROXY": unset, "OMNIGENT_DEFENSECLAW_SANDBOX_TOKEN": unset}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLauncher(t, tc.spec)
			r := l.run(t, "", tc.env, tc.args...)
			if r.exit != 0 || !r.started() || !slices.Equal(r.last().args, tc.args) {
				t.Fatalf("exit %d argv %q, want %q:\n%s", r.exit, r.last().args, tc.args, r.output)
			}
			want := map[string]string{}
			for name, value := range tc.want {
				want[name] = strings.ReplaceAll(value, "{dir}", l.dir)
			}
			checkEnv(t, r.last(), want)
		})
	}
}

// TestLaunchersRefuseUnsafeArguments pins the arguments each launcher refuses
// before its harness starts (they would drop the hooks, load other settings
// or run the session elsewhere) and look-alikes it lets through.
func TestLaunchersRefuseUnsafeArguments(t *testing.T) {
	type argCase struct {
		args    []string
		refusal string // empty: the harness must start
	}
	for _, tc := range []struct {
		spec  *Spec
		cases []argCase
	}{
		// Hermes' parsers (top level and chat) resolve each --sa... to
		// --safe-mode; --s is ambiguous there, --save and --skills are other
		// options.
		{Hermes, []argCase{
			{[]string{"--sa"}, "safe mode"}, {[]string{"--safe"}, "safe mode"}, {[]string{"--safe-mo"}, "safe mode"},
			{[]string{"--safe-mode"}, "safe mode"}, {[]string{"--safe-mode=1"}, "safe mode"},
			{[]string{"chat", "--safe", "-q", "hi"}, "safe mode"}, {[]string{"--safe", "chat"}, "safe mode"},
			{[]string{"--s"}, ""}, {[]string{"--save"}, ""}, {[]string{"--skills", "x"}, ""}, {[]string{"chat", "-q", "be safe"}, ""},
		}},
		{OmniGent, []argCase{
			{[]string{"run", "--server", "http://127.0.0.1:7000"}, "names another server"},
			{[]string{"run", "--server=https://x.example"}, "names another server"},
			{[]string{"host", "--server", "http://h"}, "names another server"},
			{[]string{"run", "--server", "local"}, ""}, {[]string{"run", "--server="}, ""},
		}},
		{Kiro, []argCase{
			{[]string{"--agent", "kiro_default", "hi"}, "--agent is not supported"},
			{[]string{"--agent=kiro_default", "hi"}, "--agent=kiro_default is not supported"},
			{[]string{"--v3", "hi"}, "--v3 is not supported"}, {[]string{"--v2", "hi"}, "--v2 is not supported"},
			{[]string{"--agent-engine", "v3", "hi"}, "--agent-engine is not supported"},
			{[]string{"--agent-engine=v3", "hi"}, "--agent-engine=v3 is not supported"},
			{[]string{"--cloud", "hi"}, "--cloud is not supported"}, {[]string{"--repo=org/x", "hi"}, "--repo=org/x is not supported"},
			{[]string{"hi"}, ""},
		}},
		{Devin, []argCase{
			{[]string{"--config", "/tmp/x.json"}, "is not supported"}, {[]string{"--config=/tmp/x.json"}, "is not supported"},
			{[]string{"--respect-workspace-trust", "true", "-p", "hi"}, "is not supported"},
			{[]string{"--respect-workspace-trust=true"}, "is not supported"},
		}},
		{OpenCode, []argCase{
			{[]string{"--pure"}, "DefenseClaw policy plugin"}, {[]string{"run", "--pure", "hi"}, "DefenseClaw policy plugin"},
			{[]string{"--pure=true"}, "DefenseClaw policy plugin"},
		}},
		{Amp, []argCase{
			{[]string{"--settings-file", "/tmp/s.json"}, "--settings-file is not supported"},
			{[]string{"--settings-file=/tmp/s.json"}, "--settings-file is not supported"},
		}},
	} {
		t.Run(tc.spec.Name, func(t *testing.T) {
			if tc.spec == Devin {
				if _, err := os.Stat("/usr/bin/jq"); err != nil {
					t.Skip("/usr/bin/jq is required")
				}
			}
			l := newYAMLCheckedLauncher(t, tc.spec, "")
			for _, c := range tc.cases {
				r := l.run(t, "", nil, c.args...)
				if c.refusal == "" {
					if r.exit != 0 || !r.started() {
						t.Errorf("%q refused: exit %d %s", c.args, r.exit, r.output)
					}
				} else if r.exit != 2 || r.started() || !strings.Contains(r.output, c.refusal) {
					t.Errorf("%q: exit %d started %t output %q, want a refusal saying %q", c.args, r.exit, r.started(), r.output, c.refusal)
				}
			}
		})
	}
}

// TestLaunchersRefuseNonFileHookConfig replaces the hook configuration of the
// harnesses that read it only from HOME with a directory, or a link to one.
// `mv -f` would move the restored file inside it and exit 0, and the harness
// would start without DefenseClaw's hooks; the launcher must refuse, leave
// the directory alone, and restore the file once the path is free.
func TestLaunchersRefuseNonFileHookConfig(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	for _, tc := range []struct {
		name      string
		spec      *Spec
		rel       string
		canonical string // the root-owned copy the file is restored from, if any
		link      bool
	}{
		{"openhands", OpenHands, ".openhands/hooks.json", connector.OpenHandsSandboxCanonicalHooksPath, false},
		{"antigravity", Antigravity, ".gemini/config/hooks.json", connector.AntigravitySandboxCanonicalHooksPath, false},
		{"devin", Devin, ".config/devin/config.json", "", false},
		{"devin link", Devin, ".config/devin/config.json", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLauncher(t, tc.spec)
			cfg := filepath.Join(l.dir, filepath.FromSlash(tc.rel))
			kept := cfg
			if tc.link {
				kept = t.TempDir()
				if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(kept, cfg); err != nil {
					t.Fatal(err)
				}
			}
			writeFile(t, filepath.Join(kept, "kept"), []byte("x\n"))
			work := t.TempDir()
			r := l.run(t, work, nil, "-p", "hi")
			if r.exit != 2 || r.started() || !strings.Contains(r.output, cfg+" is not a regular file") {
				t.Fatalf("exit %d started %t:\n%s", r.exit, r.started(), r.output)
			}
			if entries, _ := os.ReadDir(kept); len(entries) != 1 {
				t.Fatalf("the launcher wrote into the directory: %v", entries)
			}
			if err := os.RemoveAll(cfg); err != nil {
				t.Fatal(err)
			}
			if r := l.run(t, work, nil, "-p", "hi"); r.exit != 0 || !r.started() {
				t.Fatalf("after freeing the path: exit %d\n%s", r.exit, r.output)
			}
			if info, err := os.Lstat(cfg); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("config after the restore: %v %v", info, err)
			}
			if tc.canonical != "" {
				want, _ := os.ReadFile(filepath.Join(l.dir, filepath.FromSlash(tc.canonical)))
				if got, _ := os.ReadFile(cfg); len(want) == 0 || string(got) != string(want) {
					t.Fatalf("restored hooks = %q, want the canonical copy", got)
				}
			}
		})
	}
}

// TestClaudeCodeLauncherQuietsTheNativeInstallCheck pins the one Claude Code
// installation check DISABLE_INSTALLATION_CHECKS leaves on: ~/.local/bin
// follows the system directories on PATH (once), and a relative HOME adds
// nothing.
func TestClaudeCodeLauncherQuietsTheNativeInstallCheck(t *testing.T) {
	l := newLauncher(t, ClaudeCode)
	for _, tc := range []struct{ home, path, want string }{
		{l.dir, "/usr/bin:/bin", LauncherSystemPATH + ":/usr/bin:/bin:" + l.dir + "/.local/bin"},
		{l.dir, "/usr/bin:" + l.dir + "/.local/bin", LauncherSystemPATH + ":/usr/bin:" + l.dir + "/.local/bin"},
		{"relative", "/usr/bin:/bin", LauncherSystemPATH + ":/usr/bin:/bin"},
	} {
		if r := l.run(t, "", []string{"HOME=" + tc.home, "PATH=" + tc.path}); r.exit != 0 || r.last().env["PATH"] != tc.want {
			t.Fatalf("HOME=%s PATH=%s: exit %d PATH=%s, want %s\n%s", tc.home, tc.path, r.exit, r.last().env["PATH"], tc.want, r.output)
		}
	}
	artifacts := artifactsFor(t, ClaudeCode)
	for _, name := range []string{"DISABLE_INSTALLATION_CHECKS", "DISABLE_UPDATES", "DISABLE_AUTOUPDATER"} {
		if artifacts.Env[name] != "1" {
			t.Errorf("the Claude Code sandbox env does not set %s=1: %v", name, artifacts.Env)
		}
	}
}

func TestClaudeLauncherRefreshesKeyApproval(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	l := newLauncher(t, ClaudeCode)
	cfg := filepath.Join(l.dir, ".claude.json")
	writeFile(t, cfg, []byte(`{"hasCompletedOnboarding":true,"customApiKeyResponses":{"approved":["old"]}}`))
	key := "openshell:resolve:env:v13503686996004693124_ANTHROPIC_API_KEY"
	r := l.run(t, "", []string{"ANTHROPIC_API_KEY=" + key}, "--dangerously-skip-permissions", "-p", "hi")
	if r.exit != 0 || !slices.Equal(r.last().args, []string{"--dangerously-skip-permissions", "-p", "hi"}) {
		t.Fatalf("exit %d argv %q:\n%s", r.exit, r.last().args, r.output)
	}
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		HasCompletedOnboarding bool `json:"hasCompletedOnboarding"`
		CustomAPIKeyResponses  struct {
			Approved []string `json:"approved"`
			Rejected []string `json:"rejected"`
		} `json:"customApiKeyResponses"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.HasCompletedOnboarding || !reflect.DeepEqual(doc.CustomAPIKeyResponses.Approved, []string{key[len(key)-20:], "old"}) || doc.CustomAPIKeyResponses.Rejected == nil {
		t.Fatalf("config = %s", raw)
	}
}

// TestClaudeLauncherMergesRunMCPServers pins that the launcher adds the
// per-run imported servers to the user-scope registry when the manager
// mounted them, and leaves ~/.claude.json alone when it did not.
func TestClaudeLauncherMergesRunMCPServers(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	l := newLauncher(t, ClaudeCode)
	servers := filepath.Join(l.dir, filepath.FromSlash(connector.ClaudeCodeSandboxRunMCPServersPath))
	cfg := filepath.Join(l.dir, ".claude.json")
	launch := func() map[string]interface{} {
		t.Helper()
		if r := l.run(t, "", nil, "-p", "hi"); r.exit != 0 {
			t.Fatalf("exit %d:\n%s", r.exit, r.output)
		}
		raw, _ := os.ReadFile(cfg)
		var doc map[string]interface{}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%v: %s", err, raw)
		}
		return doc
	}
	command := func(doc map[string]interface{}, name string) interface{} {
		return doc["mcpServers"].(map[string]interface{})[name].(map[string]interface{})["command"]
	}
	writeFile(t, cfg, []byte(`{"hasCompletedOnboarding":true,"mcpServers":{"mine":{"command":"a"},"github":{"command":"old"}}}`))
	if doc := launch(); command(doc, "github") != "old" {
		t.Fatalf("no run file, yet the registry changed: %v", doc)
	}
	writeFile(t, servers, []byte(`{"mcpServers":{"github":{"type":"stdio","command":"npx","args":["srv"]}}}`))
	if doc := launch(); command(doc, "mine") != "a" || command(doc, "github") != "npx" || doc["hasCompletedOnboarding"] != true {
		t.Fatalf("merged registry = %v", doc)
	}
	writeFile(t, servers, []byte(`not json`))
	if doc := launch(); command(doc, "github") != "npx" {
		t.Fatalf("a malformed run file changed the registry: %v", doc)
	}
}

// TestCodexLauncherRefreshesTheLogin pins that an interactive Codex start
// refreshes the stored login from the API key, on stdin, and that the
// launcher writes trust entries only under /work or /sandbox.
func TestCodexLauncherRefreshesTheLogin(t *testing.T) {
	l := newLauncher(t, Codex)
	r := l.run(t, "", []string{"OPENAI_API_KEY=sk-placeholder", "DEFENSECLAW_SANDBOX_TOKEN=bad\"token"}, "--dangerously-bypass-approvals-and-sandbox")
	if r.exit != 0 || len(r.calls) != 2 || !slices.Equal(r.calls[0].args, []string{"login", "--with-api-key"}) || r.calls[0].stdin != "sk-placeholder" {
		t.Fatalf("interactive launch did not refresh the stored login: exit %d calls %+v\n%s", r.exit, r.calls, r.output)
	}
	if runtime.GOOS == "linux" {
		if _, err := os.Stat(filepath.Join(l.dir, ".codex", "config.toml")); err == nil {
			t.Fatal("trusted a directory outside /work and /sandbox")
		}
	}
}

// TestCodexLauncherKeepsTheTokenOffTheCommandLine pins that the Codex
// launcher hands the OTLP Authorization header to Codex's exporters in
// OTEL_EXPORTER_OTLP_{LOGS,TRACES,METRICS}_HEADERS (URL-encoded, as the
// OTLP exporter decodes them) and never in argv: with token_delivery: env
// the binding token is the credential itself, and every process in the
// sandbox can read another's command line. A malformed token, and header
// variables the caller set, reach Codex not at all; NODE_OPTIONS carries
// only the launcher's --disable-warning for the Node proxy agent warning.
func TestCodexLauncherKeepsTheTokenOffTheCommandLine(t *testing.T) {
	for _, tc := range []struct {
		name, token, header string
	}{
		{"placeholder", "openshell:resolve:env:v7_DEFENSECLAW_SANDBOX_TOKEN", "authorization=Bearer%20openshell:resolve:env:v7_DEFENSECLAW_SANDBOX_TOKEN"},
		{"env delivery", "dcsb_0123456789abcdefABCDEF-_", "authorization=Bearer%20dcsb_0123456789abcdefABCDEF-_"},
		{"malformed", `bad"token`, unset},
		{"missing", "", unset},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := []string{"OTEL_EXPORTER_OTLP_HEADERS=x-caller=1", "OTEL_EXPORTER_OTLP_LOGS_HEADERS=authorization=Bearer%20caller",
				"NODE_OPTIONS=--require=/tmp/planted.js"}
			if tc.token != "" {
				env = append(env, "DEFENSECLAW_SANDBOX_TOKEN="+tc.token)
			}
			r := newLauncher(t, Codex).run(t, "", env, "exec", "--skip-git-repo-check", "prompt")
			// The exact argv also proves no argument carries the token.
			if r.exit != 0 || len(r.calls) != 1 || !slices.Equal(r.last().args, []string{"exec", "--skip-git-repo-check", "prompt"}) {
				t.Fatalf("exit %d calls %+v:\n%s", r.exit, r.calls, r.output)
			}
			checkEnv(t, r.last(), map[string]string{
				"OTEL_EXPORTER_OTLP_LOGS_HEADERS": tc.header, "OTEL_EXPORTER_OTLP_TRACES_HEADERS": tc.header,
				"OTEL_EXPORTER_OTLP_METRICS_HEADERS": tc.header, "OTEL_EXPORTER_OTLP_HEADERS": unset,
				"NODE_OPTIONS": "--disable-warning=UNDICI-EHPA",
			})
		})
	}
}

// TestOpenCodeLauncherRefusesForeignPlugins plants each source of code
// OpenCode would import next to the DefenseClaw plugin and requires the
// launcher to refuse before OpenCode starts, naming what it found, while the
// config DefenseClaw and OpenCode themselves write still starts.
func TestOpenCodeLauncherRefusesForeignPlugins(t *testing.T) {
	// Config it cannot check is refused.
	r := newLauncher(t, OpenCode, "/usr/bin/jq", "/nonexistent/jq").run(t, "", []string{`OPENCODE_CONFIG_CONTENT={"model":"x"}`}, "run", "hi")
	if r.exit != 2 || r.started() || !strings.Contains(r.output, "OPENCODE_CONFIG_CONTENT could not be checked") {
		t.Fatalf("without jq: exit %d\n%s", r.exit, r.output)
	}
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	const plugin = "export const Planted = async () => ({});\n"
	const wellknown = `{"https://config.example":{"type":"wellknown","key":"K","token":"t"}}`
	type layout struct {
		files map[string]string // relative to the root
		env   []string          // {root} is replaced
		args  []string          // {root} is replaced
		// names is what the refusal must name ({root} is replaced); empty
		// means the launcher must start OpenCode.
		names string
		// reason, when set, is the refusal's reason.
		reason string
	}
	cases := map[string]layout{
		"clean": {},
		"empty plugin lists": {files: map[string]string{
			"home/.config/opencode/opencode.json": `{"plugin":[]}`, "work/proj/opencode.json": `{"plugin":[]}`,
			"work/proj/.opencode/opencode.json": `{"plugin":[],"agent":{}}`, "work/proj/.opencode/agents/review.md": "# review\n",
		}},
		"what OpenCode writes into a config directory": {files: map[string]string{
			"home/.config/opencode/opencode.jsonc":                               `{"$schema":"https://opencode.ai/config.json"}`,
			"home/.config/opencode/package.json":                                 `{"dependencies":{"@opencode-ai/plugin":"1.18.31"}}`,
			"home/.config/opencode/.gitignore":                                   "node_modules\n",
			"home/.config/opencode/node_modules/@opencode-ai/plugin/index.js":    plugin,
			"work/proj/.opencode/package.json":                                   `{"dependencies":{"@opencode-ai/plugin":"1.18.31"}}`,
			"work/proj/.opencode/node_modules/@opencode-ai/plugin/dist/index.js": plugin,
			"work/proj/.opencode/plugins/README.md":                              "notes\n",
		}},
		"the Mantle profile config": {env: []string{"OPENCODE_CONFIG_CONTENT=" + openCodeMantleConfig,
			"BEDROCK_MANTLE_API_KEY=openshell:resolve:env:v3_BEDROCK_MANTLE_API_KEY"}},
		// OpenCode inserts a {file:} substitution JSON-escaped, so it cannot
		// add a key.
		"an agent prompt from a file": {files: map[string]string{
			"work/proj/opencode.json": `{"agent":{"review":{"prompt":"{file:./prompt.txt}"}}}`,
			"work/proj/prompt.txt":    "\"plugin\": [\"some-plugin\"]\n", "home/.config/opencode/x.md": "notes\n",
		}},
		"JSONC comments, one hiding a plugin entry": {files: map[string]string{
			"home/.config/opencode/opencode.jsonc": "{\n  // \"plugin\": [\"some-plugin\"],\n  /* \"npm\": \"x\" */\n  \"model\": \"anthropic/claude\", // trailing\n}\n",
		}},
		"an OpenAI-compatible provider": {env: []string{
			`OPENCODE_CONFIG_CONTENT={"provider":{"local":{"npm":"@ai-sdk/openai-compatible","options":{"baseURL":"http://host.openshell.internal:1/v1"}}}}`,
		}},
		"API-key logins": {files: map[string]string{"home/.local/share/opencode/auth.json": `{"anthropic":{"type":"api","key":"sk-test"}}`}},

		"project plugin":          {files: map[string]string{"work/proj/.opencode/plugins/early.js": plugin}, names: "{root}/work/proj/.opencode/plugins/early.js"},
		"project plugin singular": {files: map[string]string{"work/proj/.opencode/plugin/early.ts": plugin}, names: "{root}/work/proj/.opencode/plugin/early.ts"},
		"project custom tool":     {files: map[string]string{"work/proj/.opencode/tools/t.ts": plugin}, names: "{root}/work/proj/.opencode/tools/t.ts"},
		"hidden custom tool":      {files: map[string]string{"work/proj/.opencode/tool/.t.js": plugin}, names: "{root}/work/proj/.opencode/tool/.t.js"},
		"ancestor plugin":         {files: map[string]string{"work/.opencode/plugins/up.js": plugin}, names: "{root}/work/.opencode/plugins/up.js"},
		"user plugin":             {files: map[string]string{"home/.config/opencode/plugins/user.js": plugin}, names: "{root}/home/.config/opencode/plugins/user.js"},
		"XDG user plugin": {files: map[string]string{"xdg/opencode/plugins/user.js": plugin},
			env: []string{"XDG_CONFIG_HOME={root}/xdg"}, names: "{root}/xdg/opencode/plugins/user.js"},
		"home .opencode plugin": {files: map[string]string{"home/.opencode/plugins/h.js": plugin}, names: "{root}/home/.opencode/plugins/h.js"},
		"OPENCODE_CONFIG_DIR plugin": {files: map[string]string{"cfg/plugins/c.js": plugin},
			env: []string{"OPENCODE_CONFIG_DIR={root}/cfg"}, names: "{root}/cfg/plugins/c.js"},
		"project config plugin entry": {files: map[string]string{"work/proj/opencode.json": `{"plugin":["file:///tmp/p.js"]}`},
			names: "{root}/work/proj/opencode.json"},
		"ancestor JSONC plugin entry": {files: map[string]string{"work/opencode.jsonc": "{\n  // extra\n  \"plugin\": [\"some-plugin\"],\n}\n"},
			names: "{root}/work/opencode.jsonc", reason: "registers plugins"},
		"config directory plugin entry": {files: map[string]string{"work/proj/.opencode/opencode.jsonc": `{"plugin":["some-plugin"]}`},
			names: "{root}/work/proj/.opencode/opencode.jsonc"},
		"user config.json plugin entry": {files: map[string]string{"home/.config/opencode/config.json": `{"plugin":["some-plugin"]}`},
			names: "{root}/home/.config/opencode/config.json"},
		"legacy TOML user config": {files: map[string]string{"home/.config/opencode/config": "plugin = [\"some-plugin\"]\n"},
			names: "{root}/home/.config/opencode/config"},
		"project TUI plugin entry": {files: map[string]string{"work/proj/tui.json": `{"plugin":["some-plugin"]}`}, names: "{root}/work/proj/tui.json"},
		"OPENCODE_CONFIG plugin entry": {files: map[string]string{"custom.json": `{"plugin":["some-plugin"]}`},
			env: []string{"OPENCODE_CONFIG={root}/custom.json"}, names: "{root}/custom.json"},
		"OPENCODE_TUI_CONFIG plugin entry": {files: map[string]string{"tui-custom.json": `{"plugin":["some-plugin"]}`},
			env: []string{"OPENCODE_TUI_CONFIG={root}/tui-custom.json"}, names: "{root}/tui-custom.json"},
		"OPENCODE_CONFIG_CONTENT plugin entry": {env: []string{`OPENCODE_CONFIG_CONTENT={"plugin":["some-plugin"]}`}, names: "OPENCODE_CONFIG_CONTENT"},
		// OpenCode substitutes {env:NAME} into the raw text before parsing.
		"plugin key from an env substitution": {files: map[string]string{"work/proj/opencode.json": `{ {env:DC_TEST_EXTRA} }`},
			env: []string{`DC_TEST_EXTRA="plugin":["some-plugin"]`}, names: "{root}/work/proj/opencode.json"},
		// A naive comment strip would drop everything between the /* and
		// */ inside the two strings, plugin entry included.
		"comment markers inside strings": {files: map[string]string{"work/proj/opencode.json": `{"model":"a/*","plugin":["some-plugin"],"small_model":"*/b"}`},
			names: "{root}/work/proj/opencode.json"},
		"escaped plugin key in JSONC": {files: map[string]string{"work/proj/opencode.jsonc": "{\n  // extra\n  \"\\u0070lugin\": [\"some-plugin\"],\n}\n"},
			names: "{root}/work/proj/opencode.jsonc", reason: "registers plugins"},
		"unparsable config with an escape": {files: map[string]string{"work/proj/opencode.json": `{"\u0070lugin": ["some-plugin"]`},
			names: "{root}/work/proj/opencode.json", reason: "could not be parsed"},
		"config that is not a file": {files: map[string]string{"work/proj/opencode.json/x": "{}"},
			names: "{root}/work/proj/opencode.json", reason: "is not a regular file"},
		"file URL provider SDK": {files: map[string]string{"work/proj/opencode.json": `{"provider":{"anthropic":{"npm":"file:///work/proj/sdk.js"}}}`},
			names: "{root}/work/proj/opencode.json", reason: "names a provider SDK"},
		"unbundled provider SDK in a model": {env: []string{`OPENCODE_CONFIG_CONTENT={"provider":{"x":{"npm":"@ai-sdk/anthropic","models":{"m":{"provider":{"npm":"some-sdk"}}}}}}`},
			names: "OPENCODE_CONFIG_CONTENT", reason: "names a provider SDK"},
		"remote config login": {files: map[string]string{"home/.local/share/opencode/auth.json": wellknown},
			names: "{root}/home/.local/share/opencode/auth.json", reason: "logs in to a remote OpenCode config"},
		"remote config login in XDG_DATA_HOME": {files: map[string]string{"data/opencode/auth.json": wellknown},
			env: []string{"XDG_DATA_HOME={root}/data"}, names: "{root}/data/opencode/auth.json"},
		"remote config login in OPENCODE_AUTH_CONTENT": {env: []string{"OPENCODE_AUTH_CONTENT=" + wellknown}, names: "OPENCODE_AUTH_CONTENT"},
		"project directory argument": {files: map[string]string{"other/.opencode/plugins/o.js": plugin},
			args: []string{"{root}/other"}, names: "{root}/other/.opencode/plugins/o.js"},
		"--dir argument": {files: map[string]string{"other/.opencode/plugins/o.js": plugin},
			args: []string{"run", "--dir={root}/other", "hi"}, names: "{root}/other/.opencode/plugins/o.js"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{"home", "work/proj"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for rel, body := range tc.files {
				writeFile(t, filepath.Join(root, rel), []byte(body))
			}
			expand := func(in []string) []string {
				out := make([]string, len(in))
				for i, v := range in {
					out[i] = strings.ReplaceAll(v, "{root}", root)
				}
				return out
			}
			args := expand(tc.args)
			if len(args) == 0 {
				args = []string{"run", "--auto", "hi"}
			}
			r := newLauncher(t, OpenCode).run(t, filepath.Join(root, "work", "proj"), append([]string{"HOME=" + filepath.Join(root, "home")}, expand(tc.env)...), args...)
			if tc.names == "" {
				if r.exit != 0 || !r.started() {
					t.Fatalf("OpenCode did not start: exit %d\n%s", r.exit, r.output)
				}
				return
			}
			names := strings.ReplaceAll(tc.names, "{root}", root)
			if r.exit != 2 || r.started() || !strings.Contains(r.output, "refusing to start OpenCode: "+names+" "+tc.reason) {
				t.Fatalf("exit %d, want a refusal naming %s %s:\n%s", r.exit, names, tc.reason, r.output)
			}
		})
	}
}
