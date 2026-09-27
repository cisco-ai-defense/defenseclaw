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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// launcherEnv runs spec's launcher with the pinned binary replaced by a stub
// that records the environment it received (one NAME=value per line), and
// returns the exit code, the record and the launcher's output.
func launcherEnv(t *testing.T, spec *Spec, env []string) (int, string, string) {
	t.Helper()
	launcher, dir := launcherFixture(t, spec, `/usr/bin/env >"${0%/*}/record"`+"\n")
	code, out := startLauncher(t, launcher, dir, dir, env)
	got, _ := os.ReadFile(filepath.Join(dir, "record"))
	return code, "\n" + string(got), out
}

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
// script (stubBody after the shebang) and the root-owned templates the
// launcher restores from laid out below the directory. It returns the
// launcher and the directory.
func launcherFixture(t *testing.T, spec *Spec, stubBody string) (string, string) {
	t.Helper()
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "stub")
	if err := os.WriteFile(stub, []byte("#!/bin/bash\n"+stubBody), 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, "launch")
	script := strings.ReplaceAll(string(spec.Launcher().Data), "/usr/local/bin/"+spec.Command+" ", stub+" ")
	// Launchers that pin the image HOME use the test directory instead, and
	// the root-owned templates they restore from are laid out below it.
	script = strings.ReplaceAll(script, "HOME="+connector.SandboxHomeDir+"\n", "HOME="+dir+"\n")
	script = strings.ReplaceAll(script, `"`+connector.SandboxLibDir+"/", `"`+dir+connector.SandboxLibDir+"/")
	for _, file := range artifactsFor(t, spec).Files {
		if file.Owner != connector.SandboxOwnerRoot || !strings.HasPrefix(file.Path, connector.SandboxLibDir+"/") {
			continue
		}
		dest := filepath.Join(dir, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, file.Data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(launcher, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return launcher, dir
}

// TestLaunchersScrubShellStartupEnv starts every launcher with the shell
// start-up variables an agent could export from ~/.bashrc and a PATH that
// puts its own directory first, plus the DefenseClaw proxy variables: the
// harness must receive none of the former (SHELLOPTS=noexec would even stop
// the stub, a bash script, from recording anything), the system directories
// first on PATH, and the standard proxy variables exported from the
// DefenseClaw ones in place of the caller's.
func TestLaunchersScrubShellStartupEnv(t *testing.T) {
	proxy := "http://b1:secret@host.openshell.internal:18972"
	noProxy := "api.anthropic.com,host.openshell.internal"
	for _, name := range Names() {
		spec, _ := Get(name)
		t.Run(name, func(t *testing.T) {
			agentBin := t.TempDir()
			startup := filepath.Join(t.TempDir(), "startup")
			if err := os.WriteFile(startup, []byte("echo sourced-startup-file\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			code, got, out := launcherEnv(t, spec, []string{
				"BASH_ENV=" + startup, "ENV=" + startup, "BASHOPTS=extglob", "SHELLOPTS=noexec",
				"CDPATH=/tmp", "GLOBIGNORE=*", "PATH=" + agentBin + ":/usr/bin:/bin",
				"HTTPS_PROXY=http://elsewhere:1", "no_proxy=*",
				openshell.EnvEgressURL + "=" + proxy, openshell.EnvEgressBypass + "=" + noProxy,
			})
			if code != 0 || !strings.Contains(got, "\nPATH=") {
				t.Fatalf("the stub never ran: exit %d\n%s", code, out)
			}
			if strings.Contains(out, "sourced-startup-file") {
				t.Errorf("a start-up file ran:\n%s", out)
			}
			for _, v := range []string{"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE"} {
				if strings.Contains(got, "\n"+v+"=") {
					t.Errorf("%s reached the harness:\n%s", v, got)
				}
			}
			if !strings.Contains(got, "\nPATH="+LauncherSystemPATH+":"+agentBin+":") {
				t.Errorf("PATH does not lead with the system directories:\n%s", got)
			}
			wantNoProxy := noProxy
			if name == "omnigent" {
				// OmniGent's processes talk to each other over loopback.
				wantNoProxy += ",127.0.0.1,localhost,::1"
			}
			for _, want := range []string{
				"HTTPS_PROXY=" + proxy, "HTTP_PROXY=" + proxy, "https_proxy=" + proxy, "http_proxy=" + proxy,
				"NODE_USE_ENV_PROXY=1", "NO_PROXY=" + wantNoProxy, "no_proxy=" + wantNoProxy,
			} {
				if !strings.Contains(got, "\n"+want+"\n") {
					t.Errorf("missing %s:\n%s", want, got)
				}
			}
		})
	}
}

// TestLaunchersKeepNodeOffWorkloadCode starts every launcher with the Node
// variables an agent could export from ~/.bashrc: a NODE_OPTIONS preload, a
// NODE_PATH module directory and a compile cache in a directory it owns. The
// Cursor Agent wrapper and the npm launchers run Node, which would load the
// preload and run cached V8 code in place of the root-owned sources, so the
// harness must receive neither variable and the compile cache switched off
// (NODE_DISABLE_COMPILE_CACHE also overrides the cache the Cursor wrapper
// points at ~/.cache).
func TestLaunchersKeepNodeOffWorkloadCode(t *testing.T) {
	for _, name := range Names() {
		spec, _ := Get(name)
		t.Run(name, func(t *testing.T) {
			planted := t.TempDir()
			code, got, out := launcherEnv(t, spec, []string{
				"NODE_OPTIONS=--require=" + planted + "/preload.js", "NODE_PATH=" + planted, "NODE_COMPILE_CACHE=" + planted,
				"NODE_DISABLE_COMPILE_CACHE=0",
			})
			if code != 0 || !strings.Contains(got, "\nPATH=") {
				t.Fatalf("the stub never ran: exit %d\n%s", code, out)
			}
			for _, v := range []string{"NODE_OPTIONS", "NODE_PATH"} {
				if strings.Contains(got, "\n"+v+"=") {
					t.Errorf("%s reached the harness:\n%s", v, got)
				}
			}
			if !strings.Contains(got, "\nNODE_DISABLE_COMPILE_CACHE=1\n") {
				t.Errorf("Node's compile cache is not switched off:\n%s", got)
			}
		})
	}
}

// TestLaunchersLeaveProxyAloneWithoutEgress keeps a strict-profile sandbox
// (no DefenseClaw proxy) free of proxy settings.
func TestLaunchersLeaveProxyAloneWithoutEgress(t *testing.T) {
	for _, name := range Names() {
		spec, _ := Get(name)
		code, got, out := launcherEnv(t, spec, nil)
		if code != 0 || !strings.Contains(got, "\nPATH=") {
			t.Fatalf("%s: exit %d\n%s", name, code, out)
		}
		for _, v := range []string{"HTTPS_PROXY", "https_proxy", "NODE_USE_ENV_PROXY", "NO_PROXY"} {
			if strings.Contains(got, "\n"+v+"=") {
				t.Errorf("%s: %s set without a DefenseClaw proxy:\n%s", name, v, got)
			}
		}
	}
}

// TestOpenCodeLauncherRefusesForeignPlugins plants each source of code
// OpenCode would import next to the DefenseClaw plugin and requires the
// launcher to refuse before OpenCode starts, naming what it found, while the
// config DefenseClaw and OpenCode themselves write still starts.
func TestOpenCodeLauncherRefusesForeignPlugins(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	const plugin = "export const Planted = async () => ({});\n"
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
			"home/.config/opencode/opencode.json":  `{"plugin":[]}`,
			"work/proj/opencode.json":              `{"plugin":[]}`,
			"work/proj/.opencode/opencode.json":    `{"plugin":[],"agent":{}}`,
			"work/proj/.opencode/agents/review.md": "# review\n",
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
		"the Mantle profile config": {env: []string{
			"OPENCODE_CONFIG_CONTENT=" + openCodeMantleConfig,
			"BEDROCK_MANTLE_API_KEY=openshell:resolve:env:v3_BEDROCK_MANTLE_API_KEY",
		}},
		// OpenCode inserts a {file:} substitution JSON-escaped, so it cannot
		// add a key.
		"an agent prompt from a file": {files: map[string]string{
			"work/proj/opencode.json":    `{"agent":{"review":{"prompt":"{file:./prompt.txt}"}}}`,
			"work/proj/prompt.txt":       "\"plugin\": [\"some-plugin\"]\n",
			"home/.config/opencode/x.md": "notes\n",
		}},
		"JSONC comments, one hiding a plugin entry": {files: map[string]string{
			"home/.config/opencode/opencode.jsonc": "{\n  // \"plugin\": [\"some-plugin\"],\n  /* \"npm\": \"x\" */\n  \"model\": \"anthropic/claude\", // trailing\n}\n",
		}},
		"an OpenAI-compatible provider": {env: []string{
			`OPENCODE_CONFIG_CONTENT={"provider":{"local":{"npm":"@ai-sdk/openai-compatible","options":{"baseURL":"http://host.openshell.internal:1/v1"}}}}`,
		}},
		"API-key logins": {files: map[string]string{
			"home/.local/share/opencode/auth.json": `{"anthropic":{"type":"api","key":"sk-test"}}`,
		}},

		"project plugin":          {files: map[string]string{"work/proj/.opencode/plugins/early.js": plugin}, names: "{root}/work/proj/.opencode/plugins/early.js"},
		"project plugin singular": {files: map[string]string{"work/proj/.opencode/plugin/early.ts": plugin}, names: "{root}/work/proj/.opencode/plugin/early.ts"},
		"project custom tool":     {files: map[string]string{"work/proj/.opencode/tools/t.ts": plugin}, names: "{root}/work/proj/.opencode/tools/t.ts"},
		"hidden custom tool":      {files: map[string]string{"work/proj/.opencode/tool/.t.js": plugin}, names: "{root}/work/proj/.opencode/tool/.t.js"},
		"ancestor plugin":         {files: map[string]string{"work/.opencode/plugins/up.js": plugin}, names: "{root}/work/.opencode/plugins/up.js"},
		"user plugin":             {files: map[string]string{"home/.config/opencode/plugins/user.js": plugin}, names: "{root}/home/.config/opencode/plugins/user.js"},
		"XDG user plugin": {
			files: map[string]string{"xdg/opencode/plugins/user.js": plugin},
			env:   []string{"XDG_CONFIG_HOME={root}/xdg"}, names: "{root}/xdg/opencode/plugins/user.js",
		},
		"home .opencode plugin": {files: map[string]string{"home/.opencode/plugins/h.js": plugin}, names: "{root}/home/.opencode/plugins/h.js"},
		"OPENCODE_CONFIG_DIR plugin": {
			files: map[string]string{"cfg/plugins/c.js": plugin},
			env:   []string{"OPENCODE_CONFIG_DIR={root}/cfg"}, names: "{root}/cfg/plugins/c.js",
		},
		"project config plugin entry": {
			files: map[string]string{"work/proj/opencode.json": `{"plugin":["file:///tmp/p.js"]}`},
			names: "{root}/work/proj/opencode.json",
		},
		"ancestor JSONC plugin entry": {
			files: map[string]string{"work/opencode.jsonc": "{\n  // extra\n  \"plugin\": [\"some-plugin\"],\n}\n"},
			names: "{root}/work/opencode.jsonc", reason: "registers plugins",
		},
		"config directory plugin entry": {
			files: map[string]string{"work/proj/.opencode/opencode.jsonc": `{"plugin":["some-plugin"]}`},
			names: "{root}/work/proj/.opencode/opencode.jsonc",
		},
		"user config.json plugin entry": {
			files: map[string]string{"home/.config/opencode/config.json": `{"plugin":["some-plugin"]}`},
			names: "{root}/home/.config/opencode/config.json",
		},
		"legacy TOML user config": {
			files: map[string]string{"home/.config/opencode/config": "plugin = [\"some-plugin\"]\n"},
			names: "{root}/home/.config/opencode/config",
		},
		"project TUI plugin entry": {
			files: map[string]string{"work/proj/tui.json": `{"plugin":["some-plugin"]}`},
			names: "{root}/work/proj/tui.json",
		},
		"OPENCODE_CONFIG plugin entry": {
			files: map[string]string{"custom.json": `{"plugin":["some-plugin"]}`},
			env:   []string{"OPENCODE_CONFIG={root}/custom.json"}, names: "{root}/custom.json",
		},
		"OPENCODE_TUI_CONFIG plugin entry": {
			files: map[string]string{"tui-custom.json": `{"plugin":["some-plugin"]}`},
			env:   []string{"OPENCODE_TUI_CONFIG={root}/tui-custom.json"}, names: "{root}/tui-custom.json",
		},
		"OPENCODE_CONFIG_CONTENT plugin entry": {
			env: []string{`OPENCODE_CONFIG_CONTENT={"plugin":["some-plugin"]}`}, names: "OPENCODE_CONFIG_CONTENT",
		},
		// OpenCode substitutes {env:NAME} into the raw text before parsing.
		"plugin key from an env substitution": {
			files: map[string]string{"work/proj/opencode.json": `{ {env:DC_TEST_EXTRA} }`},
			env:   []string{`DC_TEST_EXTRA="plugin":["some-plugin"]`}, names: "{root}/work/proj/opencode.json",
		},
		// A naive comment strip would drop everything between the /* and
		// */ inside the two strings, plugin entry included.
		"comment markers inside strings": {
			files: map[string]string{"work/proj/opencode.json": `{"model":"a/*","plugin":["some-plugin"],"small_model":"*/b"}`},
			names: "{root}/work/proj/opencode.json",
		},
		"escaped plugin key in JSONC": {
			files: map[string]string{"work/proj/opencode.jsonc": "{\n  // extra\n  \"\\u0070lugin\": [\"some-plugin\"],\n}\n"},
			names: "{root}/work/proj/opencode.jsonc", reason: "registers plugins",
		},
		"unparsable config with an escape": {
			files: map[string]string{"work/proj/opencode.json": `{"\u0070lugin": ["some-plugin"]`},
			names: "{root}/work/proj/opencode.json", reason: "could not be parsed",
		},
		"config that is not a file": {
			files: map[string]string{"work/proj/opencode.json/x": "{}"},
			names: "{root}/work/proj/opencode.json", reason: "is not a regular file",
		},
		"file URL provider SDK": {
			files: map[string]string{"work/proj/opencode.json": `{"provider":{"anthropic":{"npm":"file:///work/proj/sdk.js"}}}`},
			names: "{root}/work/proj/opencode.json", reason: "names a provider SDK",
		},
		"unbundled provider SDK in a model": {
			env:   []string{`OPENCODE_CONFIG_CONTENT={"provider":{"x":{"npm":"@ai-sdk/anthropic","models":{"m":{"provider":{"npm":"some-sdk"}}}}}}`},
			names: "OPENCODE_CONFIG_CONTENT", reason: "names a provider SDK",
		},
		"remote config login": {
			files: map[string]string{"home/.local/share/opencode/auth.json": `{"https://config.example":{"type":"wellknown","key":"K","token":"t"}}`},
			names: "{root}/home/.local/share/opencode/auth.json", reason: "logs in to a remote OpenCode config",
		},
		"remote config login in XDG_DATA_HOME": {
			files: map[string]string{"data/opencode/auth.json": `{"https://config.example":{"type":"wellknown","key":"K","token":"t"}}`},
			env:   []string{"XDG_DATA_HOME={root}/data"}, names: "{root}/data/opencode/auth.json",
		},
		"remote config login in OPENCODE_AUTH_CONTENT": {
			env:   []string{`OPENCODE_AUTH_CONTENT={"https://config.example":{"type":"wellknown","key":"K","token":"t"}}`},
			names: "OPENCODE_AUTH_CONTENT",
		},
		"project directory argument": {
			files: map[string]string{"other/.opencode/plugins/o.js": plugin},
			args:  []string{"{root}/other"}, names: "{root}/other/.opencode/plugins/o.js",
		},
		"--dir argument": {
			files: map[string]string{"other/.opencode/plugins/o.js": plugin},
			args:  []string{"run", "--dir={root}/other", "hi"}, names: "{root}/other/.opencode/plugins/o.js",
		},
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
				file := filepath.Join(root, rel)
				if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			expand := func(in []string) []string {
				out := make([]string, len(in))
				for i, v := range in {
					out[i] = strings.ReplaceAll(v, "{root}", root)
				}
				return out
			}
			env := append([]string{"HOME=" + filepath.Join(root, "home")}, expand(tc.env)...)
			args := expand(tc.args)
			if len(args) == 0 {
				args = []string{"run", "--auto", "hi"}
			}
			code, got := runLauncherIn(t, OpenCode, "/usr/local/bin/opencode", filepath.Join(root, "work", "proj"), nil, env, args...)
			if tc.names == "" {
				if code != 0 || !strings.Contains(got, "ARG ") {
					t.Fatalf("OpenCode did not start: exit %d\n%s", code, got)
				}
				return
			}
			names := strings.ReplaceAll(tc.names, "{root}", root)
			if code != 2 || strings.Contains(got, "ARG ") || !strings.Contains(got, "refusing to start OpenCode: "+names+" "+tc.reason) {
				t.Fatalf("exit %d, want a refusal naming %s %s:\n%s", code, names, tc.reason, got)
			}
		})
	}
}

// TestOpenCodeLauncherFailsClosedWithoutJQ refuses config it cannot check.
func TestOpenCodeLauncherFailsClosedWithoutJQ(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "stub")
	if err := os.WriteFile(stub, []byte("#!/bin/bash\necho started\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := strings.NewReplacer("/usr/local/bin/opencode", stub, "/usr/bin/jq", filepath.Join(dir, "no-jq")).Replace(string(OpenCode.Launcher().Data))
	launcher := filepath.Join(dir, "launch")
	if err := os.WriteFile(launcher, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(launcher, "run", "hi")
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, `OPENCODE_CONFIG_CONTENT={"model":"x"}`}
	out, err := cmd.CombinedOutput()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 || strings.Contains(string(out), "started") || !strings.Contains(string(out), "OPENCODE_CONFIG_CONTENT could not be checked") {
		t.Fatalf("%v\n%s", err, out)
	}
}
