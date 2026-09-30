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
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// kiroHostileLaunchEnv are variables Kiro CLI 2.24.1 reads to move its
// agents, settings and data or to replace the shell tool's shell, set the way
// an agent could export them from ~/.bashrc.
var kiroHostileLaunchEnv = []string{
	"KIRO_HOME", "KIRO_AGENT_CONFIG_DIR", "KIRO_TEST_AGENTS_DIR", "KIRO_CHAT_SHELL", "AMAZON_Q_CHAT_SHELL",
	"KIRO_DATA_DIR", "KIRO_TEST_SETTINGS_PATH", "KIRO_TEST_DB_PATH", "KIRO_RECORD_API_RESPONSES_PATH",
	"KIRO_RECORD_API_REQUESTS_PATH", "KIRO_AGENT_ENGINE", "KIRO_KAS_NODE_PATH", "KIRO_TEST_TUI_JS_PATH",
	"Q_MOCK_CHAT_RESPONSE", "KAS_BUNDLE_PATH", "ASBX_KIRO_MANDATORY_MCPS",
}

// TestKiroLauncherPinsTheRootOwnedAgentDir: hookless agents named defenseclaw
// in HOME and the project, under the DefenseClaw file name and under names
// that sort before it, are never read (with the agent directory pinned Kiro
// reads neither directory), the variables that move Kiro elsewhere are
// dropped, Kiro is told to run the pinned binary in place, and a missing
// DefenseClaw agent stops the launcher.
func TestKiroLauncherPinsTheRootOwnedAgentDir(t *testing.T) {
	l := newLauncher(t, Kiro)
	agentDir := filepath.Join(l.dir, filepath.FromSlash(connector.KiroSandboxAgentDir))
	hookless := []byte(`{"name":"` + connector.KiroSandboxAgentName + `","hooks":{}}`)
	project := t.TempDir()
	for _, file := range []string{
		filepath.Join(l.dir, ".kiro", "agents", "a.json"),
		filepath.Join(l.dir, ".kiro", "agents", connector.KiroSandboxAgentName+".json"),
		filepath.Join(project, ".kiro", "agents", "project.json"),
		filepath.Join(project, ".kiro", "agents", connector.KiroSandboxAgentName+".json"),
	} {
		writeFile(t, file, hookless)
	}
	// Kiro runs the binary it was started as, not a copy in its data
	// directory's run/, whatever the caller exported.
	want := map[string]string{connector.KiroSandboxAgentDirEnv: agentDir, "HOME": l.dir, kiroSkipBinaryPinningEnv: "1"}
	env := []string{"HOME=/elsewhere", kiroSkipBinaryPinningEnv + "=0"}
	for _, name := range kiroHostileLaunchEnv {
		env = append(env, name+"=/elsewhere")
		if name != connector.KiroSandboxAgentDirEnv {
			want[name] = unset
		}
	}
	for _, name := range []string{"KIRO_API_KEY", "KIRO_MOCK_CHAT_RESPONSE", "KIROTOOL_KEEP", "DC_TEST_KEEP"} {
		env = append(env, name+"=kept")
		want[name] = "kept"
	}
	r := l.run(t, project, env, "--no-interactive", "--trust-all-tools", "fix it")
	if wantArgs := []string{"chat", "--v2", "--agent", connector.KiroSandboxAgentName, "--no-interactive", "--trust-all-tools", "fix it"}; r.exit != 0 || !slices.Equal(r.last().args, wantArgs) {
		t.Fatalf("exit %d kiro-cli-chat argv = %q, want %q\n%s", r.exit, r.last().args, wantArgs, r.output)
	}
	checkEnv(t, r.last(), want)
	if got, _ := os.ReadFile(filepath.Join(l.dir, ".kiro", "agents", connector.KiroSandboxAgentName+".json")); string(got) != string(hookless) {
		t.Errorf("the launcher rewrote the HOME agent file: %s", got)
	}
	if err := os.Remove(filepath.Join(agentDir, connector.KiroSandboxAgentName+".json")); err != nil {
		t.Fatal(err)
	}
	if r := l.run(t, "", nil, "hi"); r.exit != 2 || r.started() || !strings.Contains(r.output, connector.KiroSandboxAgentPath+" is missing") {
		t.Fatalf("without the agent: exit %d\n%s", r.exit, r.output)
	}
}

// TestLoginsRunThroughTheLauncher runs every harness login with the pinned
// binaries replaced by recording stubs: the vendor login must start through
// the launcher with the egress proxy exported (a login that bypasses the
// launcher gets no proxy, and OpenShell refuses its direct connections) and
// the launcher's environment hygiene applied.
func TestLoginsRunThroughTheLauncher(t *testing.T) {
	proxy := "http://b1:secret@host.openshell.internal:18972"
	for _, tc := range []struct {
		spec *Spec
		// binary is the pinned binary the login runs.
		binary string
		want   []string
	}{
		{Cursor, "/usr/local/bin/cursor-agent", []string{"login"}},
		{Devin, "/usr/local/bin/devin", []string{"--respect-workspace-trust", "false", "auth", "login", "--force-manual-token-flow"}},
		{Kiro, "/usr/local/bin/kiro-cli", []string{"login", "--use-device-flow"}},
	} {
		t.Run(tc.spec.Name, func(t *testing.T) {
			if tc.spec == Devin {
				if _, err := os.Stat("/usr/bin/jq"); err != nil {
					t.Skip("/usr/bin/jq is required")
				}
			}
			login, ok := tc.spec.Login()
			if !ok || login.Argv[0] != tc.spec.LauncherPath() {
				t.Fatalf("login %#v does not start with %s", login, tc.spec.LauncherPath())
			}
			l := newLauncher(t, tc.spec)
			if tc.binary != "/usr/local/bin/"+tc.spec.Command {
				// Only the login binary records; the chat binary fails loudly.
				writeExecutable(t, filepath.Join(l.dir, "stub"), "#!/bin/bash\necho 'the chat binary ran' >&2; exit 9\n")
				rewriteLauncher(t, l.path, tc.binary+" ", writeExecutable(t, filepath.Join(l.dir, "login-stub"), "#!/bin/bash\n"+recordStub)+" ")
			}
			r := l.run(t, "", []string{
				openshell.EnvEgressURL + "=" + proxy, openshell.EnvEgressBypass + "=host.openshell.internal", "NODE_OPTIONS=--require=/tmp/x.js",
			}, login.Argv[1:]...)
			if r.exit != 0 || !slices.Equal(r.last().args, tc.want) {
				t.Fatalf("exit %d %s argv = %q, want %q\n%s", r.exit, tc.binary, r.last().args, tc.want, r.output)
			}
			checkEnv(t, r.last(), map[string]string{
				"HTTPS_PROXY": proxy, "https_proxy": proxy, "HTTP_PROXY": proxy, "NO_PROXY": "host.openshell.internal",
				"NODE_USE_ENV_PROXY": "1", "NODE_DISABLE_COMPILE_CACHE": "1", "HOME": l.dir, "NODE_OPTIONS": unset,
			})
		})
	}
}

// TestDevinLauncherRestoresTheHooks: whatever the agent left in its Devin
// config (hooks removed or replaced, the trust check the launcher skips
// turned back on, a file Devin's loader would not read), the launcher puts
// DefenseClaw's hooks back, keeps the user's other settings when it can
// read them, and runs Devin with the workspace trust check off (a headless
// --print run fails in an untrusted directory, and a declined trust prompt
// runs Devin without hooks).
func TestDevinLauncherRestoresTheHooks(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	hooksOf := func(raw []byte) (map[string]interface{}, interface{}) {
		t.Helper()
		var cfg map[string]interface{}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("config %s: %v", raw, err)
		}
		return cfg, cfg["hooks"]
	}
	var template []byte
	for _, file := range artifactsFor(t, Devin).Files {
		if file.Path == connector.DevinSandboxConfigTemplatePath {
			template = file.Data
		}
	}
	_, wantHooks := hooksOf(template)
	if h, _ := wantHooks.(map[string]interface{}); len(h) == 0 {
		t.Fatal("the Devin template carries no hooks")
	}
	for name, tc := range map[string]struct {
		existing  string
		keepOther bool
	}{
		"hooks-removed":   {`{"model":"opus","hooks":{}}`, true},
		"trust-reenabled": {`{"model":"opus","respect_workspace_trust":true,"skip_workspace_trust":false,"hooks":{}}`, true},
		"hooks-replaced":  {`{"model":"opus","hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":"/bin/true"}]}]}}`, true},
		"not-json":        {`{"model":`, false},
		"not-an-object":   {`["x"]`, false},
		"two-documents":   {`{"model":"opus"} {"hooks":{}}`, false},
		"comments":        {"{\n  // the user's note\n  \"model\": \"opus\"\n}", false},
		"missing":         {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			l := newLauncher(t, Devin)
			cfgPath := filepath.Join(l.dir, ".config", "devin", "config.json")
			if tc.existing != "" {
				writeFile(t, cfgPath, []byte(tc.existing))
			}
			r := l.run(t, "", []string{"XDG_CONFIG_HOME=" + t.TempDir()}, "-p", "hi")
			if r.exit != 0 || !slices.Equal(r.last().args, []string{"--respect-workspace-trust", "false", "-p", "hi"}) {
				t.Fatalf("exit %d devin argv %q:\n%s", r.exit, r.last().args, r.output)
			}
			checkEnv(t, r.last(), map[string]string{"XDG_CONFIG_HOME": unset})
			raw, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			cfg, hooks := hooksOf(raw)
			if !reflect.DeepEqual(hooks, wantHooks) || (tc.keepOther && cfg["model"] != "opus") {
				t.Fatalf("config after the launch:\n%s", raw)
			}
			for _, key := range []string{"respect_workspace_trust", "skip_workspace_trust"} {
				if _, ok := cfg[key]; ok {
					t.Fatalf("the config keeps %s:\n%s", key, raw)
				}
			}
			if info, _ := os.Stat(cfgPath); info.Mode().Perm() != 0o600 {
				t.Fatalf("config mode %v", info.Mode())
			}
		})
	}
}
