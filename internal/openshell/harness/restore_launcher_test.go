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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// recordArgsAndEnv is a stub body that records its argv (ARG lines) and
// environment (ENV lines) next to itself.
const recordArgsAndEnv = `{ printf 'ARG %s\n' "$@"; /usr/bin/env | sed 's/^/ENV /'; } >"${0%/*}/record"` + "\n"

// recordedRun is what a recordArgsAndEnv stub saw.
type recordedRun struct {
	args []string
	env  map[string]string
}

// readRecord parses the record a recordArgsAndEnv stub left in dir.
func readRecord(t *testing.T, dir string) recordedRun {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "record"))
	if err != nil {
		t.Fatalf("the stub never ran: %v", err)
	}
	run := recordedRun{env: map[string]string{}}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		switch {
		case strings.HasPrefix(line, "ARG "):
			run.args = append(run.args, strings.TrimPrefix(line, "ARG "))
		case strings.HasPrefix(line, "ENV "):
			name, value, _ := strings.Cut(strings.TrimPrefix(line, "ENV "), "=")
			run.env[name] = value
		}
	}
	return run
}

// kiroHostileLaunchEnv are variables Kiro CLI 2.24.1 reads to move its
// agents, settings and data or to replace the shell tool's shell, set the way
// an agent could export them from ~/.bashrc.
var kiroHostileLaunchEnv = []string{
	"KIRO_HOME", "KIRO_AGENT_CONFIG_DIR", "KIRO_TEST_AGENTS_DIR", "KIRO_CHAT_SHELL", "AMAZON_Q_CHAT_SHELL",
	"KIRO_DATA_DIR", "KIRO_TEST_SETTINGS_PATH", "KIRO_TEST_DB_PATH", "KIRO_RECORD_API_RESPONSES_PATH",
	"KIRO_RECORD_API_REQUESTS_PATH", "KIRO_AGENT_ENGINE", "KIRO_KAS_NODE_PATH", "KIRO_TEST_TUI_JS_PATH",
	"Q_MOCK_CHAT_RESPONSE", "KAS_BUNDLE_PATH", "ASBX_KIRO_MANDATORY_MCPS",
}

func TestKiroLauncherPinsTheRootOwnedAgentDir(t *testing.T) {
	launcher, home := launcherFixture(t, Kiro, recordArgsAndEnv)
	agentDir := filepath.Join(home, filepath.FromSlash(connector.KiroSandboxAgentDir))
	if _, err := os.Stat(filepath.Join(agentDir, connector.KiroSandboxAgentName+".json")); err != nil {
		t.Fatalf("the fixture lacks the root-owned agent: %v", err)
	}
	// Hookless agents named defenseclaw in HOME and the project, under the
	// DefenseClaw file name and under names that sort before it: with the
	// agent directory pinned Kiro reads neither directory, so the launcher
	// starts without looking at them.
	hookless := []byte(`{"name":"` + connector.KiroSandboxAgentName + `","hooks":{}}`)
	project := t.TempDir()
	for _, file := range []string{
		filepath.Join(home, ".kiro", "agents", "a.json"),
		filepath.Join(home, ".kiro", "agents", connector.KiroSandboxAgentName+".json"),
		filepath.Join(project, ".kiro", "agents", "project.json"),
		filepath.Join(project, ".kiro", "agents", connector.KiroSandboxAgentName+".json"),
	} {
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, hookless, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	elsewhere := t.TempDir()
	env := []string{"KIRO_API_KEY=placeholder", "KIRO_MOCK_CHAT_RESPONSE=/tmp/script.json", "KIROTOOL_KEEP=1", "DC_TEST_KEEP=1"}
	for _, name := range kiroHostileLaunchEnv {
		env = append(env, name+"="+elsewhere)
	}
	code, out := startLauncher(t, launcher, "/elsewhere", project, env, "--no-interactive", "--trust-all-tools", "fix it")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	run := readRecord(t, home)
	if want := []string{"chat", "--v2", "--agent", connector.KiroSandboxAgentName, "--no-interactive", "--trust-all-tools", "fix it"}; !reflect.DeepEqual(run.args, want) {
		t.Fatalf("kiro-cli-chat argv = %q, want %q", run.args, want)
	}
	if got := run.env[connector.KiroSandboxAgentDirEnv]; got != agentDir {
		t.Errorf("%s = %q, want the root-owned %s", connector.KiroSandboxAgentDirEnv, got, agentDir)
	}
	for _, name := range kiroHostileLaunchEnv {
		if name == connector.KiroSandboxAgentDirEnv {
			continue
		}
		if value, ok := run.env[name]; ok {
			t.Errorf("%s=%s reached kiro-cli-chat", name, value)
		}
	}
	for _, name := range []string{"KIRO_API_KEY", "KIRO_MOCK_CHAT_RESPONSE", "KIROTOOL_KEEP", "DC_TEST_KEEP"} {
		if _, ok := run.env[name]; !ok {
			t.Errorf("%s was dropped", name)
		}
	}
	if run.env["HOME"] != home {
		t.Errorf("HOME %q reached kiro-cli-chat", run.env["HOME"])
	}
	// Nothing is restored into HOME any more.
	if got, _ := os.ReadFile(filepath.Join(home, ".kiro", "agents", connector.KiroSandboxAgentName+".json")); string(got) != string(hookless) {
		t.Errorf("the launcher rewrote the HOME agent file: %s", got)
	}
}

func TestKiroLauncherRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(t *testing.T, home string)
		args  []string
		names string
	}{
		"agent-missing": {
			setup: func(t *testing.T, home string) {
				if err := os.Remove(filepath.Join(home, filepath.FromSlash(connector.KiroSandboxAgentPath))); err != nil {
					t.Fatal(err)
				}
			},
			names: connector.KiroSandboxAgentPath + " is missing",
		},
		"caller-agent":        {args: []string{"--agent", "kiro_default"}, names: "--agent is not supported"},
		"caller-agent-equals": {args: []string{"--agent=kiro_default"}, names: "--agent=kiro_default is not supported"},
		"v3-engine":           {args: []string{"--v3"}, names: "--v3 is not supported"},
		"engine-flag":         {args: []string{"--agent-engine", "v3"}, names: "--agent-engine is not supported"},
		"engine-flag-equals":  {args: []string{"--agent-engine=v3"}, names: "--agent-engine=v3 is not supported"},
		"cloud-session":       {args: []string{"--cloud"}, names: "--cloud is not supported"},
		"cloud-repo":          {args: []string{"--repo=org/x"}, names: "--repo=org/x is not supported"},
		"duplicate-engine":    {args: []string{"--v2"}, names: "--v2 is not supported"},
	} {
		t.Run(name, func(t *testing.T) {
			launcher, home := launcherFixture(t, Kiro, "echo started\n")
			if tc.setup != nil {
				tc.setup(t, home)
			}
			code, out := startLauncher(t, launcher, home, t.TempDir(), nil, append(tc.args, "hi")...)
			if code != 2 || strings.Contains(out, "started") || !strings.Contains(out, tc.names) {
				t.Fatalf("exit %d, want a refusal naming %q:\n%s", code, tc.names, out)
			}
		})
	}
	launcher, home := launcherFixture(t, Kiro, "echo started\n")
	if code, out := startLauncher(t, launcher, home, home, nil, "hi"); code != 0 || !strings.Contains(out, "started") {
		t.Fatalf("a launch from HOME was refused: exit %d\n%s", code, out)
	}
}

// devinHooks decodes the hooks object of a Devin config.
func devinHooks(t *testing.T, raw []byte) (map[string]interface{}, map[string]interface{}) {
	t.Helper()
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config %s: %v", raw, err)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	return cfg, hooks
}

func TestDevinLauncherRestoresTheHooks(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	var template []byte
	for _, file := range artifactsFor(t, Devin).Files {
		if file.Path == connector.DevinSandboxConfigTemplatePath {
			template = file.Data
		}
	}
	_, wantHooks := devinHooks(t, template)
	if len(wantHooks) == 0 {
		t.Fatal("the Devin template carries no hooks")
	}
	for name, tc := range map[string]struct {
		existing  string
		keepOther bool
	}{
		"hooks-removed":  {existing: `{"model":"opus","hooks":{}}`, keepOther: true},
		"hooks-replaced": {existing: `{"model":"opus","hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":"/bin/true"}]}]}}`, keepOther: true},
		"not-json":       {existing: `{"model":`},
		"not-an-object":  {existing: `["x"]`},
		"two-documents":  {existing: `{"model":"opus"} {"hooks":{}}`},
		"comments":       {existing: "{\n  // the user's note\n  \"model\": \"opus\"\n}"},
		"missing":        {},
	} {
		t.Run(name, func(t *testing.T) {
			launcher, home := launcherFixture(t, Devin, recordArgsAndEnv)
			cfgPath := filepath.Join(home, ".config", "devin", "config.json")
			if tc.existing != "" {
				if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cfgPath, []byte(tc.existing), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			code, out := startLauncher(t, launcher, home, home, []string{"XDG_CONFIG_HOME=" + t.TempDir()}, "-p", "hi")
			if code != 0 {
				t.Fatalf("exit %d:\n%s", code, out)
			}
			raw, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			cfg, hooks := devinHooks(t, raw)
			if !reflect.DeepEqual(hooks, wantHooks) {
				t.Fatalf("hooks after the launch:\n%s", raw)
			}
			if tc.keepOther && cfg["model"] != "opus" {
				t.Fatalf("the user's other settings were dropped:\n%s", raw)
			}
			if info, _ := os.Stat(cfgPath); info.Mode().Perm() != 0o600 {
				t.Fatalf("config mode %v", info.Mode())
			}
			record, _ := os.ReadFile(filepath.Join(home, "record"))
			if strings.Contains(string(record), "ENV XDG_CONFIG_HOME=") || !strings.Contains(string(record), "ARG -p\nARG hi\n") {
				t.Fatalf("devin record:\n%s", record)
			}
		})
	}
	launcher, home := launcherFixture(t, Devin, "echo started\n")
	for _, args := range [][]string{{"--config", "/tmp/x.json"}, {"--config=/tmp/x.json"}} {
		if code, out := startLauncher(t, launcher, home, home, nil, args...); code != 2 || strings.Contains(out, "started") || !strings.Contains(out, "is not supported") {
			t.Fatalf("%v: exit %d\n%s", args, code, out)
		}
	}
}
