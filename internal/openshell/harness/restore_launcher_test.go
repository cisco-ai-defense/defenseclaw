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

// kiroTemplate is the rendered DefenseClaw agent the launcher restores.
func kiroTemplate(t *testing.T) []byte {
	t.Helper()
	for _, file := range artifactsFor(t, Kiro).Files {
		if file.Path == connector.KiroSandboxAgentTemplatePath {
			return file.Data
		}
	}
	t.Fatal("the Kiro artifacts carry no agent template")
	return nil
}

func TestKiroLauncherRestoresTheAgentAndSelectsIt(t *testing.T) {
	launcher, home := launcherFixture(t, Kiro, recordArgsAndEnv)
	agents := filepath.Join(home, ".kiro", "agents")
	agent := filepath.Join(agents, connector.KiroSandboxAgentName+".json")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink the agent planted: the launcher replaces the link itself
	// and never writes through it.
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"name":"defenseclaw","hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, agent); err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	code, out := startLauncher(t, launcher, "/elsewhere", project,
		[]string{"KIRO_HOME=" + t.TempDir()}, "--no-interactive", "--trust-all-tools", "fix it")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	info, err := os.Lstat(agent)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("agent is not a regular file after the launch: %v %v", info, err)
	}
	got, _ := os.ReadFile(agent)
	if string(got) != string(kiroTemplate(t)) {
		t.Fatalf("agent was not restored from the template:\n%s", got)
	}
	if kept, _ := os.ReadFile(target); string(kept) != `{"name":"defenseclaw","hooks":{}}` {
		t.Fatalf("the launcher wrote through the planted symlink: %s", kept)
	}
	record, _ := os.ReadFile(filepath.Join(home, "record"))
	var args []string
	env := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(record)), "\n") {
		switch {
		case strings.HasPrefix(line, "ARG "):
			args = append(args, strings.TrimPrefix(line, "ARG "))
		case strings.HasPrefix(line, "ENV "):
			name, value, _ := strings.Cut(strings.TrimPrefix(line, "ENV "), "=")
			env[name] = value
		}
	}
	if want := []string{"chat", "--v2", "--agent", connector.KiroSandboxAgentName, "--no-interactive", "--trust-all-tools", "fix it"}; !reflect.DeepEqual(args, want) {
		t.Fatalf("kiro-cli-chat argv = %q, want %q", args, want)
	}
	if _, ok := env["KIRO_HOME"]; ok || env["HOME"] != home {
		t.Fatalf("KIRO_HOME %q HOME %q reached kiro-cli-chat", env["KIRO_HOME"], env["HOME"])
	}
}

func TestKiroLauncherRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(t *testing.T, home, project string)
		args  []string
		names string
	}{
		"shadowing-project-agent": {
			setup: func(t *testing.T, _, project string) {
				dir := filepath.Join(project, ".kiro", "agents")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, connector.KiroSandboxAgentName+".json"), []byte(`{"name":"defenseclaw"}`), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			names: ".kiro/agents/" + connector.KiroSandboxAgentName + ".json replaces the DefenseClaw agent",
		},
		"dangling-shadow-symlink": {
			setup: func(t *testing.T, _, project string) {
				dir := filepath.Join(project, ".kiro", "agents")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/nonexistent", filepath.Join(dir, connector.KiroSandboxAgentName+".json")); err != nil {
					t.Fatal(err)
				}
			},
			names: "replaces the DefenseClaw agent",
		},
		"caller-agent":        {args: []string{"--agent", "kiro_default"}, names: "--agent is not supported"},
		"caller-agent-equals": {args: []string{"--agent=kiro_default"}, names: "--agent=kiro_default is not supported"},
		"v3-engine":           {args: []string{"--v3"}, names: "--v3 is not supported"},
		"engine-flag":         {args: []string{"--agent-engine", "v3"}, names: "--agent-engine is not supported"},
		"engine-flag-equals":  {args: []string{"--agent-engine=v3"}, names: "--agent-engine=v3 is not supported"},
		"cloud-session":       {args: []string{"--cloud"}, names: "--cloud is not supported"},
		"cloud-repo":          {args: []string{"--repo=org/x"}, names: "--repo=org/x is not supported"},
		"duplicate-engine":    {args: []string{"--v2"}, names: "--v2 is not supported"},
		"agents-dir-is-a-file": {
			setup: func(t *testing.T, home, _ string) {
				if err := os.MkdirAll(filepath.Join(home, ".kiro"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, ".kiro", "agents"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			names: "agents cannot be created",
		},
	} {
		t.Run(name, func(t *testing.T) {
			launcher, home := launcherFixture(t, Kiro, "echo started\n")
			project := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, home, project)
			}
			code, out := startLauncher(t, launcher, home, project, nil, append(tc.args, "hi")...)
			if code != 2 || strings.Contains(out, "started") || !strings.Contains(out, tc.names) {
				t.Fatalf("exit %d, want a refusal naming %q:\n%s", code, tc.names, out)
			}
		})
	}
	// The global agent in HOME is not a project agent.
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
