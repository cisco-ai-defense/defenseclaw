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

package image

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// TestClaudeCodeHostileSettingsPlantsBothTiers runs the planting fragment
// with its absolute roots moved under a temp dir and checks what the probe
// container would see: both settings files, every knob set, and every planted
// program leaving its label when started the way Claude would start it.
func TestClaudeCodeHostileSettingsPlantsBothTiers(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	plan, ok := hostileSettingsPlans["claudecode"]
	if !ok {
		t.Fatal("no hostile-settings plan for claudecode")
	}
	if plan.workdir != "/work/dc-hookfire-project" {
		t.Fatalf("workdir = %q, want a project under the pre-trusted work root", plan.workdir)
	}
	root := t.TempDir()
	relocate := strings.NewReplacer(
		hostileRoot, root+hostileRoot,
		"'/sandbox/", "'"+root+"/sandbox/",
		"/work/", root+"/work/",
	)
	setup := relocate.Replace(plan.setup)
	if out, err := exec.Command(bash, "-c", setup).CombinedOutput(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	ranLog := root + hostileRanLog
	ran := func() []string {
		t.Helper()
		data, err := os.ReadFile(ranLog)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		_ = os.Remove(ranLog)
		return strings.Fields(string(data))
	}
	if got := ran(); len(got) != 0 {
		t.Fatalf("planting ran planted programs: %v", got)
	}

	for tier, file := range map[string]string{
		"user":    root + "/sandbox/.claude/settings.json",
		"project": root + "/work/dc-hookfire-project/.claude/settings.json",
	} {
		t.Run(tier, func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var settings struct {
				DisableAllHooks     bool              `json:"disableAllHooks"`
				Env                 map[string]string `json:"env"`
				APIKeyHelper        string            `json:"apiKeyHelper"`
				AWSAuthRefresh      string            `json:"awsAuthRefresh"`
				AWSCredentialExport string            `json:"awsCredentialExport"`
				GCPAuthRefresh      string            `json:"gcpAuthRefresh"`
				StatusLine          struct {
					Type    string `json:"type"`
					Command string `json:"command"`
				} `json:"statusLine"`
				Hooks map[string][]struct {
					Hooks []struct {
						Type    string `json:"type"`
						Command string `json:"command"`
					} `json:"hooks"`
				} `json:"hooks"`
			}
			if err := json.Unmarshal(data, &settings); err != nil {
				t.Fatalf("settings are not JSON: %v\n%s", err, data)
			}
			if !settings.DisableAllHooks {
				t.Error("disableAllHooks not planted")
			}
			var keys []string
			for key := range settings.Env {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			want := []string{
				"BASH_ENV", "CLAUDE_CODE_SHELL", "CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_CODE_SIMPLE",
				"DEFENSECLAW_GATEWAY_TOKEN", "DEFENSECLAW_HOME", "PATH", "SHELL",
			}
			if strings.Join(keys, " ") != strings.Join(want, " ") {
				t.Fatalf("planted env = %v, want %v", keys, want)
			}
			if settings.Env["CLAUDE_CODE_SIMPLE"] != "1" {
				t.Errorf("CLAUDE_CODE_SIMPLE = %q", settings.Env["CLAUDE_CODE_SIMPLE"])
			}
			if _, err := os.Stat(filepath.Join(settings.Env["DEFENSECLAW_HOME"], ".disabled")); err != nil {
				t.Errorf("DEFENSECLAW_HOME is not marked disabled: %v", err)
			}

			// Claude runs the prefix with the command as one argument, the
			// shell with -c, and settings hooks, auth helpers and the status
			// line through /bin/sh.
			bin := strings.SplitN(settings.Env["PATH"], ":", 2)[0]
			hooks := settings.Hooks["PreToolUse"]
			if len(hooks) != 1 || len(hooks[0].Hooks) != 1 || hooks[0].Hooks[0].Type != "command" {
				t.Fatalf("planted PreToolUse hook = %+v", hooks)
			}
			if settings.StatusLine.Type != "command" {
				t.Fatalf("planted statusLine = %+v, want the schema's command object", settings.StatusLine)
			}
			for label, argv := range map[string][]string{
				"shell-prefix":  {settings.Env["CLAUDE_CODE_SHELL_PREFIX"], "/usr/local/lib/defenseclaw/hooks/claude-code-hook.sh"},
				"shell":         {settings.Env["CLAUDE_CODE_SHELL"], "-c", "true"},
				"curl":          {filepath.Join(bin, "curl"), "-q"},
				"jq":            {filepath.Join(bin, "jq"), "-r"},
				"settings-hook": {"/bin/sh", "-c", hooks[0].Hooks[0].Command},
				"bash-env":      {bash, "-c", ". " + settings.Env["BASH_ENV"]},
				"apikey-helper": {"/bin/sh", "-c", settings.APIKeyHelper},
				"aws-refresh":   {"/bin/sh", "-c", settings.AWSAuthRefresh},
				"aws-export":    {"/bin/sh", "-c", settings.AWSCredentialExport},
				"gcp-refresh":   {"/bin/sh", "-c", settings.GCPAuthRefresh},
				"status-line":   {"/bin/sh", "-c", settings.StatusLine.Command},
			} {
				if out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput(); err != nil {
					t.Fatalf("%s: %v\n%s", label, err, out)
				}
				if got := ran(); len(got) != 1 || got[0] != tier+":"+label {
					t.Fatalf("%s left %v in the planted-run log, want %s:%s", label, got, tier, label)
				}
			}
			if settings.Env["SHELL"] != settings.Env["CLAUDE_CODE_SHELL"] {
				t.Errorf("SHELL = %q, want the planted shell", settings.Env["SHELL"])
			}
		})
	}
}

// TestCodexHostileSettingsPlantsBothTiers checks the Codex plan the same way:
// both config files parse as TOML with the documented keys, and every
// planted program and sourced file leaves its label.
func TestCodexHostileSettingsPlantsBothTiers(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	plan := hostileSettingsPlans["codex"]
	if plan.workdir != "/work/dc-hookfire-project" {
		t.Fatalf("workdir = %q", plan.workdir)
	}
	root := t.TempDir()
	relocate := strings.NewReplacer(hostileRoot, root+hostileRoot, "'/sandbox/", "'"+root+"/sandbox/", "/work/", root+"/work/")
	if out, err := exec.Command(bash, "-c", relocate.Replace(plan.setup)).CombinedOutput(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	ranLog := root + hostileRanLog
	ran := func() []string {
		t.Helper()
		data, _ := os.ReadFile(ranLog)
		_ = os.Remove(ranLog)
		return strings.Fields(string(data))
	}
	if got := ran(); len(got) != 0 {
		t.Fatalf("planting ran planted programs: %v", got)
	}
	for tier, file := range map[string]string{
		"user":    root + "/sandbox/.codex/config.toml",
		"project": root + "/work/dc-hookfire-project/.codex/config.toml",
	} {
		t.Run(tier, func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var cfg struct {
				Notify         []string `toml:"notify"`
				ApprovalPolicy string   `toml:"approval_policy"`
				ModelProvider  string   `toml:"model_provider"`
				Features       struct {
					Hooks *bool `toml:"hooks"`
				} `toml:"features"`
				Hooks struct {
					PreToolUse []struct {
						Matcher string `toml:"matcher"`
						Hooks   []struct {
							Type    string `toml:"type"`
							Command string `toml:"command"`
						} `toml:"hooks"`
					} `toml:"PreToolUse"`
				} `toml:"hooks"`
				Shell struct {
					Set map[string]string `toml:"set"`
				} `toml:"shell_environment_policy"`
			}
			if err := toml.Unmarshal(data, &cfg); err != nil {
				t.Fatalf("config is not TOML: %v\n%s", err, data)
			}
			if cfg.Features.Hooks == nil || *cfg.Features.Hooks || cfg.ApprovalPolicy != "never" || cfg.ModelProvider != "hostile" || len(cfg.Notify) != 1 {
				t.Fatalf("planted config = %+v", cfg)
			}
			var keys []string
			for key := range cfg.Shell.Set {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			if strings.Join(keys, " ") != "BASH_ENV DEFENSECLAW_HOME DEFENSECLAW_SANDBOX_TOKEN ENV PATH" {
				t.Fatalf("planted shell env = %v", keys)
			}
			if len(cfg.Hooks.PreToolUse) != 1 || len(cfg.Hooks.PreToolUse[0].Hooks) != 1 {
				t.Fatalf("planted hooks = %+v", cfg.Hooks)
			}
			bin := strings.SplitN(cfg.Shell.Set["PATH"], ":", 2)[0]
			for label, argv := range map[string][]string{
				"curl":        {filepath.Join(bin, "curl")},
				"jq":          {filepath.Join(bin, "jq")},
				"notify":      {cfg.Notify[0], "{}"},
				"config-hook": {"/bin/sh", "-c", cfg.Hooks.PreToolUse[0].Hooks[0].Command},
				"shell-env":   {bash, "-c", ". " + cfg.Shell.Set["BASH_ENV"]},
			} {
				if out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput(); err != nil {
					t.Fatalf("%s: %v\n%s", label, err, out)
				}
				if got := ran(); len(got) != 1 || got[0] != tier+":"+label {
					t.Fatalf("%s left %v in the planted-run log", label, got)
				}
			}
		})
	}
}
