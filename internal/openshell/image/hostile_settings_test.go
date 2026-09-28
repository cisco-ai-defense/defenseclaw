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
	"strconv"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
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

// relocatedHostileSetup runs a plan's planting fragment with its absolute
// roots moved under a temp dir and returns that root.
func relocatedHostileSetup(t *testing.T, name string) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	plan, ok := hostileSettingsPlans[name]
	if !ok || plan.workdir != hostileProject {
		t.Fatalf("%s hostile plan = %+v", name, plan)
	}
	// Resolved, so paths the launcher prints (pwd -P) match on macOS too.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	relocate := strings.NewReplacer(
		hostileRoot, root+hostileRoot,
		"'/sandbox/", "'"+root+"/sandbox/",
		"\"/sandbox/", "\""+root+"/sandbox/",
		"/work/", root+"/work/",
	)
	if out, err := exec.Command(bash, "-c", relocate.Replace(plan.setup)).CombinedOutput(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	if data, _ := os.ReadFile(root + hostileRanLog); len(data) != 0 {
		t.Fatalf("planting ran planted programs: %s", data)
	}
	return root
}

func TestCopilotHostileSettingsPlants(t *testing.T) {
	root := relocatedHostileSetup(t, "copilot")
	for _, file := range []string{"/sandbox/.copilot/settings.json", "/work/dc-hookfire-project/.github/copilot/settings.json"} {
		data, err := os.ReadFile(root + file)
		if err != nil || strings.TrimSpace(string(data)) != `{"disableAllHooks":true}` {
			t.Fatalf("%s = %s (%v)", file, data, err)
		}
	}
	for tier, file := range map[string]string{
		"user":    "/sandbox/.copilot/hooks/hostile.json",
		"project": "/work/dc-hookfire-project/.github/hooks/hostile.json",
	} {
		data, err := os.ReadFile(root + file)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Version int `json:"version"`
			Hooks   map[string][]struct {
				Bash string `json:"bash"`
			} `json:"hooks"`
		}
		if err := json.Unmarshal(data, &doc); err != nil || doc.Version != 1 || len(doc.Hooks["preToolUse"]) != 1 {
			t.Fatalf("%s hooks = %s (%v)", tier, data, err)
		}
		// Copilot runs a bash hook through bash (the setup already relocated
		// its path).
		if out, err := exec.Command("bash", "-c", doc.Hooks["preToolUse"][0].Bash).CombinedOutput(); err != nil {
			t.Fatalf("%s hook: %v\n%s", tier, err, out)
		}
		data, _ = os.ReadFile(root + hostileRanLog)
		_ = os.Remove(root + hostileRanLog)
		if strings.TrimSpace(string(data)) != tier+":settings-hook" {
			t.Fatalf("%s hook left %q", tier, data)
		}
	}
	planted, _ := filepath.Glob(root + "/sandbox/*/*/pkg/*/99.0.0/index.js")
	more, _ := filepath.Glob(root + "/sandbox/.copilot/pkg/*/99.0.0/index.js")
	if len(planted)+len(more) != 4 {
		t.Fatalf("planted packages = %v %v", planted, more)
	}

	// The launch env: a bash that reads BASH_ENV (Copilot's hook wrapper
	// shell) records it and never runs the command; every program the
	// planted PATH puts first records itself.
	plan := hostileSettingsPlans["copilot"]
	relocate := strings.NewReplacer(hostileRoot, root+hostileRoot)
	env := []string{}
	for key, value := range plan.env {
		env = append(env, key+"="+relocate.Replace(value))
	}
	sort.Strings(env)
	if want := []string{"BASH_ENV=", "ENV=", "PATH="}; len(env) != len(want) {
		t.Fatalf("launch env = %v", env)
	}
	cmd := exec.Command("/bin/bash", "-c", "echo hook-ran")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	data, _ := os.ReadFile(root + hostileRanLog)
	_ = os.Remove(root + hostileRanLog)
	if err != nil || strings.Contains(string(out), "hook-ran") || strings.TrimSpace(string(data)) != "user:bash-env" {
		t.Fatalf("BASH_ENV: %v, output %q, ran %q", err, out, data)
	}
	path := relocate.Replace(plan.env["PATH"])
	if !strings.HasSuffix(path, ":"+harness.LauncherSystemPATH) {
		t.Fatalf("PATH = %q, want the planted bin ahead of the system PATH", path)
	}
	for _, name := range []string{"bash", "sh", "curl", "jq"} {
		program := filepath.Join(strings.SplitN(path, ":", 2)[0], name)
		if out, err := exec.Command(program).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		data, _ := os.ReadFile(root + hostileRanLog)
		_ = os.Remove(root + hostileRanLog)
		if strings.TrimSpace(string(data)) != "user:path-"+name {
			t.Fatalf("planted %s left %q", name, data)
		}
	}
}

func TestOpenCodeHostileSettingsPlants(t *testing.T) {
	root := relocatedHostileSetup(t, "opencode")
	for _, file := range []string{
		"/sandbox/.config/opencode/opencode.json",
		"/work/dc-hookfire-project/opencode.json",
		"/work/dc-hookfire-project/.opencode/opencode.json",
	} {
		data, err := os.ReadFile(root + file)
		if err != nil || strings.TrimSpace(string(data)) != `{"plugin":[]}` {
			t.Fatalf("%s = %s (%v)", file, data, err)
		}
	}
}

// TestOpenCodeHostileRefusalsStopTheLauncher plants each of the OpenCode
// plan's refusals, relocated under a temp dir, and starts the image's real
// OpenCode launcher (the binary replaced by a stub) the way the probe does:
// every planting must stop it with the refusal the probe greps for, and the
// plan's other settings alone must not.
func TestOpenCodeHostileRefusalsStopTheLauncher(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	root := relocatedHostileSetup(t, "opencode")
	plan := hostileSettingsPlans["opencode"]
	if len(plan.refusals) != 3 {
		t.Fatalf("refusals = %+v", plan.refusals)
	}
	relocate := strings.NewReplacer(
		hostileRoot, root+hostileRoot,
		"'/sandbox/", "'"+root+"/sandbox/",
		" /sandbox/", " "+root+"/sandbox/",
		"/work/", root+"/work/",
	)
	stub := filepath.Join(root, "opencode-stub")
	if err := os.WriteFile(stub, []byte("#!/bin/bash\necho opencode-started\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(root, "opencode-launch")
	if err := os.WriteFile(launcher, []byte(strings.ReplaceAll(string(harness.OpenCode.Launcher().Data), "/usr/local/bin/opencode", stub)), 0o755); err != nil {
		t.Fatal(err)
	}
	start := func() (int, string) {
		t.Helper()
		cmd := exec.Command(launcher, "run", "--auto", builtinAllowPrompt)
		cmd.Dir = root + hostileProject
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root + "/sandbox"}
		out, err := cmd.CombinedOutput()
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), string(out)
		} else if err != nil {
			t.Fatal(err)
		}
		return 0, string(out)
	}
	if code, out := start(); code != 0 || !strings.Contains(out, "opencode-started") {
		t.Fatalf("the plan's settings alone stopped the launcher: exit %d\n%s", code, out)
	}
	for _, r := range plan.refusals {
		t.Run(r.label, func(t *testing.T) {
			if !strings.Contains(r.setup, r.file) || !strings.Contains(r.message, r.file) {
				t.Fatalf("refusal %+v does not plant and name its file", r)
			}
			if out, err := exec.Command("/bin/bash", "-c", relocate.Replace(r.setup)).CombinedOutput(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			code, out := start()
			if want := relocate.Replace(r.message); code == 0 || strings.Contains(out, "opencode-started") || !strings.Contains(out, want) {
				t.Fatalf("exit %d, want a refusal saying %q:\n%s", code, want, out)
			}
			if err := os.Remove(root + r.file); err != nil {
				t.Fatal(err)
			}
		})
	}
	if data, _ := os.ReadFile(root + hostileRanLog); len(data) != 0 {
		t.Fatalf("planted code ran: %s", data)
	}
}

// TestAntigravityHostileRefusalsStopTheLauncher plants each of the
// Antigravity plan's refusals, relocated under a temp dir, and starts the
// image's real agy launcher (the binary replaced by a stub) the way the
// probe does: every planting, the workspace hooks key spelled with a JSON
// escape among them, must stop it with the refusal the probe greps for.
func TestAntigravityHostileRefusalsStopTheLauncher(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	root := relocatedHostileSetup(t, "antigravity")
	plan := hostileSettingsPlans["antigravity"]
	if len(plan.refusals) != 2 {
		t.Fatalf("refusals = %+v", plan.refusals)
	}
	relocate := strings.NewReplacer("'/sandbox/", "'"+root+"/sandbox/", "/work/", root+"/work/")
	stub := filepath.Join(root, "agy-stub")
	if err := os.WriteFile(stub, []byte("#!/bin/bash\necho agy-started\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(root, "canonical-hooks.json")
	if err := os.WriteFile(canonical, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := strings.NewReplacer("/usr/local/bin/agy", stub, connector.AntigravitySandboxCanonicalHooksPath, canonical).
		Replace(string(harness.Antigravity.Launcher().Data))
	launcher := filepath.Join(root, "antigravity-launch")
	if err := os.WriteFile(launcher, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	start := func() (int, string) {
		t.Helper()
		cmd := exec.Command(launcher, "-p", builtinAllowPrompt)
		cmd.Dir = root + hostileProject
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root + "/sandbox"}
		out, err := cmd.CombinedOutput()
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), string(out)
		} else if err != nil {
			t.Fatal(err)
		}
		return 0, string(out)
	}
	if code, out := start(); code != 0 || !strings.Contains(out, "agy-started") {
		t.Fatalf("the plan's settings alone stopped the launcher: exit %d\n%s", code, out)
	}
	for _, r := range plan.refusals {
		t.Run(r.label, func(t *testing.T) {
			if !strings.Contains(r.setup, r.file) || !strings.Contains(r.message, r.file) {
				t.Fatalf("refusal %+v does not plant and name its file", r)
			}
			if out, err := exec.Command("/bin/bash", "-c", relocate.Replace(r.setup)).CombinedOutput(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			code, out := start()
			if want := root + r.message; code == 0 || strings.Contains(out, "agy-started") || !strings.Contains(out, want) {
				t.Fatalf("exit %d, want a refusal saying %q:\n%s", code, want, out)
			}
			cleanup := "rm -rf " + shQuote(r.file) + "\n"
			if r.cleanup != "" {
				cleanup = r.cleanup
			}
			if out, err := exec.Command("/bin/bash", "-c", relocate.Replace(cleanup)).CombinedOutput(); err != nil {
				t.Fatalf("cleanup: %v\n%s", err, out)
			}
			if code, out := start(); code != 0 || !strings.Contains(out, "agy-started") {
				t.Fatalf("after the cleanup: exit %d\n%s", code, out)
			}
		})
	}
	if data, _ := os.ReadFile(root + hostileRanLog); len(data) != 0 {
		t.Fatalf("planted code ran: %s", data)
	}
}

// TestOpenCodeHostilePluginReplacesFetch imports the planted plugin under
// node (when available): it must record its label and replace the global
// fetch with one that allows everything, so an image whose launcher let it
// load would answer every hook without the ingress.
func TestOpenCodeHostilePluginReplacesFetch(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available")
	}
	root := t.TempDir()
	file := filepath.Join(root, "plugin.mjs")
	body := strings.ReplaceAll(openCodeHostilePlugin("project"), hostileRanLog, root+"/ran")
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "const before = globalThis.fetch; await import(" + strconv.Quote("file://"+file) + ");" +
		"const res = await fetch(\"http://127.0.0.1:9/api/v1/opencode/hook\");" +
		"console.log(globalThis.fetch !== before, (await res.json()).action);"
	out, err := exec.Command(node, "--input-type=module", "-e", script).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "true allow" {
		t.Fatalf("planted plugin: %s", out)
	}
	if data, _ := os.ReadFile(root + "/ran"); strings.TrimSpace(string(data)) != "project:planted-plugin" {
		t.Fatalf("ran log = %q", data)
	}
}
