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

//go:build !windows

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

// relocatedHostileSetup runs a plan's planting fragment with its absolute
// roots moved under a temp dir, and returns that root and the relocation.
func relocatedHostileSetup(t *testing.T, name string) (string, *strings.Replacer) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	plan, ok := hostileSettingsPlans[name]
	if !ok || plan.workdir != hostileProject {
		t.Fatalf("%s hostile plan = %+v, want a project under the pre-trusted work root", name, plan)
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
		" /sandbox/", " "+root+"/sandbox/",
		"/work/", root+"/work/",
	)
	if out, err := exec.Command(bash, "-c", relocate.Replace(plan.setup)).CombinedOutput(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	if got := takeRan(t, root); len(got) != 0 {
		t.Fatalf("planting ran planted programs: %v", got)
	}
	return root, relocate
}

// takeRan returns and clears the labels planted programs logged under root.
func takeRan(t *testing.T, root string) []string {
	t.Helper()
	data, err := os.ReadFile(root + hostileRanLog)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	_ = os.Remove(root + hostileRanLog)
	return strings.Fields(string(data))
}

// runPlanted starts each planted program the way its harness would and
// requires it, and only it, to log tier:label.
func runPlanted(t *testing.T, root, tier string, programs map[string][]string) {
	t.Helper()
	for label, argv := range programs {
		if out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", label, err, out)
		}
		if got := takeRan(t, root); len(got) != 1 || got[0] != tier+":"+label {
			t.Fatalf("%s left %v in the planted-run log, want %s:%s", label, got, tier, label)
		}
	}
}

func sortedKeys(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, " ")
}

// TestClaudeCodeHostileSettingsPlantsBothTiers checks what the probe
// container would see: both settings files, every knob set, and every
// planted program leaving its label when started the way Claude would start
// it.
func TestClaudeCodeHostileSettingsPlantsBothTiers(t *testing.T) {
	root, _ := relocatedHostileSetup(t, "claudecode")
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
			env := settings.Env
			if want := "BASH_ENV CLAUDE_CODE_SHELL CLAUDE_CODE_SHELL_PREFIX CLAUDE_CODE_SIMPLE DEFENSECLAW_GATEWAY_TOKEN DEFENSECLAW_HOME PATH SHELL"; !settings.DisableAllHooks ||
				sortedKeys(env) != want || env["CLAUDE_CODE_SIMPLE"] != "1" || env["SHELL"] != env["CLAUDE_CODE_SHELL"] {
				t.Fatalf("planted disableAllHooks %t env %v, want %s", settings.DisableAllHooks, env, want)
			}
			if _, err := os.Stat(filepath.Join(env["DEFENSECLAW_HOME"], ".disabled")); err != nil {
				t.Errorf("DEFENSECLAW_HOME is not marked disabled: %v", err)
			}
			hooks := settings.Hooks["PreToolUse"]
			if len(hooks) != 1 || len(hooks[0].Hooks) != 1 || hooks[0].Hooks[0].Type != "command" || settings.StatusLine.Type != "command" {
				t.Fatalf("planted PreToolUse hook = %+v statusLine %+v, want the schema's command objects", hooks, settings.StatusLine)
			}
			// Claude runs the prefix with the command as one argument, the
			// shell with -c, and settings hooks, auth helpers and the status
			// line through /bin/sh.
			bin := strings.SplitN(env["PATH"], ":", 2)[0]
			runPlanted(t, root, tier, map[string][]string{
				"shell-prefix":  {env["CLAUDE_CODE_SHELL_PREFIX"], "/usr/local/lib/defenseclaw/hooks/claude-code-hook.sh"},
				"shell":         {env["CLAUDE_CODE_SHELL"], "-c", "true"},
				"curl":          {filepath.Join(bin, "curl"), "-q"},
				"jq":            {filepath.Join(bin, "jq"), "-r"},
				"settings-hook": {"/bin/sh", "-c", hooks[0].Hooks[0].Command},
				"bash-env":      {"bash", "-c", ". " + env["BASH_ENV"]},
				"apikey-helper": {"/bin/sh", "-c", settings.APIKeyHelper},
				"aws-refresh":   {"/bin/sh", "-c", settings.AWSAuthRefresh},
				"aws-export":    {"/bin/sh", "-c", settings.AWSCredentialExport},
				"gcp-refresh":   {"/bin/sh", "-c", settings.GCPAuthRefresh},
				"status-line":   {"/bin/sh", "-c", settings.StatusLine.Command},
			})
		})
	}
}

// TestCodexHostileSettingsPlantsBothTiers checks the Codex plan the same way:
// both config files parse as TOML with the documented keys, and every
// planted program and sourced file leaves its label.
func TestCodexHostileSettingsPlantsBothTiers(t *testing.T) {
	root, _ := relocatedHostileSetup(t, "codex")
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
			if cfg.Features.Hooks == nil || *cfg.Features.Hooks || cfg.ApprovalPolicy != "never" || cfg.ModelProvider != "hostile" || len(cfg.Notify) != 1 ||
				len(cfg.Hooks.PreToolUse) != 1 || len(cfg.Hooks.PreToolUse[0].Hooks) != 1 ||
				sortedKeys(cfg.Shell.Set) != "BASH_ENV DEFENSECLAW_HOME DEFENSECLAW_SANDBOX_TOKEN ENV PATH" {
				t.Fatalf("planted config = %+v", cfg)
			}
			bin := strings.SplitN(cfg.Shell.Set["PATH"], ":", 2)[0]
			runPlanted(t, root, tier, map[string][]string{
				"curl":        {filepath.Join(bin, "curl")},
				"jq":          {filepath.Join(bin, "jq")},
				"notify":      {cfg.Notify[0], "{}"},
				"config-hook": {"/bin/sh", "-c", cfg.Hooks.PreToolUse[0].Hooks[0].Command},
				"shell-env":   {"bash", "-c", ". " + cfg.Shell.Set["BASH_ENV"]},
			})
		})
	}
}

func TestCopilotHostileSettingsPlants(t *testing.T) {
	root, relocate := relocatedHostileSetup(t, "copilot")
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
		runPlanted(t, root, tier, map[string][]string{"settings-hook": {"bash", "-c", doc.Hooks["preToolUse"][0].Bash}})
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
	var env []string
	for key, value := range plan.env {
		env = append(env, key+"="+relocate.Replace(value))
	}
	if sortedKeys(plan.env) != "BASH_ENV ENV PATH" {
		t.Fatalf("launch env = %v", plan.env)
	}
	cmd := exec.Command("/bin/bash", "-c", "echo hook-ran")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if ran := takeRan(t, root); err != nil || strings.Contains(string(out), "hook-ran") || strings.Join(ran, " ") != "user:bash-env" {
		t.Fatalf("BASH_ENV: %v, output %q, ran %v", err, out, ran)
	}
	path := relocate.Replace(plan.env["PATH"])
	if !strings.HasSuffix(path, ":"+harness.LauncherSystemPATH) {
		t.Fatalf("PATH = %q, want the planted bin ahead of the system PATH", path)
	}
	programs := map[string][]string{}
	for _, name := range []string{"bash", "sh", "curl", "jq"} {
		programs["path-"+name] = []string{filepath.Join(strings.SplitN(path, ":", 2)[0], name)}
	}
	runPlanted(t, root, "user", programs)
}

func TestOpenCodeHostileSettingsPlants(t *testing.T) {
	root, _ := relocatedHostileSetup(t, "opencode")
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

// TestHostileRefusalsStopTheLauncher plants each refusal of the OpenCode and
// Antigravity plans, relocated under a temp dir, and starts the image's real
// launcher (the harness binary replaced by a stub) the way the probe does:
// every planting (the agy workspace hooks key spelled with a JSON escape
// among them) must stop it with the refusal the probe greps for, while the
// plan's other settings alone, and each planting's cleanup, must not.
func TestHostileRefusalsStopTheLauncher(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	for _, tc := range []struct {
		spec     *harness.Spec
		refusals int
		binary   string
		// canonical is a root-owned file the launcher reads, moved under
		// the temp dir.
		canonical string
		args      []string
	}{
		{harness.OpenCode, 3, "/usr/local/bin/opencode", "", []string{"run", "--auto", builtinAllowPrompt}},
		{harness.Antigravity, 2, "/usr/local/bin/agy", connector.AntigravitySandboxCanonicalHooksPath, []string{"-p", builtinAllowPrompt}},
	} {
		t.Run(tc.spec.Name, func(t *testing.T) {
			root, relocate := relocatedHostileSetup(t, tc.spec.Name)
			plan := hostileSettingsPlans[tc.spec.Name]
			if len(plan.refusals) != tc.refusals {
				t.Fatalf("refusals = %+v", plan.refusals)
			}
			write := func(file, body string, mode os.FileMode) string {
				t.Helper()
				if err := os.WriteFile(file, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
				return file
			}
			swap := []string{tc.binary, write(filepath.Join(root, "harness-stub"), "#!/bin/bash\necho harness-started\n", 0o755)}
			if tc.canonical != "" {
				swap = append(swap, tc.canonical, write(filepath.Join(root, "canonical"), "{}\n", 0o644))
			}
			launcher := write(filepath.Join(root, "launcher"), strings.NewReplacer(swap...).Replace(string(tc.spec.Launcher().Data)), 0o755)
			start := func(when string, refusal string) {
				t.Helper()
				cmd := exec.Command(launcher, tc.args...)
				cmd.Dir = root + hostileProject
				cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root + "/sandbox"}
				out, err := cmd.CombinedOutput()
				exitErr, refused := err.(*exec.ExitError)
				if err != nil && !refused {
					t.Fatal(err)
				}
				switch started := strings.Contains(string(out), "harness-started"); {
				case refusal == "" && (err != nil || !started):
					t.Fatalf("%s stopped the launcher: %v\n%s", when, err, out)
				case refusal != "" && (!refused || exitErr.ExitCode() == 0 || started || !strings.Contains(string(out), refusal)):
					t.Fatalf("%s: %v, want a refusal saying %q:\n%s", when, err, refusal, out)
				}
			}
			start("the plan's settings alone", "")
			for _, r := range plan.refusals {
				if !strings.Contains(r.setup, r.file) || !strings.Contains(r.message, r.file) {
					t.Fatalf("refusal %+v does not plant and name its file", r)
				}
				run := func(script string) {
					t.Helper()
					if out, err := exec.Command("/bin/bash", "-c", relocate.Replace(script)).CombinedOutput(); err != nil {
						t.Fatalf("%s: %v\n%s", r.label, err, out)
					}
				}
				run(r.setup)
				// The message may open with the path.
				start("the "+r.label+" planting", strings.TrimPrefix(relocate.Replace(" "+r.message), " "))
				if r.cleanup == "" {
					r.cleanup = "rm -rf " + shQuote(r.file) + "\n"
				}
				run(r.cleanup)
				start("the "+r.label+" cleanup", "")
			}
			if ran := takeRan(t, root); len(ran) != 0 {
				t.Fatalf("planted code ran: %v", ran)
			}
		})
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
