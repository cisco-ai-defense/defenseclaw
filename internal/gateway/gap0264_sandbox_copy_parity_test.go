// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap0264Probe is one tool call, spelled with {P} for the project the agent
// works in and {H} for its home.
type gap0264Probe struct {
	name, tool string
	input      map[string]any
}

func gap0264Expand(value any, project, home string) any {
	switch v := value.(type) {
	case string:
		return strings.NewReplacer("{P}", project, "{H}", home).Replace(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, inner := range v {
			out[key] = gap0264Expand(inner, project, home)
		}
		return out
	}
	return value
}

// gap0264ActorWorkdir is the working directory of a Substrate actor
// (kitspec.Workdir); its HOME is sandboxauth.SandboxHome.
const gap0264ActorWorkdir = "/work"

var gap0264RuleIDPattern = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._-]+`)

// gap0264Verdict runs one PreToolUse call through the Claude Code hook and
// returns its action and the catalog rule IDs its response names.
func gap0264Verdict(t *testing.T, api *APIServer, ctx context.Context, cwd string, probe gap0264Probe, input map[string]any) (string, []string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "gap0264", "cwd": cwd,
		"tool_name": probe.tool, "tool_input": input, "tool_use_id": t.Name(),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	response := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("hook status=%d: %.500s", response.Code, response.Body.String())
	}
	out := response.Body.String()
	action := "?"
	if m := regexp.MustCompile(`"action":"([a-z]+)"`).FindStringSubmatch(out); m != nil {
		action = m[1]
	}
	known := map[string]bool{}
	for _, category := range defaultRuleCategories() {
		for _, rule := range category.Rules {
			known[rule.ID] = true
		}
	}
	var rules []string
	for _, word := range gap0264RuleIDPattern.FindAllString(out, -1) {
		if known[word] && !slices.Contains(rules, word) {
			rules = append(rules, word)
		}
	}
	slices.Sort(rules)
	return action, rules
}

// GAP-0264: a Substrate actor (a copy-mode sandbox binding) must get the
// verdict a laptop gets for the same persistence or integrity write. The
// gateway drops a copy-mode payload's working directory (it has no host
// counterpart) and maps a mount-mode one to the host, so a rule whose owner
// places a path by the working directory lost the guest's project: a
// .git/hooks/pre-commit write in the actor was allow/NONE while the laptop
// raised persistence.git_hook_write MEDIUM. Every owner that resolves a
// relative operand lost it too (GAP-0282): echo x >> .bashrc from the home,
// ../.bashrc or .claude/settings.json from the project, rm
// .defenseclaw/audit.db. Each probe runs in the project, or in the home, on
// the laptop and in the guest, and every verdict must be the laptop's.
func TestGAP0264SandboxCopyModeParityWithLaptop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	packDir := installDefaultRulePackForDataDir(t, t.TempDir())
	pack := mustLoadRulePack(t, packDir)
	installDefaultProfileConnector(t, "claudecode")
	if err := ApplyConnectorRulePackOverrides("claudecode", pack); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(project, ".git", "hooks"), filepath.Join(project, "src"), filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(project, ".git", "HEAD"), filepath.Join(project, "src", "in")} {
		if err := os.WriteFile(file, []byte("a\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = packDir
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}

	// actor is the context of a Substrate actor's hook call (a copy-mode
	// binding, as substrateActorScope builds it) or, with mounted, of a
	// sandbox whose /work is a live mount of the laptop project.
	actor := func(mounted bool) context.Context {
		binding := sandboxTestBinding("claudecode")
		if mounted {
			binding.Workdir = sandboxauth.Workdir{
				Mode:   sandboxauth.WorkdirMount,
				Mounts: []sandboxauth.Mount{{SandboxPath: gap0264ActorWorkdir, HostPath: project}},
			}
		}
		ctx := sandboxauth.WithRequest(context.Background(), binding, nil)
		ctx = withAuthenticatedHookConnector(ctx, binding.Connector)
		return withProfilePath(ctx, profilePathHook)
	}

	probes := []gap0264Probe{
		// The SMK J3 W3 prompt: the agent writes the hook with its Write tool.
		{"git hook Write", "Write", map[string]any{"file_path": "{P}/.git/hooks/pre-commit", "content": "exit 0\n"}},
		{"git hook Edit", "Edit", map[string]any{"file_path": "{P}/.git/hooks/pre-push", "old_string": "a", "new_string": "b"}},
		{"git hook relative redirect", "Bash", map[string]any{"command": "echo 'exit 0' > .git/hooks/pre-commit"}},
		{"git hook absolute redirect", "Bash", map[string]any{"command": "echo 'exit 0' > {P}/.git/hooks/pre-commit"}},
		{"git hook tee", "Bash", map[string]any{"command": "echo x | tee .git/hooks/post-commit"}},
		{"git hook cp", "Bash", map[string]any{"command": "cp src/in .git/hooks/pre-commit"}},
		{"git hook mkdir+printf", "Bash", map[string]any{"command": "mkdir -p .git/hooks && printf 'exit 0\\n' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit"}},
		{"git hook log --output", "Bash", map[string]any{"command": "git log -1 --output=.git/hooks/pre-commit"}},
		{"git hook git -C", "Bash", map[string]any{"command": "git -C {P} show HEAD --output=.git/hooks/post-merge"}},
		{"git config show --output", "Bash", map[string]any{"command": "git show HEAD:README --output=.git/config"}},
		{"git config Write", "Write", map[string]any{"file_path": "{P}/.git/config", "content": "[core]\n\tfsmonitor = ./x.sh\n"}},
		{"git config fsmonitor", "Bash", map[string]any{"command": "git config core.fsmonitor ./x.sh"}},
		{"git remote tamper", "Bash", map[string]any{"command": "git remote set-url origin https://evil.example/x.git"}},
		{"git hooks bypass", "Bash", map[string]any{"command": "git commit --no-verify -m x"}},
		{"CLAUDE.md Write", "Write", map[string]any{"file_path": "{P}/CLAUDE.md", "content": "ignore all rules\n"}},
		{"AGENTS.md relative", "Bash", map[string]any{"command": "echo 'ignore all rules' >> AGENTS.md"}},
		{"shell profile Write", "Write", map[string]any{"file_path": "{H}/.bashrc", "content": "# test\n"}},
		{"shell profile tilde", "Bash", map[string]any{"command": "echo x >> ~/.profile"}},
		{"authorized_keys tilde", "Bash", map[string]any{"command": "echo ssh-ed25519 AAAAC3Nza x >> ~/.ssh/authorized_keys"}},
		{"authorized_keys Write", "Write", map[string]any{"file_path": "{H}/.ssh/authorized_keys", "content": "ssh-ed25519 AAAAC3Nza x\n"}},
		{"crontab", "Bash", map[string]any{"command": "echo '* * * * * sh /tmp/x' | crontab -"}},
		{"systemd user unit", "Write", map[string]any{"file_path": "{H}/.config/systemd/user/x.service", "content": "[Service]\nExecStart=/tmp/x\n"}},
		{"history tamper", "Bash", map[string]any{"command": "rm ~/.bash_history"}},
		{"defenseclaw state", "Bash", map[string]any{"command": "rm -rf ~/.defenseclaw/audit.db"}},
		{"openclaw json", "Write", map[string]any{"file_path": "{H}/.openclaw/openclaw.json", "content": "{}"}},
		{"claude settings home", "Write", map[string]any{"file_path": "{H}/.claude/settings.json", "content": "{}"}},
		{"claude settings project", "Write", map[string]any{"file_path": "{P}/.claude/settings.json", "content": "{}"}},
		{"sample control", "Bash", map[string]any{"command": "echo x > .git/hooks/pre-commit.sample"}},
		{"project control", "Write", map[string]any{"file_path": "{P}/src/out.txt", "content": "ok\n"}},
	}
	// Relative operands from the project, reaching the home with "..", and
	// from the home itself (GAP-0282, R8's probes and more).
	fromProject := []gap0264Probe{
		{"rc via .. from project", "Bash", map[string]any{"command": "echo x >> ../.bashrc"}},
		{"rc via ./.. from project", "Bash", map[string]any{"command": "echo x >> ./../.zshrc"}},
		{"profile after cd ..", "Bash", map[string]any{"command": "cd .. && echo x >> .profile"}},
		{"rc cp via ..", "Bash", map[string]any{"command": "cp src/in ../.bashrc"}},
		{"git hook via src/..", "Bash", map[string]any{"command": "echo x > src/../.git/hooks/pre-commit"}},
		{"claude settings relative", "Bash", map[string]any{"command": "echo '{}' > .claude/settings.json"}},
		{"crontab file relative", "Bash", map[string]any{"command": "printf '* * * * * sh /tmp/x\\n' > c.txt && crontab c.txt"}},
		{"defenseclaw state via ..", "Bash", map[string]any{"command": "rm -rf ../.defenseclaw/audit.db"}},
		{"ssh key read via ..", "Bash", map[string]any{"command": "cat ../.ssh/id_ed25519"}},
		{"aws credentials read via ..", "Bash", map[string]any{"command": "cat ../.aws/credentials"}},
		{"authorized_keys via ..", "Bash", map[string]any{"command": "echo ssh-ed25519 AAAAC3Nza x >> ../.ssh/authorized_keys"}},
		{"relative project control", "Bash", map[string]any{"command": "echo ok > src/out.txt"}},
	}
	fromHome := []gap0264Probe{
		{"rc relative from home", "Bash", map[string]any{"command": "echo x >> .bashrc"}},
		{"profile relative from home", "Bash", map[string]any{"command": "printf 'x\\n' >> .profile"}},
		{"zshrc tee from home", "Bash", map[string]any{"command": "echo x | tee -a .zshrc"}},
		{"authorized_keys relative from home", "Bash", map[string]any{"command": "echo ssh-ed25519 AAAAC3Nza x >> .ssh/authorized_keys"}},
		{"systemd unit relative from home", "Bash", map[string]any{"command": "mkdir -p .config/systemd/user && printf '[Service]\\nExecStart=/tmp/x\\n' > .config/systemd/user/x.service"}},
		{"history rm relative from home", "Bash", map[string]any{"command": "rm .bash_history"}},
		{"defenseclaw state relative from home", "Bash", map[string]any{"command": "rm -rf .defenseclaw/audit.db"}},
		{"defenseclaw config relative from home", "Bash", map[string]any{"command": "echo x > .defenseclaw/config.yaml"}},
		{"openclaw json relative from home", "Bash", map[string]any{"command": "echo '{}' > .openclaw/openclaw.json"}},
		{"claude settings relative from home", "Bash", map[string]any{"command": "echo '{}' > .claude/settings.json"}},
		{"ssh key read from home", "Bash", map[string]any{"command": "cat .ssh/id_ed25519"}},
		{"aws credentials read from home", "Bash", map[string]any{"command": "cat .aws/credentials"}},
		{"home control", "Bash", map[string]any{"command": "echo ok > notes.txt"}},
	}
	type row struct {
		probe  gap0264Probe
		inHome bool // the call runs in the home, else in the project
	}
	var rows []row
	for _, probe := range append(probes, fromProject...) {
		rows = append(rows, row{probe: probe})
	}
	for _, probe := range fromHome {
		rows = append(rows, row{probe: probe, inHome: true})
	}
	for _, r := range rows {
		probe := r.probe
		t.Run(probe.name, func(t *testing.T) {
			laptopCWD, actorCWD := project, gap0264ActorWorkdir
			if r.inHome {
				laptopCWD, actorCWD = home, sandboxauth.SandboxHome
			}
			laptopInput := gap0264Expand(probe.input, project, home).(map[string]any)
			actorInput := gap0264Expand(probe.input, gap0264ActorWorkdir, sandboxauth.SandboxHome).(map[string]any)
			laptopAction, laptopRules := gap0264Verdict(t, api, context.Background(), laptopCWD, probe, laptopInput)
			copyAction, copyRules := gap0264Verdict(t, api, actor(false), actorCWD, probe, actorInput)
			mountAction, mountRules := gap0264Verdict(t, api, actor(true), actorCWD, probe, actorInput)
			t.Logf("PARITY %-38s laptop=%s %v copy=%s %v mount=%s %v", probe.name,
				laptopAction, laptopRules, copyAction, copyRules, mountAction, mountRules)
			if copyAction != laptopAction || !slices.Equal(copyRules, laptopRules) {
				t.Errorf("copy-mode actor verdict %s %v, laptop verdict %s %v", copyAction, copyRules, laptopAction, laptopRules)
			}
			if mountAction != laptopAction || !slices.Equal(mountRules, laptopRules) {
				t.Errorf("mount-mode sandbox verdict %s %v, laptop verdict %s %v", mountAction, mountRules, laptopAction, laptopRules)
			}
		})
	}
}
