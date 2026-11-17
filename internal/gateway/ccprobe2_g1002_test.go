// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// s7-probe2 old-API probe for rel-1-0-10:GAP-1002: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha f1ccff5b7a lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"context"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

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
func TestCCP2G1002_GAP0264SandboxCopyModeParityWithLaptop(t *testing.T) {
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
		{"rc via {U} from project", "Bash", map[string]any{"command": "echo x >> {U}/.bashrc"}},
		{"rc via ./{U} from project", "Bash", map[string]any{"command": "echo x >> ./{U}/.zshrc"}},
		{"profile after cd {U}", "Bash", map[string]any{"command": "cd {U} && echo x >> .profile"}},
		{"rc cp via {U}", "Bash", map[string]any{"command": "cp src/in {U}/.bashrc"}},
		{"git hook via src/..", "Bash", map[string]any{"command": "echo x > src/../.git/hooks/pre-commit"}},
		// A project hook file the pull-back carries into the laptop project
		// (sandboxAgentHookConfigFindings).
		{"claude settings relative", "Bash", map[string]any{"command": "echo '{}' > .claude/settings.json"}},
		{"claude settings.local relative", "Bash", map[string]any{"command": "echo '{}' > .claude/settings.local.json"}},
		{"claude settings via src/..", "Bash", map[string]any{"command": "cp src/in src/../.claude/settings.json"}},
		{"claude settings absolute", "Bash", map[string]any{"command": "echo '{}' > {P}/.claude/settings.json"}},
		{"claude settings home via {U}", "Bash", map[string]any{"command": "echo '{}' > {U}/.claude/settings.json"}},
		{"codex config relative", "Bash", map[string]any{"command": "printf 'x' >> .codex/config.toml"}},
		{"claude settings rm", "Bash", map[string]any{"command": "rm .claude/settings.json"}},
		{"claude settings disable Write", "Write", map[string]any{"file_path": "{P}/.claude/settings.json", "content": "{\"disableAllHooks\": true}"}},
		{"claude folder control", "Bash", map[string]any{"command": "echo ok > .claude/notes.txt"}},
		{"crontab file relative", "Bash", map[string]any{"command": "printf '* * * * * sh /tmp/x\\n' > c.txt && crontab c.txt"}},
		{"defenseclaw state via {U}", "Bash", map[string]any{"command": "rm -rf {U}/.defenseclaw/audit.db"}},
		{"ssh key read via {U}", "Bash", map[string]any{"command": "cat {U}/.ssh/id_ed25519"}},
		{"aws credentials read via {U}", "Bash", map[string]any{"command": "cat {U}/.aws/credentials"}},
		{"authorized_keys via {U}", "Bash", map[string]any{"command": "echo ssh-ed25519 AAAAC3Nza x >> {U}/.ssh/authorized_keys"}},
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
