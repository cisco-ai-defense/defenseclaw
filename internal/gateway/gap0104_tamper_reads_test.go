// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap0104Row is one shell call on DefenseClaw state or an agent hook config
// and its verdict in the default and the strict pack.
type gap0104Row struct {
	name, command    string
	defaults, strict string
	rule             string
}

func newGAP0104Home(t *testing.T) gap0048Home {
	t.Helper()
	h := newGAP0048Home(t)
	for _, name := range []string{".defenseclaw/config.yaml", ".defenseclaw/hooks/codex-hook.sh"} {
		path := filepath.Join(h.home, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// gap0104TamperRules are the self-protection rules and the world-writable
// mode rule: an allowed read names none of them.
var gap0104TamperRules = []string{
	"tamper.detector_state_write", agentHookConfigWriteRuleID, agentHookConfigDisableRuleID, "CMD-CHMOD-WORLD",
}

// rel-1-0-10:GAP-0104: the self-protection rules fired on read-only shell
// calls that name DefenseClaw state or an agent hook config (hashes, stat,
// cmp, copies out, archive creation, rsync dry runs, read-only find -exec
// bodies) whenever the same call wrote anything anywhere. A read is allowed;
// a write, append, truncate, removal, move, link, mode change or redirect
// into the file still alerts (hook config, default pack) or blocks (state in
// every pack; hook config in strict).
func TestGAP0104ShellReadsOfProtectedFilesStayAllowed(t *testing.T) {
	h := newGAP0104Home(t)
	settings := filepath.ToSlash(h.userSettings)
	codex := filepath.ToSlash(filepath.Join(h.home, ".codex", "config.toml"))
	hookWrite, state := agentHookConfigWriteRuleID, "tamper.detector_state_write"
	rows := []gap0104Row{
		// Reads.
		{name: "hashes redirected to a log", command: `sha256sum ~/.claude/settings.json ~/.codex/config.toml ~/.defenseclaw/config.yaml > /tmp/gap0104-hashes.txt`},
		{name: "sudo hash then an unrelated write", command: `sudo -u testuser -H shasum -a 256 ~/.defenseclaw/config.yaml ~/.codex/config.toml; echo done > /tmp/gap0104-log`, strict: "alert-or-allow"},
		{name: "stat into evidence", command: `stat -c '%a %U:%G %n' ~/.codex/config.toml ~/.cursor/hooks.json > /tmp/gap0104-stat.raw`},
		{name: "cmp then a marker", command: `cmp -s /tmp/gap0104-before.json ~/.claude/settings.json && echo SAME > /tmp/gap0104-cmp`},
		{name: "cp out into a backup", command: `mkdir -p /tmp/gap0104-bak; cp -p ~/.claude/settings.json /tmp/gap0104-bak/settings.json; cp -p ~/.codex/config.toml /tmp/gap0104-bak/config.toml`},
		{name: "sudo cp out of state", command: `sudo mkdir -p /var/tmp/gap0104; sudo cp ~/.defenseclaw/config.yaml /var/tmp/gap0104/config.yaml; sudo chmod 600 /var/tmp/gap0104/*`, strict: "alert-or-allow"},
		{name: "tar create from configs", command: `s=/tmp/gap0104-bak; tar -C ~ -cpf "$s/pre.tar" .defenseclaw/config.yaml .claude/settings.json .codex/config.toml; chmod 600 "$s/pre.tar"`},
		{name: "tar extract to stdout", command: `tar -xOf /tmp/gap0104.tar .codex/config.toml | sha256sum`},
		{name: "tar list", command: `tar tf /tmp/gap0104.tar .codex/config.toml > /tmp/gap0104-list`},
		{name: "sudo rsync dry run onto hooks", command: `sudo rsync -anrc --delete /tmp/gap0104-src/ ~/.defenseclaw/hooks/`, strict: "alert-or-allow"},
		{name: "rsync dry run onto state root", command: `rsync -naci --delete /tmp/gap0104-src/ ~/.defenseclaw/ | head -70 > /tmp/gap0104-diff.raw`},
		{name: "rsync dry-run long option", command: `rsync -a --dry-run /tmp/gap0104-src/ ~/.defenseclaw/`},
		{name: "hashing loop into a log", command: `for p in .claude/settings.json .codex/config.toml; do shasum -a 256 ~/$p; done >> /tmp/gap0104-loop.txt`},
		{name: "find exec read-only shell body", command: `find ~/.defenseclaw/hooks -type f -exec sh -c 'for f do printf "%s " "$f"; sha256sum "$f"; done' sh {} +`},
		{name: "find exec read-only python", command: `find ~/.defenseclaw -name config.yaml -exec python3 -c 'import sys; print(open(sys.argv[1]).read())' {} \;`},
		{name: "sudo sh -c reads", command: `sudo -n sh -c "shasum -a 256 ~/.codex/config.toml; ls -ld ~/.codex/config.toml" > /tmp/gap0104-sh.raw`, strict: "alert-or-allow"},
		{name: "sudo -iu login shell doctor and hashes", command: `sudo -iu testuser sh -lc "defenseclaw doctor; sha256sum ~/.claude/settings.json ~/.codex/config.toml" > /tmp/gap0104-doctor.raw`, strict: "alert-or-allow"},
		{name: "python heredoc read", command: "python3 - <<'PY'\nimport json\nfrom pathlib import Path\nprint(json.loads(Path('" + settings + "').read_text()).get('hooks'))\nPY\necho ok > /tmp/gap0104-py"},
		{name: "python -c read piped", command: `python3 -c 'import json; print(json.load(open("` + settings + `")))' | head`},
		{name: "doctor into a file", command: `defenseclaw doctor > /tmp/gap0104-doctor.txt 2>&1`},
		{name: "diff of a config into a file", command: `diff <(cat ~/.codex/config.toml) /tmp/gap0104-bak/config.toml > /tmp/gap0104-diff.txt`},
		// Writes of an agent hook config.
		{name: "hash then redirect into settings", command: `sha256sum ~/.codex/config.toml; echo '{}' > ~/.claude/settings.json`, defaults: "alert", strict: "block", rule: hookWrite},
		{name: "cp into codex config", command: `cp /tmp/gap0104-bak/config.toml ~/.codex/config.toml && sha256sum ~/.codex/config.toml`, defaults: "alert", strict: "block", rule: hookWrite},
		{name: "tee append into codex config", command: `echo x | tee -a ~/.codex/config.toml > /dev/null`, defaults: "alert", strict: "block", rule: hookWrite},
		{name: "mv codex config away", command: `mv ~/.codex/config.toml /tmp/gap0104-moved.toml`, defaults: "alert", strict: "block", rule: hookWrite},
		{name: "ln over settings", command: `ln -sf /dev/null ~/.claude/settings.json`, defaults: "alert", strict: "block", rule: hookWrite},
		{name: "chmod settings world writable", command: `chmod 666 ~/.claude/settings.json`, defaults: "alert", strict: "block", rule: hookWrite},
		{name: "sudo sh -c redirect into settings", command: `sudo -n sh -c "printf '{}' > ~/.claude/settings.json"`, defaults: "alert", strict: "block", rule: hookWrite},
		{name: "loop writes its item", command: `for p in ~/.claude/settings.json; do cp /dev/null "$p"; done`, defaults: "alert", strict: "block", rule: hookWrite},
		{name: "python heredoc writes codex config", command: "python3 - <<'PY'\nopen('" + codex + "', 'w').write('')\nPY", defaults: "alert", strict: "block", rule: hookWrite},
		{name: "rsync onto codex config", command: `rsync -a /tmp/gap0104-src/config.toml ~/.codex/config.toml`, defaults: "alert", strict: "block", rule: hookWrite},
		{name: "tar create into a config", command: `tar -cf ~/.codex/config.toml /tmp/gap0104-src`, defaults: "alert", strict: "block", rule: hookWrite},
		// Writes of DefenseClaw state.
		{name: "hash then redirect into state", command: `sha256sum ~/.defenseclaw/config.yaml; echo x > ~/.defenseclaw/config.yaml`, defaults: "block", strict: "block", rule: state},
		{name: "cp into a hook script", command: `cp /tmp/gap0104-x ~/.defenseclaw/hooks/codex-hook.sh`, defaults: "block", strict: "block", rule: state},
		{name: "rsync with delete onto hooks", command: `rsync -a --delete /tmp/gap0104-src/ ~/.defenseclaw/hooks/`, defaults: "block", strict: "block", rule: state},
		{name: "sudo rsync with delete onto hooks", command: `sudo rsync -a --delete /tmp/gap0104-src/ ~/.defenseclaw/hooks/`, defaults: "block", strict: "block", rule: state},
		{name: "rm state", command: `rm -f ~/.defenseclaw/config.yaml`, defaults: "block", strict: "block", rule: state},
		{name: "chmod state", command: `chmod 600 ~/.defenseclaw/config.yaml`, defaults: "block", strict: "block", rule: state},
		{name: "mv state away", command: `mv ~/.defenseclaw/config.yaml /tmp/gap0104-c.yaml`, defaults: "block", strict: "block", rule: state},
		{name: "ln over state", command: `ln -sf /tmp/gap0104-evil ~/.defenseclaw/config.yaml`, defaults: "block", strict: "block", rule: state},
		{name: "find exec shell body truncates hooks", command: `find ~/.defenseclaw/hooks -type f -exec sh -c 'for f do : > "$f"; done' sh {} +`, defaults: "block", strict: "block", rule: state},
		{name: "find exec python writes state", command: `find ~/.defenseclaw -name config.yaml -exec python3 -c 'import sys; open(sys.argv[1], "w").write("")' {} \;`, defaults: "block", strict: "block", rule: state},
	}
	for _, profile := range []string{"default", "strict"} {
		t.Run(profile, func(t *testing.T) {
			judge := newHookConfigJudge(t, "claudecode", profile)
			for _, row := range rows {
				want := row.defaults
				if profile == "strict" {
					want = row.strict
				}
				if want == "" {
					want = "allow"
				}
				t.Run(row.name, func(t *testing.T) {
					t.Parallel()
					got := judge(h.project, false, "Bash", map[string]any{"command": row.command})
					// A sudo read alerts on CMD-SUDO (LOW) in strict: not a
					// self-protection finding.
					action := hookConfigAction(got)
					if want == "alert-or-allow" && (action == "alert" || action == "allow") {
						want = action
					}
					if action != want {
						t.Fatalf("%s %q: action %q, want %q: %.900s", profile, row.command, action, want, got)
					}
					if row.rule != "" && !strings.Contains(got, row.rule) {
						t.Fatalf("%s %q: want rule %s: %.900s", profile, row.command, row.rule, got)
					}
					if row.rule == "" {
						for _, rule := range gap0104TamperRules {
							if strings.Contains(got, rule) {
								t.Fatalf("%s %q: a read names %s: %.900s", profile, row.command, rule, got)
							}
						}
					}
				})
			}
		})
	}
}

// A state write still blocks in observe mode (the one finding observe mode
// enforces); a read of the same file stays allowed there too.
func TestGAP0104StateWriteBlocksInObserveMode(t *testing.T) {
	h := newGAP0104Home(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "claudecode"
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	handler := api.handleAgentHook("claudecode")
	judge := func(command string) string {
		payload, _ := json.Marshal(map[string]any{"session_id": "gap0104", "hook_event_name": "PreToolUse",
			"tool_name": "Bash", "cwd": h.project, "tool_input": map[string]any{"command": command}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		if header := hookpaths.ResolveConnector("claudecode", "", "PreToolUse", payload); header != "" {
			req.Header.Set(hookpaths.Header, header)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	for command, want := range map[string]string{
		`sha256sum ~/.defenseclaw/config.yaml; echo x > ~/.defenseclaw/config.yaml`: "block",
		`sudo rsync -a --delete /tmp/gap0104-src/ ~/.defenseclaw/hooks/`:            "block",
		`sudo rsync -anrc --delete /tmp/gap0104-src/ ~/.defenseclaw/hooks/`:         "allow",
		`sha256sum ~/.defenseclaw/config.yaml > /tmp/gap0104-hashes.txt`:            "allow",
	} {
		if got := judge(command); hookConfigAction(got) != want {
			t.Errorf("observe %q: action %q, want %q: %.700s", command, hookConfigAction(got), want, got)
		}
	}
}

// The PowerShell spellings: reads of state and hook configs (Get-FileHash,
// Get-Content, Copy-Item out, Compress-Archive from them, Test-Path) are not
// state writes; Set-Content, Copy-Item into, Remove-Item, Move-Item and a
// link onto state are.
func TestGAP0104PowerShellReadsAndWritesOfState(t *testing.T) {
	const connectorName = "gap0104-ps"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, value := range []string{"C:/Users/Alice/.defenseclaw", "C:/Users/Alice/.defenseclaw/config.yaml", "C:/Users/Alice/.defenseclaw/hooks"} {
		resolved[value] = value
	}
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`Get-FileHash $HOME\.defenseclaw\config.yaml, $HOME\.claude\settings.json, $HOME\.codex\config.toml | Out-File C:\Temp\gap0104-hashes.txt`, false},
		{`Get-Content $HOME\.defenseclaw\config.yaml | Out-File C:\Temp\gap0104-config.txt`, false},
		{`Copy-Item $HOME\.defenseclaw\config.yaml C:\Temp\gap0104-config.yaml`, false},
		{`Copy-Item -Path $HOME\.codex\config.toml -Destination C:\Temp\gap0104-config.toml`, false},
		{`Compress-Archive -Path $HOME\.defenseclaw\config.yaml -DestinationPath C:\Temp\gap0104-pre.zip`, false},
		{`Test-Path $HOME\.defenseclaw\config.yaml; Get-Item $HOME\.defenseclaw\hooks | Select-Object FullName`, false},
		{`Get-ChildItem $HOME\.defenseclaw\hooks | Get-FileHash | Out-File C:\Temp\gap0104-hooks.txt`, false},
		{`Set-Content $HOME\.defenseclaw\config.yaml ''`, true},
		{`Get-FileHash $HOME\.defenseclaw\config.yaml; Set-Content $HOME\.defenseclaw\config.yaml x`, true},
		{`Copy-Item C:\Temp\gap0104-x.yaml $HOME\.defenseclaw\config.yaml -Force`, true},
		{`Remove-Item $HOME\.defenseclaw\config.yaml -Force`, true},
		{`Move-Item $HOME\.defenseclaw\config.yaml C:\Temp\gap0104-moved.yaml`, true},
		{`'x' | Add-Content $HOME\.defenseclaw\config.yaml`, true},
		{`'' > $HOME\.defenseclaw\config.yaml`, true},
	} {
		for _, tool := range []string{"Bash", "PowerShell"} {
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			input := actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home}
			input.DialectHint = agentHookWindowsShellDialect(input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			verdict := buildVerdict(findings, "tool_call")
			if got := verdict.Action == "block"; got != tc.block {
				t.Errorf("%s %s: action %q, want block=%t (findings %v)", tool, tc.command, verdict.Action, tc.block, findingIDs(findings))
			}
			if !tc.block && findingWithID(findings, "tamper.detector_state_write") != nil {
				t.Errorf("%s %s: a read carries tamper.detector_state_write", tool, tc.command)
			}
		}
	}
}

// CMD-CHMOD-WORLD matches a mode that grants write to others, a setuid or
// setgid bit on an absolute path, or read for others on private security
// material; group or other read and execute on ordinary paths do not.
func TestGAP0104ChmodWorldMatchesOnlyOthersWrite(t *testing.T) {
	for _, profile := range []string{"default", "strict"} {
		connector := "gap0104-chmod-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		check := func(command string) bool {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo"},
				LegacyText: command, Connector: connector, EnforcementCapable: true,
			})
			return findingWithID(findings, "CMD-CHMOD-WORLD") != nil
		}
		for _, command := range []string{
			`chmod 600 /srv/app/key.txt`, `chmod 640 /srv/app/app.conf`, `chmod 660 /dev/kvm`,
			`chmod 750 /srv/app`, `chmod 0750 /etc/defenseclaw/policies/sandbox`, `chmod 755 /usr/local/bin/tool`,
			`chmod -R a+rX /var/tmp/gap0104-out`, `chmod a+r /srv/app/README`, `chmod u+x /tmp/helper`,
			`chmod g+w /srv/shared/notes`, `chmod +w /tmp/gap0104-file`, `chmod go-w /srv/app`, `chmod o-rwx /srv/app`,
			`chmod 700 ~/.ssh/id_rsa`, `chmod 600 ~/.ssh/id_rsa`,
		} {
			if check(command) {
				t.Errorf("%s: %q emits CMD-CHMOD-WORLD", profile, command)
			}
		}
		for _, command := range []string{
			`chmod 777 /srv/app`, `chmod 666 /dev/kvm`, `chmod 602 /srv/app/log`, `chmod 0733 /opt/data`,
			`chmod o+w /srv/app/log`, `chmod a+w /srv/app/log`, `chmod a=rwx /srv/app`, `chmod ugo+w /srv/app`,
			`chmod -R o+w /srv/app`, `chmod 4755 /usr/local/bin/helper`, `chmod u+s /usr/local/bin/helper`,
			`chmod 0644 /etc/shadow`, `chmod o+r /etc/shadow`,
		} {
			if !check(command) {
				t.Errorf("%s: %q does not emit CMD-CHMOD-WORLD", profile, command)
			}
		}
	}
}
