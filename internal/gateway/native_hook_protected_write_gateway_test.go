// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestR104CodexNativeExecWorkdirRefix3(t *testing.T) {
	home, project := r104ReviewHome(t)
	makefile := "writekeys:\n\t@echo marker >> alias\nsafe:\n\t@echo marker >> report.txt\n"
	if err := os.WriteFile(filepath.Join(project, "Makefile"), []byte(makefile), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command, workdir string
		block                  bool
	}{
		{"native exec_command indirect writer", "make writekeys", project, true},
		{"native exec_command relative workdir", "make writekeys", filepath.Base(project), true},
		{"native exec_command ordinary writer", "make safe", project, false},
		{"GAP-0475 native f-string trailing argument", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; f"""{p.write_text("marker")}"""' .`, project, true},
		{"GAP-0475 native f-string exact", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; f"""{p.write_text("marker")}"""'`, project, true},
		{"GAP-0475 plain string beside the protected path", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; """{p.write_text("marker")}"""'`, project, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := mustJSON(t, map[string]any{
				"hook_event_name": "PreToolUse", "session_id": "r104-native-exec",
				"tool_name": "exec_command", "cwd": home,
				"tool_input": map[string]any{"cmd": tc.command, "workdir": tc.workdir, "login": false},
			})
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "codex"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(string(body)))
			header := hookpaths.Resolve(body)
			targets, ok := hookpaths.Decode(header)
			if !ok || targets[hookpaths.CWDKey] != project {
				t.Fatalf("native exec_command client CWD evidence=%v", targets)
			}
			req.Header.Set(hookpaths.Header, header)
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			response := httptest.NewRecorder()
			api.handleAgentHook("codex").ServeHTTP(response, req)
			want := `"action":"allow"`
			if tc.block {
				want = `"action":"block"`
			}
			if !strings.HasPrefix(response.Body.String(), "{"+want) {
				t.Fatalf("native exec_command: status=%d body=%s, want %s", response.Code, response.Body.String(), want)
			}
		})
	}
}

func TestR104ProtectedWriteRefix3(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"GAP-0314 pathlib home joinpath", `python3 -c 'from pathlib import Path; Path.home().joinpath(".ssh/authorized_keys").open("a").write("marker")'`, true},
		{"awk computed protected target", `awk 'BEGIN { target="alias"; print "marker" >> target }'`, true},
		{"awk adjacent literal target", `awk 'BEGIN { print "marker" >> "ali" "as" }'`, true},
		{"awk mutated target", `awk 'BEGIN { target="report.txt"; sub(/report.txt/, "alias", target); print "marker" >> target }'`, true},
		{"awk side effect before target", `awk 'BEGIN { target="report.txt"; system("ln -sf ~/.ssh/authorized_keys report.txt"); print "marker" >> target }'`, true},
		{"awk ordinary target", `awk 'BEGIN { target="report.txt"; print "marker" >> target }'`, false},
		{"python computed Path receiver", `python3 -c 'from pathlib import Path; p=Path("alias"); p.write_text("marker")'`, true},
		{"python concatenated Path receiver", `python3 -c 'from pathlib import Path; p=Path("ali"+"as"); p.write_text("marker")'`, true},
		{"python ordinary Path destination with protected data", `python3 -c 'from pathlib import Path; Path("out/result.json").write_text("alias")'`, true},
		{"python ordinary Path destination with escaped data", `python3 -c 'from pathlib import Path; Path("out/result.json").write_text("alias\n")'`, true},
		{"python ordinary open destination with protected data", `python3 -c 'open("out.txt","w").write("alias")'`, true},
		{"shell parse error after redirect", `echo marker >> alias; if (`, true},
		{"shell parse error after dynamic redirect", `echo marker >> "$destination"; if (`, false},
		{"shell parse error after copy", `cp report.txt alias; if (`, true},
		{"shell parse error after Python write", `python3 -c 'open("alias","a").write("marker")'; if (`, true},
		{"shell parse error after ordinary copy", `cp report.txt out.txt; if (`, false},
		{"GAP-0322 nice long option", `nice --adjustment=5 python3 -c 'open("alias","a").write("marker")'`, true},
		{"GAP-0322 timeout signal", `timeout --signal=TERM 30 python3 -c 'open("alias","a").write("marker")'`, true},
		{"opaque launcher computed target", `nice --adjustment=5 python3 -c 'open("ali"+"as","a").write("marker")'`, true},
		{"GAP-0331 xargs replacement", `printf alias | xargs --replace=DEST python3 -c 'open("DEST","a").write("marker")'`, true},
		{"GAP-0332 imported copyfile", `python3 -c 'from shutil import copyfile; copyfile("payload","alias")'`, true},
		{"GAP-0333 copyfile keyword destination", `python3 -c 'import shutil; shutil.copyfile(src="payload",dst="alias")'`, true},
		{"GAP-0333 copyfile supplemental option", `python3 -c 'import shutil; shutil.copyfile("payload","alias",follow_symlinks=True)'`, true},
		{"copyfile keyword literal expression", `python3 -c 'import shutil; shutil.copyfile(src="payload",dst="ali" "as")'`, true},
		{"copyfile optional literal expression", `python3 -c 'import shutil; shutil.copyfile("payload","ali" "as",follow_symlinks=True)'`, true},
		{"copyfile ordinary destination", `python3 -c 'import shutil; shutil.copyfile("payload","out.txt")'`, false},
		{"GAP-0475 trailing Python argument", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; f"""{p.write_text("marker")}"""' .`, true},
		{"GAP-0475 exact Python argument", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; f"""{p.write_text("marker")}"""'`, true},
		{"GAP-0475 triple string beside the protected path", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; """{p.write_text("marker")}"""'`, false},
		{"GAP-0495 nested bash login shell", `bash -lc 'echo marker >> alias'`, true},
		{"GAP-0495 nested sh shell", `sh -c 'echo marker >> alias'`, true},
		{"GAP-0495 separate login option", `bash -l -c 'echo marker >> alias'`, true},
		{"GAP-0495 environment wrapper", `env -u UNUSED bash -lc 'echo marker >> alias'`, true},
		{"GAP-0495 priority wrapper", `nice -n 5 bash -lc 'echo marker >> alias'`, true},
		{"GAP-0495 deadline wrapper", `timeout 30 bash -lc 'echo marker >> alias'`, true},
		{"GAP-0495 nested ordinary shell", `bash -lc 'echo marker >> report.txt'`, false},
		{"GAP-0495 ordinary wrapped shell", `env -u UNUSED bash -lc 'echo marker >> report.txt'`, false},
		{"GAP-0284 managed Codex quoted home", `echo marker >> "$HOME/.ssh/authorized_keys"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, got := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if got != tc.block {
					t.Fatalf("route %d blocked=%v, want %v", i, got, tc.block)
				}
			}
		})
	}
}

func TestR104NestedShellProtectedPath(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"GAP-0495 login shell", `bash -lc 'echo marker >> ~/.ssh/authorized_keys'`, true},
		{"GAP-0495 separate login option", `bash -l -c 'echo marker >> ~/.ssh/authorized_keys'`, true},
		{"GAP-0495 ordinary nested write", `bash -lc 'echo marker >> report.txt'`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: cwd,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
			facts := actionfacts.Analyze(input)
			write := trustedExistingAuthorizedKeysSymlinkWrite(trustedActionRequest{Input: input}, facts)
			if got := trustedAuthorizedKeysWriteProof(input, facts, write, nil); got != tc.block {
				t.Fatalf("protected write = %v, want %v", got, tc.block)
			}
		})
	}
}

func TestR104MaterializedLinkWriteRefix3(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	if err := os.Mkdir(filepath.Join(cwd, "other-repo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "other-repo", ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"GAP-1550 git clone", `git clone ../repo d && echo marker >> d/k`, false},
		{"GAP-1550 git checkout", `git checkout -- k && echo marker >> k`, false},
		{"GAP-1550 git switch", `git switch updated && echo marker >> k`, false},
		{"GAP-1550 git pull", `git pull && echo marker >> k`, false},
		{"GAP-1550 git apply", `git apply link.patch && echo marker >> k`, false},
		{"GAP-1550 remote rsync", `rsync -a host:src/ copy/ && echo marker >> copy/k`, true},
		{"GAP-1550 jar extraction", `jar xf keys.jar && echo marker >> n1.txt`, true},
		{"GAP-1550 ditto extraction", `ditto -x -k keys.zip unpack && echo marker >> unpack/n`, true},
		{"git clone outside destination", `git clone ../repo d && echo marker >> report.txt`, false},
		{"git pull separate project file", `git -C other-repo pull && echo marker >> report.txt`, false},
		{"remote rsync outside destination", `rsync -a host:src/ copy/ && echo marker >> report.txt`, false},
		{"jar list only", `jar tf keys.jar && echo marker >> n1.txt`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, blocked := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if blocked != tc.block {
					t.Fatalf("route %d blocked=%v, want %v", i, blocked, tc.block)
				}
			}
		})
	}
}

func TestR104WindowsRegisteredHookWriteRefix3(t *testing.T) {
	for _, tc := range []struct {
		name, connector, tool, command string
		block                          bool
	}{
		{"GAP-0317 Copilot CMD", "copilot", "powershell", `cmd.exe /c "echo dummy-key>>%USERPROFILE%\.ssh\authorized_keys"`, true},
		{"Copilot CMD short name", "copilot", "powershell", `cmd /c "echo dummy-key>>%USERPROFILE%\.ssh\authorized_keys"`, true},
		{"Copilot CMD ordinary", "copilot", "powershell", `cmd.exe /c "echo marker>>%USERPROFILE%\report.txt"`, false},
		{"GAP-0318 Hermes PowerShell", "hermes", "shell", `Add-Content -Path '~/.ssh/authorized_keys' -Value 'dummy-key'`, true},
		{"Hermes Set-Content", "hermes", "shell", `Set-Content -Path '~/.ssh/authorized_keys' -Value 'dummy-key'`, true},
		{"Hermes Out-File", "hermes", "shell", `Out-File -FilePath '~/.ssh/authorized_keys' -InputObject 'dummy-key'`, true},
		{"Hermes ordinary", "hermes", "shell", `Add-Content -Path '~/report.txt' -Value 'dummy-key'`, false},
		{"GAP-0421 Codex Join-Path variable", "codex", "exec_command", `$sshDirectory = Join-Path $HOME '.ssh'; $authorizedKeys = Join-Path $sshDirectory 'authorized_keys'; New-Item -ItemType Directory -Path $sshDirectory -Force | Out-Null; Add-Content -LiteralPath $authorizedKeys -Value 'dummy-key'; Write-Output "Appended literal string to $authorizedKeys"`, true},
		{"Codex Join-Path ordinary variable", "codex", "exec_command", `$output = Join-Path $HOME 'report.txt'; Add-Content -LiteralPath $output -Value 'dummy-key'`, false},
		{"Codex Join-Path ordinary quoted variable", "codex", "exec_command", `$output = Join-Path $HOME 'report.txt'; Add-Content -LiteralPath "$output" -Value 'dummy-key'`, false},
		{"Codex unknown write variable is audit only", "codex", "exec_command", `Add-Content -LiteralPath $destination -Value 'dummy-key'`, false},
		{"GAP-0510 Codex newline", "codex", "exec_command", "Write-Output 'ok'\nAdd-Content -Path '~/.ssh/authorized_keys' -Value 'marker'", true},
		{"GAP-0510 CMD prefix then newline", "codex", "exec_command", "cmd.exe /c \"echo ok\"\nAdd-Content -Path '~/.ssh/authorized_keys' -Value 'marker'", true},
		{"GAP-0510 Copilot CRLF", "copilot", "powershell", "Write-Output 'ok'\r\nSet-Content -Path '~/.ssh/authorized_keys' -Value 'marker'", true},
		{"GAP-0510 Hermes ordinary newline", "hermes", "shell", "Write-Output 'ok'\nAdd-Content -Path 'notes.txt' -Value 'marker'", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: agentHookTrustedActionTool(tc.connector, tc.tool, "windows"),
				Command: tc.command, CWD: `C:\Users\alice\project`, ActiveHome: `C:\Users\alice`}
			input.DialectHint = selectWindowsShellDialect(input.Tool, input.Command, input)
			if tc.connector == "copilot" && tc.block && soleCMDInvocation(tc.command) &&
				input.DialectHint != actionfacts.DialectCMD {
				t.Fatalf("CMD wrapper dialect=%q, want CMD", input.DialectHint)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: tc.connector, EnforcementCapable: true,
			})
			finding := findingWithID(findings, "persistence.ssh_authorized_keys_command")
			if got := finding != nil && finding.contributesToEnforcement(); got != tc.block {
				t.Fatalf("registered %s proof: blocked=%v, want %v; dialect=%q findings=%v", tc.connector, got, tc.block, input.DialectHint, FindingStrings(findings))
			}
		})
	}
}

func TestR104WindowsRegisteredHookNativeRefix3(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native registered Windows hook route")
	}
	for _, tc := range []struct {
		connector, event, tool, command, commandKey string
	}{
		{"copilot", "preToolUse", "powershell", `cmd.exe /c "echo dummy-key>>%USERPROFILE%\.ssh\authorized_keys"`, "command"},
		{"hermes", "pre_tool_call", "terminal", `Add-Content -Path '~/.ssh/authorized_keys' -Value 'dummy-key'`, "command"},
		{"codex", "PreToolUse", "exec_command", `$sshDirectory = Join-Path $HOME '.ssh'; $authorizedKeys = Join-Path $sshDirectory 'authorized_keys'; New-Item -ItemType Directory -Path $sshDirectory -Force | Out-Null; Add-Content -LiteralPath $authorizedKeys -Value 'dummy-key'; Write-Output "Appended literal string to $authorizedKeys"`, "cmd"},
		{"codex", "PreToolUse", "exec_command", "Write-Output 'ok'\nAdd-Content -Path '~/.ssh/authorized_keys' -Value 'marker'", "cmd"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = tc.connector
			api := &APIServer{scannerCfg: cfg}
			args, err := json.Marshal(map[string]string{tc.commandKey: tc.command})
			if err != nil {
				t.Fatal(err)
			}
			resp := api.evaluateAgentHook(t.Context(), agentHookRequest{
				ConnectorName: tc.connector, HookEventName: tc.event, ToolName: tc.tool, ToolArgs: args,
			})
			if resp.RawAction != "block" || resp.Action != "block" ||
				!containsString(resp.RuleIDs, "persistence.ssh_authorized_keys_command") {
				t.Fatalf("registered hook action=%q raw=%q rules=%v", resp.Action, resp.RawAction, resp.RuleIDs)
			}
		})
	}
}
