// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// postManagedSettingsShellCell posts a shell command to the hook of a
// connector, per-user or as a managed hook peer of home, under the rule pack
// ("" is the default pack), and returns the response.
func postManagedSettingsShellCell(t *testing.T, home, project, connector, pack string, managed bool, command string) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePack = pack
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	body := mustJSON(t, map[string]any{"session_id": "managed-settings-session", "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": command, "description": "d"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if managed {
		req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	return recorder.Body.String()
}

// rel-1-0-6:GAP-0734: a write to a managed agent settings file DefenseClaw
// publishes (Claude Code managed-settings.json and managed-settings.d, Codex
// requirements.toml, the Cursor, Copilot and OpenCode machine policy) is a
// state mutation in every profile, per-user and managed, on both hooks. A
// read of the same files, and a write beside them, stay allowed.
func TestManagedAgentSettingsAreSelfProtection(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	type row struct {
		command   string
		protected bool
	}
	var rows []row
	for _, file := range []string{
		"/etc/claude-code/managed-settings.json",
		"/etc/claude-code/managed-settings.d/50-defenseclaw.json",
		"/Library/Application Support/ClaudeCode/managed-settings.json",
		"/Library/Application Support/ClaudeCode/managed-settings.d/50-defenseclaw.json",
		"/etc/codex/requirements.toml",
		"/etc/cursor/hooks.json",
		"/etc/github-copilot/policy.d/50-defenseclaw.json",
		"/etc/opencode/opencode.json",
	} {
		q := "\x27" + file + "\x27"
		for _, form := range []string{
			"printf x > " + q,
			"echo x >> " + q,
			"sed -i d " + q,
			"cp " + project + "/a.txt " + q,
			"tee " + q + " < /dev/null",
			"rm " + q,
			"mv " + project + "/a.txt " + q,
			"truncate -s 0 " + q,
			"cd /tmp && printf x > " + q,
		} {
			rows = append(rows, row{form, true})
		}
		rows = append(rows,
			row{"cat " + q, false},
			row{"grep -n x " + q, false},
			row{"ls -l " + q, false},
			row{"cp " + q + " " + project + "/copy.txt", false},
			row{"sed -n 1p " + q, false},
		)
	}
	rows = append(rows,
		row{"printf x > /etc/claude-code-notes.txt", false},
		row{"printf x > /etc/codex-extra/requirements.toml", false},
		row{"printf x > /private/etc/codex-extra/requirements.toml", false},
		row{"printf x > /private/var/etc/codex/requirements.toml", false},
		row{"printf x > " + project + "/etc/codex/requirements.toml", false},
		row{"sed -i d " + project + "/managed-settings.json", false},
		// A Linux file system tells these from the published names, and
		// /private is an ordinary directory there (macOS: see
		// TestManagedAgentSettingsOnMacOSIgnoreCase).
		row{"printf x > /etc/claude-code/MANAGED-SETTINGS.JSON", false},
		row{"printf x > /etc/codex/REQUIREMENTS.TOML", false},
		row{"printf x > /etc/claude-code/Managed-Settings.d/50-defenseclaw.json", false},
		row{"printf x > /private/etc/codex/requirements.toml", false},
		row{"printf x > /library/application support/claudecode/managed-settings.json", false},
	)
	for _, connector := range []string{"claudecode", "codex"} {
		for _, pack := range []string{"", "strict", "permissive"} {
			for _, managed := range []bool{false, true} {
				for _, row := range rows {
					got := postManagedSettingsShellCell(t, home, project, connector, pack, managed, row.command)
					block := strings.HasPrefix(got, `{"action":"block"`)
					switch {
					case row.protected && (!block || !strings.Contains(got, "tamper.detector_state_write")):
						t.Errorf("%s managed=%t pack=%s: %s = %.200s, want protected block", connector, managed, pack, row.command, got)
					case !row.protected && block && pack != "strict":
						t.Errorf("%s managed=%t pack=%s: %s = %.200s, want allow", connector, managed, pack, row.command, got)
					}
				}
			}
		}
	}
}

// rel-1-0-6:GAP-0734 review 6: the managed agent settings DefenseClaw
// publishes on Windows (Claude Code under Program Files, Codex, Cursor,
// Copilot and OpenCode under ProgramData) are self-protection targets of a
// file-tool write in every spelling of the drive and the case, and in every
// profile. A file of the project with the same names, or a directory that
// only starts with the same letters, stays allowed.
func TestWindowsManagedAgentSettingsAreSelfProtection(t *testing.T) {
	const home = `C:\Users\vn`
	protected := []string{
		`C:\Program Files\ClaudeCode\managed-settings.json`,
		`C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json`,
		`c:\program files\claudecode\managed-settings.json`,
		`D:/Program Files/ClaudeCode/managed-settings.d/90-defenseclaw.json`,
		`C:\Program Files\ClaudeCode\managed-settings.d\..\managed-settings.json`,
		`\\?\C:\Program Files\ClaudeCode\managed-settings.json`,
		`C:\ProgramData\OpenAI\Codex\requirements.toml`,
		`C:\ProgramData\Cursor\hooks.json`,
		`C:\ProgramData\GitHub\Copilot\policy.d\90-defenseclaw.json`,
		`C:\ProgramData\opencode\opencode.json`,
		// The local administrative share. The 8.3 names of the same files are
		// in TestWindowsShortNamesOfManagedAgentSettingsStayBlocked.
		`\\localhost\C$\Program Files\ClaudeCode\managed-settings.json`,
		`\\127.0.0.1\C$\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json`,
		`\\?\UNC\localhost\C$\ProgramData\OpenAI\Codex\requirements.toml`,
		`\\[::1]\C$\Program Files\ClaudeCode\managed-settings.json`,
	}
	allowed := []string{
		home + `\proj\ClaudeCode\managed-settings.json`,
		`C:\Program Files\ClaudeCodeX\managed-settings.json`,
		`C:\ProgramData\OpenAI\Codex2\requirements.toml`,
		`C:\ProgramData\Cursor2\hooks.json`,
		`C:\Program Files\Other\managed-settings.json`,
		`\\localhost\C$\Users\vn\proj\ClaudeCode\managed-settings.json`,
		`\\localhost\C$\Program Files\Other\managed-settings.json`,
		// No 8.3 row is written here: which short names exist is for the
		// volume to say. The names the volume gives come from
		// TestWindowsShortNamesOfManagedAgentSettingsStayBlocked and
		// TestWindowsShortNameOfAnotherVendorFolderFileStaysAllowed, the
		// shapes it does not generate from the vendor-folder test.
	}
	// Another machine: this host name with one letter changed.
	if host, err := os.Hostname(); err == nil && host != "" {
		allowed = append(allowed, `\\`+otherMachineName(host, 0)+`\C$\Program Files\ClaudeCode\managed-settings.json`)
	}
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "strict", "permissive"} {
			for _, file := range protected {
				for _, input := range []map[string]any{
					{"file_path": file, "content": "x"},
					{"content": "x", "file_path": home + `\proj\a.txt`, "destination": file},
				} {
					if block, got := postFileToolCell(t, home, home+`\proj`, "Write", input, managed, pack); !block {
						t.Errorf("managed=%t pack=%s %v = %.160s, want protected block", managed, pack, input, got)
					}
				}
			}
			for _, file := range allowed {
				if _, got := postFileToolCell(t, home, home+`\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
					t.Errorf("managed=%t pack=%s %s = %.160s, want allow", managed, pack, file, got)
				}
			}
		}
	}
}

// rel-1-0-6:GAP-0734 round 11: the managed settings files are matched by the
// semantics of the file system they sit on. macOS ignores case and reads /etc
// as /private/etc, so a case variant or the /private spelling is the file;
// the gateway of such a host is a darwin one. The same names on a Linux host
// are ordinary files (Linux tells them apart).
func TestManagedAgentSettingsOnMacOSIgnoreCase(t *testing.T) {
	withMacOSPlatform(t, true)
	const macHome = "/Users/vn"
	for _, file := range []string{
		"/etc/claude-code/MANAGED-SETTINGS.JSON",
		"/ETC/codex/requirements.toml",
		"/private/etc/codex/requirements.toml",
		"/PRIVATE/ETC/Cursor/HOOKS.JSON",
		"/library/application support/claudecode/managed-settings.json",
	} {
		for _, pack := range []string{"", "strict", "permissive"} {
			input := map[string]any{"file_path": file, "content": "x"}
			if block, got := postFileToolCell(t, macHome, macHome+"/proj", "Write", input, true, pack); !block {
				t.Errorf("macOS home pack=%s %s = %.160s, want protected block", pack, file, got)
			}
		}
	}
	withMacOSPlatform(t, false)
	home, project := dynamicWordParityProject(t)
	for _, file := range []string{
		"/etc/claude-code/MANAGED-SETTINGS.JSON",
		"/etc/codex/REQUIREMENTS.TOML",
		"/private/etc/codex/requirements.toml",
		"/etc/CURSOR/hooks.json",
	} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "permissive"} {
				input := map[string]any{"file_path": file, "content": "x"}
				if _, got := postFileToolCell(t, home, project, "Write", input, managed, pack); strings.HasPrefix(got, fileToolBlockPrefix) {
					t.Errorf("Linux home managed=%t pack=%s %s = %.160s, want allow (distinct file)", managed, pack, file, got)
				}
			}
		}
	}
}

// withMacOSPlatform makes the managed settings match as a macOS host does
// (case folded, /etc read as /private/etc) for one test.
func withMacOSPlatform(t *testing.T, macOS bool) {
	t.Helper()
	saved := managedSettingsCaseFold
	t.Cleanup(func() { managedSettingsCaseFold = saved })
	managedSettingsCaseFold = func() bool { return macOS }
}

// rel-1-0-6:GAP-0734 review 11 M2: the platform decides whether case folds,
// not the home. On a Linux host whose managed home sits under /Users, a case
// variant of a managed settings file is another file and stays allowed; the
// exact name is still protected.
func TestManagedAgentSettingsLinuxHomeUnderUsersKeepsExactCase(t *testing.T) {
	withMacOSPlatform(t, false)
	const home = "/Users/vn"
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, file := range []string{"/etc/codex/requirements.toml", "/etc/claude-code/managed-settings.json"} {
				input := map[string]any{"file_path": file, "content": "x"}
				if block, got := postFileToolCell(t, home, home+"/proj", "Write", input, managed, pack); !block {
					t.Errorf("managed=%t pack=%s %s = %.160s, want protected block", managed, pack, file, got)
				}
			}
			for _, file := range []string{"/etc/codex/REQUIREMENTS.TOML", "/etc/claude-code/MANAGED-SETTINGS.JSON", "/private/etc/codex/requirements.toml"} {
				input := map[string]any{"file_path": file, "content": "x"}
				if pack == "strict" {
					continue
				}
				if _, got := postFileToolCell(t, home, home+"/proj", "Write", input, managed, pack); strings.HasPrefix(got, fileToolBlockPrefix) {
					t.Errorf("managed=%t pack=%s %s = %.160s, want allow (distinct file on Linux)", managed, pack, file, got)
				}
			}
		}
	}
}

// otherMachineName is the computer name with the letter at index i changed to
// one that is not the same letter in either case: a name of the same length
// that is another machine.
func otherMachineName(name string, i int) string {
	letter := "a"
	if strings.EqualFold(name[i:i+1], letter) {
		letter = "b"
	}
	return name[:i] + letter + name[i+1:]
}

// rel-1-0-6:GAP-0734 review 11 M1: an administrative share is this machine
// only when the whole server name is one of its names. A server that shares
// the first label of the host name with another DNS domain is another
// machine; the host name as the system gives it, and localhost, are this one.
func TestWindowsAdminShareNeedsWholeHostName(t *testing.T) {
	const home = `C:\Users\vn`
	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Skip("host has no name")
	}
	short, _, _ := strings.Cut(host, ".")
	if short == "" {
		t.Skip("host has no short name")
	}
	const tail = `\C$\Program Files\ClaudeCode\managed-settings.json`
	local := []string{`\\` + host + tail, `\\` + strings.ToUpper(short) + tail}
	// Another machine differs from this one in a letter. It never has an
	// added one: NetBIOS cuts a computer name to 15 characters, so a
	// 15-character host name with a letter added is this machine. The same
	// first label in another DNS domain is a changed letter in the domain
	// part of a name that has one (the stand-in host names of
	// TestWindowsLocalHostIsAWholeName cover the single-label host).
	remote := []string{
		`\\` + otherMachineName(short, len(short)-1) + tail,
		`\\` + otherMachineName(short, 0) + tail,
		`\\` + otherMachineName(short, len(short)/2) + tail,
	}
	if dot := strings.IndexByte(host, '.'); dot >= 0 && dot+1 < len(host)-1 {
		remote = append(remote,
			`\\`+otherMachineName(host, dot+1)+tail,
			`\\`+otherMachineName(host, len(host)-1)+tail,
		)
	}
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, file := range local {
				if block, got := postFileToolCell(t, home, home+`\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); !block {
					t.Errorf("managed=%t pack=%s %s = %.160s, want protected block (this host)", managed, pack, file, got)
				}
			}
			for _, file := range remote {
				if _, got := postFileToolCell(t, home, home+`\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); strings.HasPrefix(got, fileToolBlockPrefix) {
					t.Errorf("managed=%t pack=%s %s = %.160s, want allow (another machine)", managed, pack, file, got)
				}
			}
		}
	}
}
