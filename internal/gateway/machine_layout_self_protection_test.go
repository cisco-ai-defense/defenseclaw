// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// machineLayoutCall posts one PreToolUse call of the Claude Code hook, as
// the per-user hook or as a managed hook peer of home, under the rule pack
// ("" is the default pack), and reports whether it is blocked by the
// DefenseClaw state-write finding.
func machineLayoutCall(t *testing.T, home, project, tool string, input map[string]any, managed bool, pack string) (blocked bool, response string) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePack = pack
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	body := mustJSON(t, map[string]any{"session_id": "machine-layout", "hook_event_name": "PreToolUse",
		"tool_name": tool, "cwd": project, "tool_input": input})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
	if managed {
		req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
	response = recorder.Body.String()
	return strings.HasPrefix(response, `{"action":"block"`) && strings.Contains(response, "tamper.detector_state_write"), response
}

// machineLayoutProtected are files of the machine install and state of a
// managed deployment, one or more per Linux and macOS layout field.
var machineLayoutProtected = []string{
	"/etc/defenseclaw/config.yaml",
	"/etc/defenseclaw/policies/local.rego",
	"/etc/defenseclaw/secrets/ai-defense.key",
	"/etc/defenseclaw/managed-runtime.json",
	"/opt/defenseclaw/bin/defenseclaw-hook",
	"/opt/defenseclaw/share/policies/default.yaml",
	"/var/lib/defenseclaw/audit.db",
	"/var/lib/defenseclaw-hook-guardian/ledger.json",
	"/var/lib/defenseclaw-enterprise/record.json",
	"/var/log/defenseclaw/gateway.log",
	"/opt/cisco/defenseclaw/etc/config.yaml",
	"/opt/cisco/defenseclaw/bin/defenseclaw-hook",
	"/opt/cisco/defenseclaw/runtime/audit.db",
	"/opt/cisco/defenseclaw/hook-guardian-state/ledger.json",
	"/Library/Logs/Cisco/DefenseClaw/gateway.log",
}

// machineLayoutOrdinary are files beside the machine roots, in a project, or
// under a name that only starts like one.
var machineLayoutOrdinary = []string{
	"/etc/defenseclaw-notes.txt",
	"/etc/defenseclawd/config.yaml",
	"/opt/defenseclaw-scan/report.txt",
	"/opt/cisco/defenseclaw-scan/report.txt",
	"/var/lib/defenseclaw-notes/a.txt",
	"/tmp/defenseclaw/config.yaml",
	"/usr/local/bin/defenseclaw",
	"{P}/etc/defenseclaw/config.yaml",
	"{P}/opt/defenseclaw/bin/defenseclaw-hook",
}

// rel-1-0-6:GAP-0796: an agent write to the machine install and state of a
// managed deployment (config, policy, secrets, binaries, guardian and
// runtime state, logs) is a DefenseClaw state mutation in every profile,
// per-user and managed, whatever the file modes say. A read of the same
// files and a write beside them stay allowed.
func TestMachineLayoutShellWritesAreSelfProtection(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	type row struct {
		command   string
		protected bool
	}
	var rows []row
	for _, file := range machineLayoutProtected {
		q := "'" + file + "'"
		for _, form := range []string{
			"echo lab-marker >> " + q,
			"printf x > " + q,
			"sed -i d " + q,
			"cp " + project + "/a.txt " + q,
			"tee " + q + " < /dev/null",
			"rm " + q,
			"mv " + project + "/a.txt " + q,
			"truncate -s 0 " + q,
			"cd /tmp && printf x > " + q,
			"sudo sh -c 'echo x >> " + file + "'",
		} {
			rows = append(rows, row{form, true})
		}
		for _, form := range []string{
			"cat " + q, "grep -n x " + q, "ls -l " + q, "stat " + q, "sed -n 1p " + q, "sha256sum " + q,
			"cp " + q + " " + project + "/copy.txt",
		} {
			rows = append(rows, row{form, false})
		}
	}
	for _, spelled := range []string{
		"/etc/defenseclaw/../defenseclaw/config.yaml", "/etc/./defenseclaw/config.yaml", "//etc//defenseclaw/config.yaml",
		"/opt/defenseclaw/bin/../bin/defenseclaw-hook", "/var/run/defenseclaw-hook/x", "/run/defenseclaw-hook/x",
	} {
		rows = append(rows, row{"echo x >> " + spelled, true})
	}
	for _, file := range machineLayoutOrdinary {
		file = strings.ReplaceAll(file, "{P}", project)
		rows = append(rows, row{"printf x > '" + file + "'", false}, row{"cat '" + file + "'", false})
	}
	for _, command := range []string{
		"grep -rn log_level /etc/defenseclaw",
		"find /etc/defenseclaw /opt/defenseclaw -name '*.yaml'",
		"diff -u /etc/defenseclaw/config.yaml " + project + "/a.txt",
		"tar czf " + project + "/backup.tgz /etc/defenseclaw",
		"rsync -a /etc/defenseclaw/ " + project + "/backup/",
		"ls -la /opt/defenseclaw/bin /var/lib/defenseclaw",
		"/opt/defenseclaw/bin/defenseclaw-gateway status",
		"sudo systemctl restart defenseclaw-gateway",
		"cat /etc/defenseclaw/config.yaml | head -3",
	} {
		rows = append(rows, row{command, false})
	}
	for _, pack := range []string{"", "permissive", "strict"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				blocked, got := machineLayoutCall(t, home, project, "Bash", map[string]any{"command": row.command, "description": "d"}, managed, pack)
				switch {
				case row.protected && !blocked:
					t.Errorf("managed=%t pack=%q: %s = %.200s, want protected block", managed, pack, row.command, got)
				case !row.protected && pack != "strict" && strings.HasPrefix(got, `{"action":"block"`):
					t.Errorf("managed=%t pack=%q: %s = %.200s, want allow", managed, pack, row.command, got)
				}
			}
		}
	}
}

// The native file tools of Claude Code (Write, Edit, MultiEdit) judge the
// same files as the shell does; the ordinary twins stay allowed.
func TestMachineLayoutFileToolWritesAreSelfProtection(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	for _, tool := range []string{"Write", "Edit", "MultiEdit"} {
		input := func(file string) map[string]any {
			switch tool {
			case "Edit":
				return map[string]any{"file_path": file, "old_string": "a", "new_string": "b"}
			case "MultiEdit":
				return map[string]any{"file_path": file, "edits": []any{map[string]any{"old_string": "a", "new_string": "b"}}}
			}
			return map[string]any{"file_path": file, "content": "lab-marker"}
		}
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "permissive", "strict"} {
				for _, file := range machineLayoutProtected {
					if blocked, got := machineLayoutCall(t, home, project, tool, input(file), managed, pack); !blocked {
						t.Errorf("%s %s managed=%t pack=%q = %.200s, want protected block", tool, file, managed, pack, got)
					}
				}
				if pack == "strict" {
					continue
				}
				for _, file := range machineLayoutOrdinary {
					file = strings.ReplaceAll(file, "{P}", project)
					if _, got := machineLayoutCall(t, home, project, tool, input(file), managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
						t.Errorf("%s %s managed=%t pack=%q = %.200s, want allow", tool, file, managed, pack, got)
					}
				}
			}
		}
	}
}

// A Codex or Copilot CLI apply_patch names the same files in its patch text.
func TestMachineLayoutApplyPatchIsSelfProtection(t *testing.T) {
	for _, profile := range []string{"default", "strict"} {
		for _, managed := range []bool{false, true} {
			for _, connectorName := range []string{"codex", "copilot"} {
				f := newAbsolutePatchFixture(t)
				for _, file := range machineLayoutProtected {
					for _, patch := range []string{updatePatch(file), "*** Begin Patch\n*** Add File: " + file + "\n+x\n*** End Patch\n",
						"*** Begin Patch\n*** Delete File: " + file + "\n*** End Patch\n"} {
						if got, out := postApplyPatch(t, f, connectorName, profile, managed, patch); got != "block" || !strings.Contains(out, "tamper.detector_state_write") {
							t.Errorf("%s/%s managed=%t patch of %s = %s, want protected block: %.300s", profile, connectorName, managed, file, got, out)
						}
					}
				}
				if profile == "strict" {
					continue
				}
				for _, file := range machineLayoutOrdinary {
					file = strings.ReplaceAll(file, "{P}", f.project)
					if got, out := postApplyPatch(t, f, connectorName, profile, managed, updatePatch(file)); got == "block" {
						t.Errorf("%s/%s managed=%t patch of %s = block, want allow: %.300s", profile, connectorName, managed, file, out)
					}
				}
			}
		}
	}
}

// The Windows machine folders in every spelling NTFS and a POSIX shell on
// Windows give them, as file-tool targets.
func TestMachineLayoutWindowsFileToolWritesAreSelfProtection(t *testing.T) {
	const home = `C:\Users\tester`
	protected := []string{
		`C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`C:\ProgramData\Cisco\DefenseClaw\policies\local.rego`,
		`C:\ProgramData\Cisco\DefenseClaw\secrets\ai-defense.key`,
		`C:\ProgramData\Cisco\DefenseClaw\hook-guardian\targets.yaml`,
		`C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		`C:\ProgramData\Cisco\DefenseClaw-HookRuntime\enroll.json`,
		`C:\ProgramData\Cisco\DefenseClaw-ScannerRuntime\defenseclaw-scanners.exe`,
		`c:\programdata\cisco\defenseclaw\etc\CONFIG.YAML`,
		`C:/ProgramData/Cisco/DefenseClaw/etc/config.yaml`,
		`\\?\C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`//localhost/C$/ProgramData/Cisco/DefenseClaw/etc/config.yaml`,
		`C:\PROGRA~3\Cisco\DEFENS~1\etc\config.yaml`,
		`C:\ProgramData\Cisco\DefenseClaw.\etc\config.yaml`,
		`C:\ProgramData\Cisco\x\..\DefenseClaw\etc\config.yaml`,
	}
	ordinary := []string{
		`C:\ProgramData\Cisco\DefenseClaw-Notes\a.txt`,
		`C:\ProgramData\Cisco\Cisco Secure Client\a.txt`,
		`C:\ProgramData\Other\DefenseClaw\a.txt`,
		`C:\Users\tester\proj\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`C:\Users\tester\proj\notes.txt`,
		// Without a registration the layout is the default one, on C:.
		`D:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`D:\Program Files\Cisco\DefenseClaw\bin\project.exe`,
		// The hook and scanner runtime are below ProgramData only, and a
		// short name is the one NTFS makes: six characters, a tilde, a number.
		`C:\Program Files\Cisco\DefenseClaw-HookRuntime\a.txt`,
		`C:\Program Files\Cisco\DefenseClaw-ScannerRuntime\a.txt`,
		`C:\ProgramData\Cisco\D~1\a.txt`,
		`C:\ProgramData\Cisco\DE~9\a.txt`,
		`C:\PRO~1\Cisco\DefenseClaw\a.txt`,
		`C:\ProgramData\Cisco\DEFENSE~1\a.txt`,
	}
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, file := range protected {
				if blocked, got := machineLayoutCall(t, home, home+`\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); !blocked {
					t.Errorf("Write %s managed=%t pack=%q = %.200s, want protected block", file, managed, pack, got)
				}
			}
			if pack == "strict" {
				continue
			}
			for _, file := range ordinary {
				if _, got := machineLayoutCall(t, home, home+`\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
					t.Errorf("Write %s managed=%t pack=%q = %.200s, want allow", file, managed, pack, got)
				}
			}
		}
	}
}

// On macOS the file system ignores case and /etc is /private/etc.
func TestMachineLayoutOnMacOSIgnoresCase(t *testing.T) {
	const macHome = "/Users/tester"
	for _, file := range []string{
		"/opt/CISCO/DefenseClaw/etc/config.yaml", "/private/var/run/defenseclaw-sensor/x", "/library/logs/cisco/defenseclaw/gateway.log",
	} {
		if blocked, got := machineLayoutCall(t, macHome, macHome+"/proj", "Write", map[string]any{"file_path": file, "content": "x"}, true, ""); !blocked {
			t.Errorf("Write %s = %.200s, want protected block", file, got)
		}
	}
	// The same differently cased names outside a macOS home: a Linux file
	// system tells them apart (different files, allowed), a macOS one does not
	// (the same protected file, blocked).
	wantBlocked := runtime.GOOS == "darwin"
	home, project := dynamicWordParityProject(t)
	for _, file := range []string{"/opt/CISCO/DefenseClaw/etc/config.yaml", "/ETC/defenseclaw/config.yaml"} {
		protectedBlock, got := machineLayoutCall(t, home, project, "Write", map[string]any{"file_path": file, "content": "x"}, false, "")
		if wantBlocked && !protectedBlock {
			t.Errorf("Write %s on %s = %.200s, want protected block", file, runtime.GOOS, got)
		}
		if !wantBlocked && strings.HasPrefix(got, `{"action":"block"`) {
			t.Errorf("Write %s on %s = %.200s, want allow", file, runtime.GOOS, got)
		}
	}
}

// A relative path is a project file whatever its names are: the Windows
// machine folders are absolute.
func TestMachineLayoutRelativeWindowsNamesAreProjectFiles(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	for _, file := range []string{
		"ProgramData/Cisco/DefenseClaw/etc/project.yaml",
		"Program Files/Cisco/DefenseClaw/bin/project.txt",
		`ProgramData\Cisco\DefenseClaw\etc\project.yaml`,
		"./ProgramData/Cisco/DefenseClaw-HookRuntime/project.txt",
		"ProgramData/Cisco/DEFENS~1/project.txt",
	} {
		for _, pack := range []string{"", "permissive"} {
			for _, tool := range []string{"Write", "Bash"} {
				input := map[string]any{"file_path": file, "content": "x"}
				if tool == "Bash" {
					input = map[string]any{"command": "printf x > \x27" + file + "\x27", "description": "d"}
				}
				if _, got := machineLayoutCall(t, home, project, tool, input, false, pack); strings.HasPrefix(got, `{"action":"block"`) {
					t.Errorf("%s %s pack=%q = %.200s, want allow", tool, file, pack, got)
				}
			}
		}
	}
}

// The Program Files and ProgramData roots are the ones the trusted machine
// registration names (managed.StandaloneWindowsLayoutForRoots accepts any
// absolute drive roots), not only the default folder names.
func TestMachineLayoutWindowsRegisteredRootsAreSelfProtection(t *testing.T) {
	previous := defenseClawMachineLayout
	defenseClawMachineLayout = func() machineLayout {
		return newMachineLayout(func() (string, string, error) { return `D:\Applications`, `E:\CompanyData`, nil })
	}
	t.Cleanup(func() { defenseClawMachineLayout = previous })
	const home = `C:\Users\tester`
	protected := []string{
		`E:\CompanyData\Cisco\DefenseClaw\etc\config.yaml`,
		`D:\Applications\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		`E:\CompanyData\Cisco\DefenseClaw-HookRuntime\enroll.json`,
		`E:\CompanyData\Cisco\DefenseClaw-ScannerRuntime\defenseclaw-scanners.exe`,
		`e:/companydata/cisco/defenseclaw/etc/config.yaml`,
		`E:\COMPAN~1\Cisco\DEFENS~1\etc\config.yaml`,
		`//localhost/D$/Applications/Cisco/DefenseClaw/bin/defenseclaw-hook.exe`,
	}
	ordinary := []string{
		`D:\Applications\Cisco\DefenseClaw-HookRuntime\a.txt`,
		`E:\CompanyData\Other\DefenseClaw\a.txt`,
		`E:\Other\Cisco\DefenseClaw\a.txt`,
		`D:\Applications\Cisco\Other\a.txt`,
		`E:\CompanyData\Cisco\D~1\a.txt`,
		`C:\Users\tester\proj\CompanyData\Cisco\DefenseClaw\a.txt`,
		// The default folders on a drive that is not registered, and the
		// registered names on the other registered drive.
		`C:\ProgramData\Cisco\DefenseClaw\etc\project.yaml`,
		`D:\ProgramData\Cisco\DefenseClaw\etc\project.yaml`,
		`D:\Program Files\Cisco\DefenseClaw\bin\project.exe`,
		`E:\Applications\Cisco\DefenseClaw\bin\project.exe`,
		`D:\CompanyData\Cisco\DefenseClaw\etc\project.yaml`,
	}
	for _, managed := range []bool{false, true} {
		for _, file := range protected {
			if blocked, got := machineLayoutCall(t, home, home+`\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, managed, ""); !blocked {
				t.Errorf("Write %s managed=%t = %.200s, want protected block", file, managed, got)
			}
		}
		for _, file := range ordinary {
			if _, got := machineLayoutCall(t, home, home+`\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, managed, ""); strings.HasPrefix(got, `{"action":"block"`) {
				t.Errorf("Write %s managed=%t = %.200s, want allow", file, managed, got)
			}
		}
	}
}

// A value the shell holds in a variable names the machine file as well.
func TestMachineLayoutKnownShellValuesAreSelfProtection(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	for _, command := range []string{
		`target=/etc/defenseclaw/config.yaml; printf x >> "$target"`,
		`root=/opt/defenseclaw/bin; printf x >> "$root/defenseclaw-hook"`,
		`target=/opt/cisco/defenseclaw/etc/config.yaml; printf x >> "$target"`,
	} {
		if blocked, got := machineLayoutCall(t, home, project, "Bash", map[string]any{"command": command, "description": "d"}, false, ""); !blocked {
			t.Errorf("%q = %.200s, want protected block", command, got)
		}
	}
}

// The default Windows folder names on a drive that is not a registered root
// are project files, in balanced and permissive alike; the registered roots
// stay protected.
func TestMachineLayoutWindowsUnregisteredDriveIsOrdinary(t *testing.T) {
	previous := defenseClawMachineLayout
	defenseClawMachineLayout = func() machineLayout {
		return newMachineLayout(func() (string, string, error) { return `C:\Program Files`, `C:\ProgramData`, nil })
	}
	t.Cleanup(func() { defenseClawMachineLayout = previous })
	const home = `C:\Users\tester`
	for _, pack := range []string{"", "permissive"} {
		for _, file := range []string{
			`D:\ProgramData\Cisco\DefenseClaw\etc\project.yaml`,
			`D:\Program Files\Cisco\DefenseClaw\bin\project.exe`,
			`D:\ProgramData\Cisco\DefenseClaw-HookRuntime\project.txt`,
		} {
			if _, got := machineLayoutCall(t, home, home+`\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, false, pack); strings.HasPrefix(got, `{"action":"block"`) {
				t.Errorf("Write %s pack=%q = %.200s, want allow", file, pack, got)
			}
		}
		for _, file := range []string{
			`C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
			`C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		} {
			if blocked, got := machineLayoutCall(t, home, home+`\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, false, pack); !blocked {
				t.Errorf("Write %s pack=%q = %.200s, want protected block", file, pack, got)
			}
		}
	}
}

// With one registered root below the other, only the layout folders are
// protected; their neighbors between the roots are project files.
func TestMachineLayoutWindowsNestedRegisteredRootsKeepFolderBoundary(t *testing.T) {
	previous := defenseClawMachineLayout
	defenseClawMachineLayout = func() machineLayout {
		return newMachineLayout(func() (string, string, error) { return `D:\Applications`, `D:\Applications\Data`, nil })
	}
	t.Cleanup(func() { defenseClawMachineLayout = previous })
	const home = `C:\Users\tester`
	for _, file := range []string{
		`D:\Applications\Data\Cisco\Other\a.txt`,
		`D:\Applications\Data\Cisco\Notes\project.txt`,
		`D:\Applications\Cisco\Other\a.txt`,
	} {
		if _, got := machineLayoutCall(t, home, home+`\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, false, ""); strings.HasPrefix(got, `{"action":"block"`) {
			t.Errorf("Write %s = %.200s, want allow", file, got)
		}
	}
	for _, file := range []string{
		`D:\Applications\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		`D:\Applications\Data\Cisco\DefenseClaw\etc\config.yaml`,
		`D:\Applications\Data\Cisco\DefenseClaw-HookRuntime\enroll.json`,
	} {
		if blocked, got := machineLayoutCall(t, home, home+`\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, false, ""); !blocked {
			t.Errorf("Write %s = %.200s, want protected block", file, got)
		}
	}
}

// A path with no drive is on the drive the hook runs on: registered on C:,
// a drive-less machine folder is protected from C: and an ordinary file from
// any other drive.
func TestMachineLayoutWindowsDriveLessPathFollowsTheCurrentDrive(t *testing.T) {
	previous := defenseClawMachineLayout
	defenseClawMachineLayout = func() machineLayout {
		return newMachineLayout(func() (string, string, error) { return `C:\Program Files`, `C:\ProgramData`, nil })
	}
	t.Cleanup(func() { defenseClawMachineLayout = previous })
	const home = `C:\Users\tester`
	files := []string{
		`\ProgramData\Cisco\DefenseClaw\etc\project.yaml`,
		`\Program Files\Cisco\DefenseClaw\bin\project.exe`,
		`\ProgramData\Cisco\DefenseClaw-HookRuntime\project.txt`,
		`/ProgramData/Cisco/DefenseClaw/etc/project.yaml`,
		`/Program Files/Cisco/DefenseClaw/bin/project.exe`,
		`/ProgramData/Cisco/DefenseClaw-HookRuntime/project.txt`,
		`/ProgramData\Cisco/DefenseClaw\etc/project.yaml`,
		`\Program Files/Cisco\DefenseClaw/bin\project.exe`,
	}
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, file := range files {
				for _, project := range []string{`D:\proj`, `D:/proj`} {
					if _, got := machineLayoutCall(t, home, project, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
						t.Errorf("Write %s from %s managed=%t pack=%q = %.200s, want allow", file, project, managed, pack, got)
					}
				}
				for _, project := range []string{`C:\proj`, `c:/proj`} {
					if blocked, got := machineLayoutCall(t, home, project, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); !blocked {
						t.Errorf("Write %s from %s managed=%t pack=%q = %.200s, want protected block", file, project, managed, pack, got)
					}
				}
			}
		}
	}
}

// Windows reads exactly two leading separators and a server name as a UNC
// path; one, or three and more, is rooted on the current drive whatever the
// mix of slashes and backslashes. A real //server/share path stays distinct.
func TestMachineLayoutWindowsRepeatedLeadingSeparatorsAreRootedOnTheCurrentDrive(t *testing.T) {
	previous := defenseClawMachineLayout
	defenseClawMachineLayout = func() machineLayout {
		return newMachineLayout(func() (string, string, error) { return `C:\Program Files`, `C:\ProgramData`, nil })
	}
	t.Cleanup(func() { defenseClawMachineLayout = previous })
	const home = `C:\Users\tester`
	files := []string{
		`/\/ProgramData/Cisco/DefenseClaw/etc/config.yaml`,
		`\\\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`///ProgramData/Cisco/DefenseClaw/etc/config.yaml`,
		`\/\/Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		`////ProgramData\Cisco/DefenseClaw-HookRuntime/enroll.json`,
	}
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, file := range files {
				for _, project := range []string{`D:\proj`} {
					if _, got := machineLayoutCall(t, home, project, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
						t.Errorf("Write %s from %s managed=%t pack=%q = %.200s, want allow", file, project, managed, pack, got)
					}
				}
				for _, project := range []string{`C:\proj`, `c:/proj`} {
					if blocked, got := machineLayoutCall(t, home, project, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); !blocked {
						t.Errorf("Write %s from %s managed=%t pack=%q = %.200s, want protected block", file, project, managed, pack, got)
					}
				}
			}
			for _, share := range []string{`//server/share/ProgramData/Cisco/DefenseClaw/etc/config.yaml`, `\\server\share\ProgramData\Cisco\DefenseClaw\etc\config.yaml`} {
				if _, got := machineLayoutCall(t, home, `C:\proj`, "Write", map[string]any{"file_path": share, "content": "x"}, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
					t.Errorf("Write %s managed=%t pack=%q = %.200s, want allow", share, managed, pack, got)
				}
			}
		}
	}
}

// On a POSIX target a /ProgramData path is an ordinary path, never a
// drive-less Windows one, whether the hook reports no directory or one the
// gateway cannot place. Where the target is Windows and nothing places the
// drive, the drive-less machine folder stays protected on every drive.
func TestMachineLayoutPOSIXTargetWithoutPlacedDirectoryIsNotADriveLessWindowsPath(t *testing.T) {
	previous := defenseClawMachineLayout
	defenseClawMachineLayout = func() machineLayout {
		return newMachineLayout(func() (string, string, error) { return `C:\Program Files`, `C:\ProgramData`, nil })
	}
	t.Cleanup(func() { defenseClawMachineLayout = previous })
	const posixHome = "/home/tester"
	files := []string{
		`/ProgramData/Cisco/DefenseClaw/etc/project.yaml`,
		`/Program Files/Cisco/DefenseClaw/bin/project.exe`,
	}
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, file := range files {
				for _, project := range []string{"", posixHome + "/proj"} {
					if _, got := machineLayoutCall(t, posixHome, project, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
						t.Errorf("Write %s from %q managed=%t pack=%q = %.200s, want allow", file, project, managed, pack, got)
					}
				}
			}
		}
	}
	for _, file := range files {
		if blocked, got := machineLayoutCall(t, `C:\Users\tester`, "", "Write", map[string]any{"file_path": file, "content": "x"}, true, ""); !blocked {
			t.Errorf("Write %s with a Windows home and no directory = %.200s, want protected block", file, got)
		}
	}
}

// A DOS device path (\\.\C:\... or \\?\C:\...) names the volume right after
// the prefix: it is the file on that drive, not a UNC share, in every
// profile. The same file on another drive stays an ordinary one.
func TestMachineLayoutWindowsDOSDevicePathsNameTheFile(t *testing.T) {
	previous := defenseClawMachineLayout
	defenseClawMachineLayout = func() machineLayout {
		return newMachineLayout(func() (string, string, error) { return `C:\Program Files`, `C:\ProgramData`, nil })
	}
	t.Cleanup(func() { defenseClawMachineLayout = previous })
	const home = `C:\Users\tester`
	protected := []string{
		`\\.\C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`//./C:/ProgramData/Cisco/DefenseClaw/etc/config.yaml`,
		`\\.\c:\programdata\cisco\defenseclaw\etc\config.yaml`,
		`\\?\C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`\\.\C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		`\\.\UNC\localhost\C$\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`\\?\UNC\localhost\C$\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		// Each name is read without trailing dots and spaces under every
		// namespace prefix, although the exact prefixes keep them: a look-alike
		// machine folder is a documented false block, never a protected allow.
		`\\?\C:\ProgramData\Cisco\DefenseClaw.\etc\project.yaml`,
		`\\?\C:\ProgramData\Cisco\DefenseClaw \etc\project.yaml`,
		`\\.\C:\ProgramData\Cisco\DefenseClaw.\etc\project.yaml`,
		`\\.\C:\ProgramData\Cisco\DefenseClaw \etc\project.yaml`,
		`\\?\UNC\localhost\C$\ProgramData\Cisco\DefenseClaw.\etc\project.yaml`,
		`\\?\UNC\localhost\C$\ProgramData\Cisco\DefenseClaw \etc\project.yaml`,
		`\\?\UNC\localhost\C$.\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`\\.\UNC\localhost\C$\ProgramData\Cisco\DefenseClaw .\etc\project.yaml`,
	}
	ordinary := []string{
		`\\.\D:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`\\?\D:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`\\.\C:\ProgramData\Cisco\DefenseClaw-Notes\a.txt`,
		`\\.\C:\Users\tester\proj\notes.txt`,
		`\\.\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		`UNC\localhost\C$\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
	}
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, file := range protected {
				if blocked, got := machineLayoutCall(t, home, `D:\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); !blocked {
					t.Errorf("Write %s managed=%t pack=%q = %.200s, want protected block", file, managed, pack, got)
				}
			}
			if pack == "strict" {
				continue
			}
			for _, file := range ordinary {
				if _, got := machineLayoutCall(t, home, `D:\proj`, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
					t.Errorf("Write %s managed=%t pack=%q = %.200s, want allow", file, managed, pack, got)
				}
			}
		}
	}
}

// A Linux home below /mnt/c (a Windows drive mounted into the Linux tree) is a
// POSIX target: its /ProgramData is an ordinary path whatever directory the
// hook reports, for a file tool and a shell write alike. The same /mnt/c
// spelling of a machine file stays protected, and so does a Windows target.
func TestMachineLayoutPOSIXHomeUnderMountedDriveIsAPOSIXTarget(t *testing.T) {
	previous := defenseClawMachineLayout
	defenseClawMachineLayout = func() machineLayout {
		return newMachineLayout(func() (string, string, error) { return `C:\Program Files`, `C:\ProgramData`, nil })
	}
	t.Cleanup(func() { defenseClawMachineLayout = previous })
	files := []string{
		`/ProgramData/Cisco/DefenseClaw/etc/project.yaml`,
		`/Program Files/Cisco/DefenseClaw/bin/project.exe`,
	}
	for _, posixHome := range []string{"/mnt/c/Users/tester", "/cygdrive/c/Users/tester", "/c/Users/tester"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "permissive"} {
				for _, project := range []string{"", posixHome + "/proj", "/mnt/c/proj"} {
					for _, file := range files {
						if _, got := machineLayoutCall(t, posixHome, project, "Write", map[string]any{"file_path": file, "content": "x"}, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
							t.Errorf("Write %s home=%s from %q managed=%t pack=%q = %.200s, want allow", file, posixHome, project, managed, pack, got)
						}
						if _, got := machineLayoutCall(t, posixHome, project, "Bash", map[string]any{"command": "echo x > \"" + file + "\""}, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
							t.Errorf("Bash write %s home=%s from %q managed=%t pack=%q = %.200s, want allow", file, posixHome, project, managed, pack, got)
						}
					}
				}
			}
		}
	}
	for _, file := range []string{
		`/mnt/c/ProgramData/Cisco/DefenseClaw/etc/config.yaml`,
		`/cygdrive/c/ProgramData/Cisco/DefenseClaw/etc/config.yaml`,
	} {
		if blocked, got := machineLayoutCall(t, "/mnt/c/Users/tester", "", "Write", map[string]any{"file_path": file, "content": "x"}, true, ""); !blocked {
			t.Errorf("Write %s from a mounted drive = %.200s, want protected block", file, got)
		}
	}
}
