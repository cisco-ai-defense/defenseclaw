// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// rel-1-0-10 GAP-0880 (live, dc-ent-win slot 3): an enrolled account signed
// out with its own Copilot and Hermes files rendered by 1.0.10. Retire ended
// ok (still_named empty), Setup 1.0.9 /upgrade went through, and the 1.0.9
// guardian failed both connectors at that account's sign-in: copilot "hook
// files ... hold handlers DefenseClaw did not write"
// (.copilot\hooks\defenseclaw-vscode.json, its hooks as PowerShell
// -EncodedCommand bridges) and hermes "allowlist entry pre_tool_call has a
// tampered DefenseClaw command" (shell-hooks-allowlist.json and config.yaml,
// the hook in forward slashes). Each such file must hold retire back, named
// as the account's, until the account signs in or is skipped.

const gap0880Home = `C:\Users\dcw-std2`

// gap0880AccountFiles are the account's files as 1.0.10 renders them for
// the launch image launch.
func gap0880AccountFiles(t *testing.T, launch string) map[string][]byte {
	t.Helper()
	vscode, err := enterprisepolicy.RenderCopilotVSCodeLocalHooks("windows", launch)
	if err != nil {
		t.Fatal(err)
	}
	command := `"` + strings.ReplaceAll(launch, `\`, "/") + `" hook --connector hermes`
	config, err := yaml.Marshal(map[string]any{"hooks": map[string]any{"pre_tool_call": []any{map[string]any{"command": command, "timeout": 30}}}})
	if err != nil {
		t.Fatal(err)
	}
	allowlist, err := json.MarshalIndent(map[string]any{"approvals": []any{map[string]any{"event": "pre_tool_call", "command": command}}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		gap0880Home + `\.copilot\hooks\` + enterprisepolicy.CopilotVSCodeLocalHookFileName:   vscode,
		gap0880Home + `\.copilot\installed-plugins\defenseclaw\defenseclaw\hooks\hooks.json`: vscode,
		gap0880Home + `\AppData\Local\hermes\config.yaml`:                                    config,
		gap0880Home + `\AppData\Local\hermes\` + connector.HermesAllowlistFileName:           allowlist,
	}
}

func gap0880Scan(bodies map[string][]byte, sid string) func() windowsHookImageConfigScan {
	var files []windowsHookImageConfigFile
	for path := range bodies {
		files = append(files, windowsHookImageConfigFile{Path: path, User: true, Home: gap0880Home, SID: sid})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	read := func(file windowsHookImageConfigFile) ([]byte, error) {
		if body, ok := bodies[file.Path]; ok {
			return body, nil
		}
		return nil, fs.ErrNotExist
	}
	return func() windowsHookImageConfigScan {
		return scanWindowsHookImageConfigFiles(files, hookImageTestBin, read)
	}
}

func TestHookImageRetirePendsOnASignedOutProfilesCopilotAndHermesFiles(t *testing.T) {
	r := newRetireFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(r.recorded["hook"])
	bodies := gap0880AccountFiles(t, hookImageTestBin+`\hooks\`+folder+`\`+winpath.EnterpriseHookImageName)
	steps := r.steps()
	steps.Scan = gap0880Scan(bodies, signedOutAccountSID)
	steps.DeselectSignedOut = func() windowsHookImageDeselection {
		return windowsHookImageDeselection{Errors: map[string]string{}, Profiles: []windowsHookImageSignedOutProfile{{
			SID: signedOutAccountSID, Account: `DCLAB\std2`, Connectors: []string{"copilot", "hermes"},
		}}}
	}
	report := retireWindowsHookImages(steps)
	if report.OK || report.Reason != windowsHookImageRetirePending {
		t.Fatalf("retire ended %v (%s) over the signed-out account's Copilot and Hermes files: %+v", report.OK, report.Reason, report)
	}
	got := map[string]windowsHookImageNamedFile{}
	for _, named := range report.StillNamed {
		got[named.File] = named
	}
	for path := range bodies {
		named, ok := got[path]
		if !ok || !named.Account || named.Unreadable || named.Folder != folder {
			t.Errorf("%s: still_named entry %+v (listed %t), want the account's file naming %s", path, named, ok, folder)
		}
	}
	if len(report.StillNamed) != len(bodies) {
		t.Errorf("still_named = %+v, want exactly the %d account files", report.StillNamed, len(bodies))
	}
	for _, want := range []string{"sign in", "--skip-profile", "Do NOT run an older release's Setup"} {
		if !strings.Contains(report.Error, want) {
			t.Errorf("error does not say %q: %s", want, report.Error)
		}
	}
	// The same files as the transition image renders them (what the 1.0.9
	// guardian accepts) hold nothing back.
	transition := gap0880AccountFiles(t, hookImageTestBin+`\`+winpath.EnterpriseHookImageName)
	steps = r.steps()
	steps.Scan = gap0880Scan(transition, signedOutAccountSID)
	if report := retireWindowsHookImages(steps); !report.OK || len(report.StillNamed) != 0 {
		t.Fatalf("retire over the transition renders = %+v", report)
	}
}

// The administrator's way out for an account that cannot sign in: skip it by
// SID, audited (STEER GAP-0794 ruling).
func TestHookImageRetireSkipsTheSignedOutProfileWithItsAudit(t *testing.T) {
	s := newSkipFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(s.recorded["hook"])
	bodies := gap0880AccountFiles(t, hookImageTestBin+`\hooks\`+folder+`\`+winpath.EnterpriseHookImageName)
	steps := s.skipSteps(skipTestSID)
	steps.Scan = gap0880Scan(bodies, skipTestSID)
	report := retireWindowsHookImages(steps)
	if !report.OK || len(report.StillNamed) != 0 || len(report.SkippedProfiles) != 1 ||
		report.SkippedProfiles[0].SID != skipTestSID || len(report.SkippedProfiles[0].Files) != len(bodies) || len(s.audits) != 1 {
		t.Fatalf("retire with the profile skipped = %+v (audits %d)", report, len(s.audits))
	}
}

// rel-1-0-10 GAP-0882: an account file retire could not read (an elevated
// administrator is denied an account's .codex folder) must not end ok: it is
// named in still_named (account, unreadable, with its cause) and the error
// says to run retire as LocalSystem. A skip of the profile covers it, audited.
func TestHookImageRetirePendsOnAnUnreadableAccountFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows-native twin makes the file unreadable with a deny ACE (TestHookImageRetirePendsOnAnAccountFileItIsDenied)")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 000 file")
	}
	home := t.TempDir()
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[hooks]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	file := windowsHookImageConfigFile{Path: path, User: true, Home: home, SID: skipTestSID}
	read := func(f windowsHookImageConfigFile) ([]byte, error) { return os.ReadFile(f.Path) }
	scan := func() windowsHookImageConfigScan {
		return scanWindowsHookImageConfigFiles([]windowsHookImageConfigFile{file}, hookImageTestBin, read)
	}
	if got := scan(); len(got.Unverified) != 1 || !errors.Is(func() error { _, err := os.ReadFile(path); return err }(), fs.ErrPermission) {
		t.Fatalf("scan of the unreadable file = %+v", got)
	}

	s := newSkipFixture(t)
	steps := s.steps()
	steps.Scan = scan
	report := retireWindowsHookImages(steps)
	if report.OK || report.Reason != windowsHookImageRetirePending || len(report.StillNamed) != 1 {
		t.Fatalf("retire over an unreadable account file = %+v", report)
	}
	named := report.StillNamed[0]
	if named.File != path || !named.Account || !named.Unreadable || named.Folder != windowsHookImageUnknownFolder ||
		!strings.Contains(named.Cause, "permission denied") {
		t.Fatalf("still_named = %+v", named)
	}
	if !strings.Contains(report.Error, "unreadable true") || !strings.Contains(report.Error, "LocalSystem") || !strings.Contains(report.Error, "--skip-profile") {
		t.Fatalf("error = %s", report.Error)
	}

	steps = s.skipSteps(skipTestSID)
	steps.Scan = scan
	report = retireWindowsHookImages(steps)
	if !report.OK || len(report.SkippedProfiles) != 1 || len(report.SkippedProfiles[0].Files) != 1 ||
		!report.SkippedProfiles[0].Files[0].Unreadable || len(s.audits) != 1 {
		t.Fatalf("retire with the unreadable profile skipped = %+v", report)
	}
}

// Retire reads the files a managed install writes beside the watched hook
// configs, at the paths the enterprise policy renders them (rel-1-0-10
// GAP-0880).
func TestManagedAccountHookCompanionPathsMatchTheRenderedFiles(t *testing.T) {
	home := t.TempDir()
	opts := connector.SetupOpts{ManagedEnterprise: true}
	var copilot, hermes, hermesConfig, kiro []string
	if err := connector.WithUserHomeDir(home, func() error {
		copilot = connector.ManagedAccountHookCompanionPaths(connector.NewCopilotConnector(), opts)
		hermes = connector.ManagedAccountHookCompanionPaths(connector.NewHermesConnector(), opts)
		hermesConfig = connector.HookConfigPathsForConnector(connector.NewHermesConnector(), opts)
		kiro = connector.ManagedAccountHookCompanionPaths(connector.NewKiroConnector(), opts)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{enterprisepolicy.CopilotVSCodeLocalHookFilePath(home), enterprisepolicy.CopilotPluginHooksPath(home)}
	if strings.Join(copilot, "|") != strings.Join(want, "|") {
		t.Errorf("copilot companions = %v, want %v", copilot, want)
	}
	if len(hermesConfig) != 1 || len(hermes) != 1 || hermes[0] != filepath.Join(filepath.Dir(hermesConfig[0]), connector.HermesAllowlistFileName) {
		t.Errorf("hermes companions = %v beside %v", hermes, hermesConfig)
	}
	if len(kiro) != 1 || kiro[0] != filepath.Join(home, ".kiro", "agents", "defenseclaw.json") {
		t.Errorf("kiro companions = %v", kiro)
	}
	if got := connector.ManagedAccountHookCompanionPaths(connector.NewCodexConnector(), opts); len(got) != 0 {
		t.Errorf("codex companions = %v", got)
	}
}

// The matcher every account file goes through (rel-1-0-10 GAP-0880, WU2's
// slot-3 files): a Copilot hook file that names the launch folder only inside
// PowerShell -EncodedCommand blobs, a Hermes file that spells it with forward
// slashes, and a plain file with no launch folder (the transition image,
// another install's folder, prose about a folder) that names none.
func TestHookImageFoldersNamedInEncodedForwardSlashAndPlainFiles(t *testing.T) {
	const folder = "2f2cecec41b0ee4b"
	launch := hookImageTestBin + `\hooks\` + folder + `\` + winpath.EnterpriseHookImageName
	files := gap0880AccountFiles(t, launch)
	copilot := files[gap0880Home+`\.copilot\hooks\`+enterprisepolicy.CopilotVSCodeLocalHookFileName]
	if strings.Contains(strings.ToLower(string(copilot)), folder) {
		t.Fatal("the Copilot render names the folder in clear text; the test needs it only inside -EncodedCommand")
	}
	if !strings.Contains(string(copilot), "-EncodedCommand") && !strings.Contains(string(copilot), "-encodedcommand") {
		t.Fatalf("the Copilot render has no -EncodedCommand: %s", copilot)
	}
	hermes := files[gap0880Home+`\AppData\Local\hermes\`+connector.HermesAllowlistFileName]
	if !strings.Contains(string(hermes), "C:/Program Files/") {
		t.Fatalf("the Hermes allowlist does not use forward slashes: %s", hermes)
	}
	for name, body := range map[string][]byte{"copilot -EncodedCommand": copilot, "hermes forward slashes": hermes,
		"hermes config.yaml": files[gap0880Home+`\AppData\Local\hermes\config.yaml`]} {
		if got := windowsHookImageFoldersNamedIn(body, hookImageTestBin); len(got) != 1 || got[0] != folder {
			t.Errorf("%s: folders named = %v, want [%s]", name, got, folder)
		}
	}
	transition := gap0880AccountFiles(t, hookImageTestBin+`\`+winpath.EnterpriseHookImageName)
	plain := map[string][]byte{
		"copilot transition render": transition[gap0880Home+`\.copilot\hooks\`+enterprisepolicy.CopilotVSCodeLocalHookFileName],
		"hermes transition render":  transition[gap0880Home+`\AppData\Local\hermes\`+connector.HermesAllowlistFileName],
		"another install":           []byte(`{"command":"\"D:/Other/bin/hooks/` + folder + `/defenseclaw-hook.exe\" hook --connector hermes"}`),
		"prose":                     []byte("# the launch folder bin\\hooks\\" + folder + " was retired\nmodel: sonnet\n"),
		"empty":                     nil,
	}
	for name, body := range plain {
		if got := windowsHookImageFoldersNamedIn(body, hookImageTestBin); len(got) != 0 {
			t.Errorf("%s: folders named = %v, want none", name, got)
		}
	}
}
