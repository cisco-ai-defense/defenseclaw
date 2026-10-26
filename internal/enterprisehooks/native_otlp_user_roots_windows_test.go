// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// staleWindowsNativeOTLP is what an earlier per-user install wrote into the
// account's Codex and Claude Code configurations (GAP-0836, R5).
func staleWindowsNativeOTLP(bearer string) map[string]string {
	codex := "model = \"gpt-5\"\r\n[otel]\r\nlog_user_prompt = true\r\n"
	for _, pair := range [][2]string{{"exporter", "logs"}, {"metrics_exporter", "metrics"}, {"trace_exporter", "traces"}} {
		codex += "[otel." + pair[0] + ".otlp-http]\r\nendpoint = 'http://127.0.0.1:19010/v1/" + pair[1] + "'\r\nprotocol = 'json'\r\n" +
			"[otel." + pair[0] + ".otlp-http.headers]\r\nauthorization = 'Bearer " + bearer + "'\r\n" +
			"x-defenseclaw-source = 'codex'\r\nx-defenseclaw-client = 'codex-otel/1.0'\r\n"
	}
	headers := "authorization=Bearer " + bearer + ",x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode"
	claude := `{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","OTEL_LOGS_EXPORTER":"otlp",` +
		`"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:19010","OTEL_EXPORTER_OTLP_HEADERS":"` + headers + `"},"model":"opus"}`
	return map[string]string{"codex": codex, "claudecode": claude}
}

type windowsNativeOTLPRootsFixture struct {
	sid     *windows.SID
	home    string
	dataDir string
	bearer  string
	env     map[string]string
	machine map[string]string
	// volatile is the account's logon environment; readAs counts the
	// configuration reads verify made under the account's token, which
	// fail with readAsErr when it is set (no signed-in session).
	volatile  map[string]string
	readAs    int
	readAsErr error
	// warnings are what the check could not do (windowsNativeOTLPWarn).
	warnings []string
}

func newWindowsNativeOTLPRootsFixture(t *testing.T) *windowsNativeOTLPRootsFixture {
	t.Helper()
	previousImpersonation := windowsEnterpriseTargetImpersonation
	windowsEnterpriseTargetImpersonation = func(*windows.SID, string, func() error) error {
		return errors.New("read-only verification attempted target impersonation")
	}
	f := &windowsNativeOTLPRootsFixture{
		sid:     currentWindowsTestSID(t),
		home:    t.TempDir(),
		bearer:  strings.Repeat("c4", 32),
		env:     map[string]string{},
		machine: map[string]string{},
	}
	f.dataDir = filepath.Join(f.home, ".defenseclaw")
	previousUser, previousMachine := windowsUserEnvironment, windowsMachineEnvironment
	windowsUserEnvironment = func(sid, name string) string {
		if sid != f.sid.String() {
			t.Errorf("the account environment of %s was read for the row of %s", sid, f.sid)
		}
		return f.env[name]
	}
	windowsMachineEnvironment = func(name string) string { return f.machine[name] }
	f.volatile = map[string]string{}
	previousWarn := windowsNativeOTLPWarn
	windowsNativeOTLPWarn = func(message string) { f.warnings = append(f.warnings, message) }
	previousVolatile, previousReadAs := windowsAccountVolatileEnvironment, windowsAccountConfigReadAs
	windowsAccountVolatileEnvironment = func(sid *windows.SID, name string) string {
		if !sid.Equals(f.sid) {
			t.Errorf("the logon environment of %s was read for the row of %s", sid, f.sid)
		}
		return f.volatile[name]
	}
	// The test process is the account, so reading as the account is a
	// direct read.
	windowsAccountConfigReadAs = func(sid *windows.SID, home string, fn func() error) error {
		if !sid.Equals(f.sid) || home != f.home {
			t.Errorf("a configuration of the row of %s was read as %s", f.sid, sid)
		}
		f.readAs++
		if f.readAsErr != nil {
			return f.readAsErr
		}
		return fn()
	}
	t.Cleanup(func() {
		windowsEnterpriseTargetImpersonation = previousImpersonation
		windowsUserEnvironment, windowsMachineEnvironment = previousUser, previousMachine
		windowsAccountVolatileEnvironment, windowsAccountConfigReadAs = previousVolatile, previousReadAs
		windowsNativeOTLPWarn = previousWarn
	})
	for _, scope := range []connector.OTLPPathTokenScope{connector.OTLPScopeCodex, connector.OTLPScopeClaude} {
		path, err := connector.OTLPPathTokenFilePath(f.dataDir, scope)
		if err != nil {
			t.Fatal(err)
		}
		f.write(t, path, f.bearer)
	}
	return f
}

func (f *windowsNativeOTLPRootsFixture) write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeOwned writes a file the account owns, as the account's own agent
// would (an elevated test process otherwise makes Administrators the owner).
func (f *windowsNativeOTLPRootsFixture) writeOwned(t *testing.T, path, body string) {
	t.Helper()
	f.write(t, path, body)
	setWindowsTestPathExactOwner(t, path, f.sid)
}

// repairAsAccount repairs, then gives the files repair rewrote outside the
// profile or behind a link back to the account: in production repair runs
// under the account's token, so what it writes is the account's.
func (f *windowsNativeOTLPRootsFixture) repairAsAccount(t *testing.T, name string, rewritten ...string) {
	t.Helper()
	f.repair(t, name)
	for _, path := range rewritten {
		setWindowsTestPathExactOwner(t, path, f.sid)
	}
}

// outside is a folder outside the profile the account owns.
func (f *windowsNativeOTLPRootsFixture) outside(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	setWindowsTestPathExactOwner(t, dir, f.sid)
	return dir
}

// ownRuntime gives the profile, the data directory and the native OTLP
// credentials to the account (an elevated test process otherwise makes
// Administrators their owner), as when the account's own setup made them;
// with present false it removes the credentials, as for a fresh account.
func (f *windowsNativeOTLPRootsFixture) ownRuntime(t *testing.T, present bool) {
	t.Helper()
	for _, path := range []string{f.home, f.dataDir, filepath.Join(f.dataDir, "hooks")} {
		setWindowsTestPathExactOwner(t, path, f.sid)
	}
	for _, scope := range []connector.OTLPPathTokenScope{connector.OTLPScopeCodex, connector.OTLPScopeClaude} {
		token, err := connector.OTLPPathTokenFilePath(f.dataDir, scope)
		if err != nil {
			t.Fatal(err)
		}
		if !present {
			if err := os.Remove(token); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			continue
		}
		f.writeOwned(t, token, f.bearer)
	}
}

// requireStale fails unless verify named the stale exporter in source.
func (f *windowsNativeOTLPRootsFixture) requireStale(t *testing.T, name, source string, err error) {
	t.Helper()
	f.requireRefusal(t, name, source, err)
	if !strings.Contains(err.Error(), "keeps a native OTLP exporter") {
		t.Fatalf("%s: verify = %v, want the stale exporter in %s read and named", name, err, source)
	}
}

// requireWarning fails unless the last check warned with every part, and
// with no value or path.
func (f *windowsNativeOTLPRootsFixture) requireWarning(t *testing.T, name string, parts ...string) {
	t.Helper()
	all := strings.Join(f.warnings, "\n")
	for _, part := range parts {
		if !strings.Contains(all, part) {
			t.Fatalf("%s: warnings %q, want %q", name, f.warnings, part)
		}
	}
	if strings.Contains(all, f.bearer) || strings.Contains(all, f.home) || strings.Contains(all, `\\`) {
		t.Fatalf("%s: a warning carries a value or a path: %q", name, f.warnings)
	}
}

// requireNeedsSession fails unless verify warned that source is read only
// as the account and the account has no session: the row is not failed for
// it (a failed row closes the account's hooks).
func (f *windowsNativeOTLPRootsFixture) requireNeedsSession(t *testing.T, name, source string) {
	t.Helper()
	f.requireWarning(t, name, "no signed-in session", source)
}

// tokenPath is the earlier per-user install's credential of name.
func (f *windowsNativeOTLPRootsFixture) tokenPath(t *testing.T, name string) string {
	t.Helper()
	token, err := connector.OTLPPathTokenFilePath(f.dataDir, map[string]connector.OTLPPathTokenScope{
		"codex": connector.OTLPScopeCodex, "claudecode": connector.OTLPScopeClaude}[name])
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// windowsTestShare is local reached as a share, through the administrative
// share of its drive.
func windowsTestShare(t *testing.T, local string) string {
	t.Helper()
	volume := filepath.VolumeName(local)
	if len(volume) != 2 || volume[1] != ':' {
		t.Fatalf("%s is not on a drive", local)
	}
	share := `\\localhost\` + volume[:1] + `$` + local[2:]
	if _, err := os.Stat(share); err != nil {
		t.Skipf("the administrative share of %s is not reachable on this host: %v", volume, err)
	}
	return share
}

func (f *windowsNativeOTLPRootsFixture) verify(name string) error {
	f.warnings = nil
	return windowsManagedUserNativeOTLPAbsent(name, f.home, f.dataDir, f.sid)
}

func (f *windowsNativeOTLPRootsFixture) repair(t *testing.T, name string) {
	t.Helper()
	if err := connector.WithUserHomeDir(f.home, func() error {
		removeWindowsManagedUserNativeOTLPAsTarget(name, f.sid, f.home, f.dataDir)
		return nil
	}); err != nil {
		t.Fatalf("%s: repair: %v", name, err)
	}
	if _, err := os.Stat(f.tokenPath(t, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s: repair kept the earlier per-user credential: %v", name, err)
	}
}

func (f *windowsNativeOTLPRootsFixture) requireClean(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "19010") || strings.Contains(string(data), f.bearer) {
		t.Fatalf("%s keeps the stale exporter:\n%s", filepath.Base(path), data)
	}
	if !strings.Contains(string(data), "gpt-5") && !strings.Contains(string(data), "opus") {
		t.Fatalf("%s lost an unrelated setting:\n%s", filepath.Base(path), data)
	}
}

func (f *windowsNativeOTLPRootsFixture) requireRefusal(t *testing.T, name, source string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "native OTLP exporter") || !strings.Contains(err.Error(), source) {
		t.Fatalf("%s: verify = %v, want the stale exporter in %s named", name, err, source)
	}
	if strings.Contains(err.Error(), f.bearer) || strings.Contains(err.Error(), "19010") || strings.Contains(err.Error(), f.home) {
		t.Fatalf("%s: verify error carries a value or a path: %v", name, err)
	}
}

// GAP-0928: the account's CODEX_HOME or CLAUDE_CONFIG_DIR (its own or the
// machine's, with %USERPROFILE% and the like expanded as for its processes)
// and the file its per-user setup recorded are configurations the agent
// reads. An exporter there is reported and removed like one in the default
// root, and the credential is revoked only once all of them are clean.
func TestWindowsManagedRowCleansRelocatedAgentConfigurations(t *testing.T) {
	for _, tc := range []struct {
		name, variable, file string
	}{
		{"codex", "CODEX_HOME", "config.toml"},
		{"claudecode", "CLAUDE_CONFIG_DIR", "settings.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWindowsNativeOTLPRootsFixture(t)
			stale := staleWindowsNativeOTLP(f.bearer)[tc.name]
			userRoot := f.outside(t)
			f.env[tc.variable] = userRoot
			// The machine value is shadowed by the account's own.
			machineRoot := f.outside(t)
			f.machine[tc.variable] = machineRoot
			f.writeOwned(t, filepath.Join(machineRoot, tc.file), stale)
			f.writeOwned(t, filepath.Join(userRoot, tc.file), stale)
			recorded := filepath.Join(f.outside(t), tc.file)
			f.writeOwned(t, recorded, stale)
			record, err := json.Marshal(map[string]any{
				"version": 1, "connector": tc.name, "logical_name": tc.file, "path": recorded, "existed": true,
				"pristine_sha256": strings.Repeat("0", 64), "captured_at": "2026-10-01T00:00:00Z",
			})
			if err != nil {
				t.Fatal(err)
			}
			f.write(t, connector.UserAgentConfigRecordPath(f.dataDir, tc.name), string(record))

			f.requireRefusal(t, tc.name, tc.variable+" "+tc.file, f.verify(tc.name))
			f.requireRefusal(t, tc.name, "the recorded "+tc.file, f.verify(tc.name))
			f.repairAsAccount(t, tc.name, filepath.Join(userRoot, tc.file), recorded)
			if err := f.verify(tc.name); err != nil {
				t.Fatalf("verify after repair: %v", err)
			}
			f.requireClean(t, filepath.Join(userRoot, tc.file))
			f.requireClean(t, recorded)
			if data, _ := os.ReadFile(filepath.Join(machineRoot, tc.file)); string(data) != stale {
				t.Fatal("the shadowed machine root was changed: the agent does not read it")
			}

			// With only the machine value set, that root is the account's.
			// Repair revoked the credential, and only a known credential
			// owns an OTLP value (base ownership rule), so issue it again.
			f.ownRuntime(t, true)
			delete(f.env, tc.variable)
			f.requireRefusal(t, tc.name, tc.variable+" "+tc.file, f.verify(tc.name))
			f.repairAsAccount(t, tc.name, filepath.Join(machineRoot, tc.file))
			if err := f.verify(tc.name); err != nil {
				t.Fatalf("verify after the machine root repair: %v", err)
			}

			// A profile variable expands as it does for the account.
			inProfile := filepath.Join(f.home, "agent-root")
			f.env[tc.variable] = `%USERPROFILE%\agent-root`
			f.write(t, filepath.Join(inProfile, tc.file), stale)
			f.ownRuntime(t, true)
			f.requireRefusal(t, tc.name, tc.variable+" "+tc.file, f.verify(tc.name))
			f.repair(t, tc.name)
			f.requireClean(t, filepath.Join(inProfile, tc.file))

			// A value that names no folder cannot be checked: a warning, never
			// a failed row.
			f.env[tc.variable] = `%DC_NOT_SET%\agent-root`
			if err := f.verify(tc.name); err != nil {
				t.Fatalf("an unresolvable %s failed the row: %v", tc.variable, err)
			}
			f.requireWarning(t, tc.name, tc.variable)
		})
	}
}

// GAP-0929: a configuration reached through a junction is the file the agent
// reads. Verify follows the link and judges that file: a stale exporter there
// is reported and repair removes it through the link, which stays. A link to
// a file the account does not own is never read or changed for the row: a
// warning names the source and says what to do, the row is not failed for
// it, and repair revokes the credential.
func TestWindowsManagedRowResolvesLinkedAgentConfigurations(t *testing.T) {
	for _, tc := range []struct{ name, dir, file string }{
		{"codex", ".codex", "config.toml"},
		{"claudecode", ".claude", "settings.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWindowsNativeOTLPRootsFixture(t)
			stale := staleWindowsNativeOTLP(f.bearer)[tc.name]
			target := f.outside(t)
			f.writeOwned(t, filepath.Join(target, tc.file), stale)
			link := filepath.Join(f.home, tc.dir)
			makeTestJunction(t, link, target)

			f.requireRefusal(t, tc.name, tc.file, f.verify(tc.name))
			f.repairAsAccount(t, tc.name, filepath.Join(target, tc.file))
			if err := f.verify(tc.name); err != nil {
				t.Fatalf("verify after repair through the junction: %v", err)
			}
			f.requireClean(t, filepath.Join(target, tc.file))
			if err := rejectWindowsReparseChain(filepath.Join(link, tc.file)); err == nil {
				t.Fatal("repair replaced the account's junction")
			}

			// The same link to another owner's file.
			foreign := t.TempDir()
			f.write(t, filepath.Join(foreign, tc.file), stale)
			administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
			if err != nil {
				t.Fatal(err)
			}
			setWindowsTestPathExactOwner(t, filepath.Join(foreign, tc.file), administrators)
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			makeTestJunction(t, link, foreign)
			f.write(t, f.tokenPath(t, tc.name), f.bearer)
			err = f.verify(tc.name)
			if err == nil || !strings.Contains(err.Error(), "hooks/") {
				t.Fatalf("verify with the credential left = %v, want it named for repair", err)
			}
			f.requireWarning(t, tc.name, "does not own", tc.file)
			if strings.Contains(strings.Join(f.warnings, " "), foreign) {
				t.Fatalf("warning names the foreign file: %q", f.warnings)
			}
			f.repair(t, tc.name)
			if data, _ := os.ReadFile(filepath.Join(foreign, tc.file)); string(data) != stale {
				t.Fatal("repair changed a file the account does not own")
			}
			if err := f.verify(tc.name); err != nil {
				t.Fatalf("verify after repair = %v, want a warning, not a failed row", err)
			}
			f.requireWarning(t, tc.name, "does not own")
		})
	}
}

// GAP-1043: Windows resolves APPDATA and LOCALAPPDATA from User Shell Folders,
// not by appending AppData to USERPROFILE. A per-user setup record may still
// name the old file after an account moves its known folder.
func TestWindowsManagedRowCleansRedirectedAppDataNativeOTLP(t *testing.T) {
	for _, tc := range []struct {
		name, variable, file, folderVariable, shellValue string
	}{
		{"codex roaming", "CODEX_HOME", "config.toml", "APPDATA", "AppData"},
		{"codex local", "CODEX_HOME", "config.toml", "LOCALAPPDATA", "Local AppData"},
		{"claudecode roaming", "CLAUDE_CONFIG_DIR", "settings.json", "APPDATA", "AppData"},
		{"claudecode local", "CLAUDE_CONFIG_DIR", "settings.json", "LOCALAPPDATA", "Local AppData"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWindowsNativeOTLPRootsFixture(t)
			name := strings.Fields(tc.name)[0]
			redirected := f.outside(t)
			f.env[tc.variable] = "%" + tc.folderVariable + "%\\Moved"
			previousShell := windowsAccountUserShellFolderValue
			windowsAccountUserShellFolderValue = func(sid *windows.SID, value string) (string, error) {
				if !sid.Equals(f.sid) {
					t.Errorf("read another account's User Shell Folders: %s", sid)
				}
				if value == tc.shellValue {
					return redirected, nil
				}
				return filepath.Join(f.home, "AppData", "Local"), nil
			}
			t.Cleanup(func() { windowsAccountUserShellFolderValue = previousShell })

			currentDir := filepath.Join(redirected, "Moved")
			current := filepath.Join(currentDir, tc.file)
			f.writeOwned(t, current, staleWindowsNativeOTLP(f.bearer)[name])
			setWindowsTestPathExactOwner(t, currentDir, f.sid)
			recorded := filepath.Join(f.outside(t), tc.file)
			clean := "model = \"gpt-5\""
			if name == "claudecode" {
				clean = `{"model":"opus"}`
			}
			f.writeOwned(t, recorded, clean)
			record, err := json.Marshal(map[string]any{
				"version": 1, "connector": name, "logical_name": tc.file, "path": recorded, "existed": true,
				"pristine_sha256": strings.Repeat("0", 64), "captured_at": "2026-10-01T00:00:00Z",
			})
			if err != nil {
				t.Fatal(err)
			}
			f.write(t, connector.UserAgentConfigRecordPath(f.dataDir, name), string(record))
			// The elevated lane creates temporary directories under the
			// Administrators group; production repair runs as this account.
			for _, path := range []string{f.home, f.dataDir, filepath.Join(f.dataDir, "hooks")} {
				setWindowsTestPathExactOwner(t, path, f.sid)
			}
			for _, scope := range []connector.OTLPPathTokenScope{connector.OTLPScopeCodex, connector.OTLPScopeClaude} {
				token, err := connector.OTLPPathTokenFilePath(f.dataDir, scope)
				if err != nil {
					t.Fatal(err)
				}
				setWindowsTestPathExactOwner(t, token, f.sid)
			}

			f.requireRefusal(t, name, tc.variable+" "+tc.file, f.verify(name))
			f.repairAsAccount(t, name, current)
			f.requireClean(t, current)
			if err := f.verify(name); err != nil {
				t.Fatalf("verify after redirected config repair: %v", err)
			}
		})
	}
}

// AppData redirected to a share, by User Shell Folders or through the
// account's home share, is where its agent reads its configuration. A fresh
// account verifies there; a stale exporter there is reported. Repair cannot
// edit a share durably, so it leaves that file, revokes the credential, and
// verify warns to remove the exporter there by hand without failing the row.
// Verify reads the share as the account (the service would reach it as the
// computer) and only warns while the account has no signed-in session to
// read it under.
func TestWindowsManagedRowChecksNetworkAppDataAsTheAccount(t *testing.T) {
	for _, tc := range []struct {
		name, variable, file, folderVariable, shellName string
		homeShare                                       bool
	}{
		{"codex roaming", "CODEX_HOME", "config.toml", "APPDATA", "AppData", false},
		{"claudecode local", "CLAUDE_CONFIG_DIR", "settings.json", "LOCALAPPDATA", "Local AppData", false},
		{"codex home share", "CODEX_HOME", "config.toml", "APPDATA", "AppData", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWindowsNativeOTLPRootsFixture(t)
			name := strings.Fields(tc.name)[0]
			account, _, _, err := f.sid.LookupAccount("")
			if err != nil || account == "" {
				t.Fatalf("look up the test account: %v", err)
			}
			local := f.outside(t)
			share := windowsTestShare(t, local)
			shellValue := share + `\%USERNAME%\AppData`
			if tc.homeShare {
				f.volatile["HOMESHARE"] = share + `\` + account
				shellValue = `%HOMESHARE%\AppData`
			}
			f.env[tc.variable] = "%" + tc.folderVariable + "%\\Moved"
			previousShell := windowsAccountUserShellFolderValue
			windowsAccountUserShellFolderValue = func(sid *windows.SID, value string) (string, error) {
				if !sid.Equals(f.sid) {
					t.Errorf("read another account's User Shell Folders: %s", sid)
				}
				if value == tc.shellName {
					return shellValue, nil
				}
				return "", nil
			}
			t.Cleanup(func() { windowsAccountUserShellFolderValue = previousShell })
			agentDir := filepath.Join(local, account, "AppData", "Moved")
			if err := os.MkdirAll(agentDir, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{filepath.Join(local, account), filepath.Join(local, account, "AppData"), agentDir} {
				setWindowsTestPathExactOwner(t, dir, f.sid)
			}
			source := tc.variable + " " + tc.file

			f.ownRuntime(t, false)
			if err := f.verify(name); err != nil {
				t.Fatalf("a fresh account with AppData on a share failed verify: %v", err)
			}
			if f.readAs == 0 {
				t.Fatal("verify did not read the share as the account")
			}

			f.ownRuntime(t, true)
			f.writeOwned(t, filepath.Join(agentDir, tc.file), staleWindowsNativeOTLP(f.bearer)[name])
			err = f.verify(name)
			if err == nil || !strings.Contains(err.Error(), "hooks/") {
				t.Fatalf("verify with the credential left = %v, want it named for repair", err)
			}
			f.requireWarning(t, name, source+" on a network share", "by hand")
			if strings.Contains(strings.Join(f.warnings, " "), "localhost") {
				t.Fatalf("warning names the share: %q", f.warnings)
			}

			f.readAsErr = errors.New("no session")
			_ = f.verify(name)
			f.requireNeedsSession(t, name, source)
			f.readAsErr = nil

			// Repair cannot edit a share durably: it leaves the file and
			// revokes the credential. Only a known credential owns an OTLP
			// value, so the revoked one left on the share is no longer
			// DefenseClaw's and verify passes the row.
			stale := staleWindowsNativeOTLP(f.bearer)[name]
			f.repair(t, name)
			if data, _ := os.ReadFile(filepath.Join(agentDir, tc.file)); string(data) != stale {
				t.Fatal("repair edited a configuration on a share")
			}
			if err := f.verify(name); err != nil {
				t.Fatalf("verify after repair = %v, want the row passed", err)
			}

			// Once the account removes it, verify has nothing to warn about.
			clean := `model = "gpt-5"`
			if name == "claudecode" {
				clean = `{"model":"opus"}`
			}
			f.writeOwned(t, filepath.Join(agentDir, tc.file), clean)
			if err := f.verify(name); err != nil || len(f.warnings) != 0 {
				t.Fatalf("verify after the exporter on the share was removed: %v %q", err, f.warnings)
			}
		})
	}
}

// A configuration on a drive the service does not have as the account has it
// (the account's mapped drive is remote, or missing for the service) is read
// as the account: the service would find no file there and pass a stale
// exporter, or judge another file than the agent reads.
func TestWindowsManagedRowReadsMappedDriveConfigAsTheAccount(t *testing.T) {
	missing := ""
	for letter := 'Z'; letter >= 'D'; letter-- {
		if windowsDriveType(string(letter)+`:\`) == windows.DRIVE_NO_ROOT_DIR {
			missing = string(letter) + ":"
			break
		}
	}
	f := newWindowsNativeOTLPRootsFixture(t)
	root := f.outside(t)
	f.env["CODEX_HOME"] = root
	f.writeOwned(t, filepath.Join(root, "config.toml"), staleWindowsNativeOTLP(f.bearer)["codex"])
	drive := filepath.VolumeName(root) + `\`
	previous := windowsDriveType
	windowsDriveType = func(r string) uint32 {
		if strings.EqualFold(r, drive) {
			return windows.DRIVE_REMOTE
		}
		return previous(r)
	}
	t.Cleanup(func() { windowsDriveType = previous })

	// The profile is on the same drive, so its default file is the first
	// one read as the account.
	f.readAsErr = errors.New("no session")
	_ = f.verify("codex")
	f.requireNeedsSession(t, "codex", "config.toml")
	f.readAsErr = nil
	f.requireStale(t, "codex", "CODEX_HOME config.toml", f.verify("codex"))
	if f.readAs == 0 {
		t.Fatal("verify read a configuration on a remote drive as the service")
	}

	if missing == "" {
		t.Skip("every drive letter is in use on this host")
	}
	windowsDriveType = previous
	f.env["CODEX_HOME"] = missing + `\codex`
	f.readAsErr = errors.New("no session")
	_ = f.verify("codex")
	f.requireNeedsSession(t, "codex", "CODEX_HOME config.toml")
}

// A configuration the service is refused (by its DACL, or through a link
// that reaches a share) is read again as the account.
func TestWindowsManagedRowRereadsRefusedConfigAsTheAccount(t *testing.T) {
	f := newWindowsNativeOTLPRootsFixture(t)
	path := connector.UserNativeOTLPConfigPathFor("codex", f.home)
	f.write(t, path, staleWindowsNativeOTLP(f.bearer)["codex"])
	sid := f.sid.String()
	setDACL := func(sddl string) {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	allowed := "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)"
	setDACL("D:P(D;;0x1;;;" + sid + ")(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	t.Cleanup(func() { setDACL(allowed) })
	previous := windowsAccountConfigReadAs
	windowsAccountConfigReadAs = func(sid *windows.SID, home string, fn func() error) error {
		// The account's own rights let it read its file.
		setDACL(allowed)
		return previous(sid, home, fn)
	}
	t.Cleanup(func() { windowsAccountConfigReadAs = previous })

	f.requireStale(t, "codex", "config.toml", f.verify("codex"))
	if f.readAs != 1 {
		t.Fatalf("verify read the refused configuration as the account %d times, want once", f.readAs)
	}
}

// An AppData folder whose User Shell Folders value cannot be read (the
// account's hive is not loaded) is never guessed: the configuration under it
// is not judged, verify warns instead of failing the row, and repair revokes
// the credential.
func TestWindowsManagedRowWarnsOnUnknownAppDataFolder(t *testing.T) {
	for _, variable := range []string{"APPDATA", "LOCALAPPDATA"} {
		t.Run(variable, func(t *testing.T) {
			f := newWindowsNativeOTLPRootsFixture(t)
			f.env["CODEX_HOME"] = "%" + variable + "%\\Codex"
			guessed := filepath.Join(f.home, "AppData", "Roaming", "Codex", "config.toml")
			if variable == "LOCALAPPDATA" {
				guessed = filepath.Join(f.home, "AppData", "Local", "Codex", "config.toml")
			}
			stale := staleWindowsNativeOTLP(f.bearer)["codex"]
			f.write(t, guessed, stale)
			previousShell := windowsAccountUserShellFolderValue
			windowsAccountUserShellFolderValue = func(*windows.SID, string) (string, error) {
				return "", errors.New("profile hive unavailable")
			}
			t.Cleanup(func() { windowsAccountUserShellFolderValue = previousShell })

			if err := f.verify("codex"); err == nil || strings.Contains(err.Error(), "CODEX_HOME") {
				t.Fatalf("verify = %v, want only the credential named for repair", err)
			}
			f.requireWarning(t, "codex", "CODEX_HOME", "cannot be determined")
			f.repair(t, "codex")
			if data, _ := os.ReadFile(guessed); string(data) != stale {
				t.Fatal("repair edited a guessed AppData folder")
			}
			if err := f.verify("codex"); err != nil {
				t.Fatalf("verify after repair = %v, want a warning, not a failed row", err)
			}
			f.requireWarning(t, "codex", "CODEX_HOME", "cannot be determined")
		})
	}
}
