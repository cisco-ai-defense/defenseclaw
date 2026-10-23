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
	t.Cleanup(func() {
		windowsEnterpriseTargetImpersonation = previousImpersonation
		windowsUserEnvironment, windowsMachineEnvironment = previousUser, previousMachine
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

func (f *windowsNativeOTLPRootsFixture) verify(name string) error {
	return windowsManagedUserNativeOTLPAbsent(name, f.home, f.dataDir, f.sid)
}

func (f *windowsNativeOTLPRootsFixture) repair(t *testing.T, name string) {
	t.Helper()
	if err := connector.WithUserHomeDir(f.home, func() error {
		return removeWindowsManagedUserNativeOTLPAsTarget(name, f.sid, f.home, f.dataDir)
	}); err != nil {
		t.Fatalf("%s: repair: %v", name, err)
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
			f.requireRefusal(t, tc.name, tc.variable+" "+tc.file, f.verify(tc.name))
			f.repair(t, tc.name)
			f.requireClean(t, filepath.Join(inProfile, tc.file))

			// A value that names no folder cannot be checked.
			f.env[tc.variable] = `%DC_NOT_SET%\agent-root`
			if err := f.verify(tc.name); err == nil || !strings.Contains(err.Error(), tc.variable) {
				t.Fatalf("an unresolvable %s verified: %v", tc.variable, err)
			}
		})
	}
}

// GAP-0929: a configuration reached through a junction is the file the agent
// reads. Verify follows the link and judges that file: a stale exporter there
// is reported and repair removes it through the link, which stays. A link to
// a file the account does not own is never read or changed for the row: the
// row stays unverified, names the source and says what to do, and the
// credential stays until the account can be checked.
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
			token, err := connector.OTLPPathTokenFilePath(f.dataDir, map[string]connector.OTLPPathTokenScope{
				"codex": connector.OTLPScopeCodex, "claudecode": connector.OTLPScopeClaude}[tc.name])
			if err != nil {
				t.Fatal(err)
			}
			f.write(t, token, f.bearer)
			err = f.verify(tc.name)
			if err == nil || !strings.Contains(err.Error(), "does not own") || !strings.Contains(err.Error(), tc.file) ||
				strings.Contains(err.Error(), foreign) {
				t.Fatalf("verify of a link to another owner's file = %v, want the explicit unverified refusal", err)
			}
			f.repair(t, tc.name)
			if data, _ := os.ReadFile(filepath.Join(foreign, tc.file)); string(data) != stale {
				t.Fatal("repair changed a file the account does not own")
			}
			if _, err := os.Stat(token); err != nil {
				t.Fatalf("the credential was revoked while a configuration could not be checked: %v", err)
			}
			if err := f.verify(tc.name); err == nil || !strings.Contains(err.Error(), "does not own") {
				t.Fatalf("verify after repair = %v, want the row still unverified", err)
			}
		})
	}
}
