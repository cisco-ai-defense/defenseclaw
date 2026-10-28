// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// GAP-0723: every configured Windows hook must have an enrollment path.
// Empty connector blocks still count, and removed IDs must be checked before
// migration can erase them from the decoded runtime candidate.
func TestWindowsStandaloneConfigPreflightRefusesUnsupportedConnectors(t *testing.T) {
	for _, name := range []string{"openhands", "omnigent", "openclaw", "zeptoclaw", "gemini", "unknown-agent"} {
		t.Run(name, func(t *testing.T) {
			raw := []byte("guardrail:\n  connectors:\n    codex: {}\n    " + name + ": {}\n")
			if err := refuseUnsupportedWindowsGuardrailConnectors(raw); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("unsupported %s accepted: %v", name, err)
			}
		})
	}
	for _, name := range []string{"claudecode", "claude-code", "codex", "cursor", "amp", "copilot", "hermes", "opencode"} {
		t.Run("supported-"+name, func(t *testing.T) {
			raw := []byte("guardrail:\n  connectors:\n    " + name + ": {}\n")
			if err := refuseUnsupportedWindowsGuardrailConnectors(raw); err != nil {
				t.Fatalf("supported %s refused: %v", name, err)
			}
		})
	}
}

// GAP-0705: these values pass the gateway's generic compiler, but the
// installed Windows service rejects them after config.yaml is replaced.
// Ensure must refuse them while the previous config is still in place.
func TestWindowsStandaloneConfigPreflightRefusesForeignRuntimePaths(t *testing.T) {
	previousLayout, previousSource := windowsEnterpriseStandaloneLayoutForPreflight, windowsEnterpriseStandaloneConfigSource
	t.Cleanup(func() {
		windowsEnterpriseStandaloneLayoutForPreflight, windowsEnterpriseStandaloneConfigSource = previousLayout, previousSource
	})
	windowsEnterpriseStandaloneConfigSource = func(string) error { return nil }
	root := t.TempDir()
	installed := filepath.Join(root, "etc", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(installed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, []byte(standaloneGatewayCheckConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	windowsEnterpriseStandaloneLayoutForPreflight = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{
			GOOS: "windows", ConfigPath: installed, DataDir: filepath.Join(root, "runtime"),
			SecretsDir: filepath.Join(root, "secrets"), ServiceUser: `NT SERVICE\DefenseClawGateway`,
		}, nil
	}
	for _, tc := range []struct {
		name, body, key string
	}{
		{"macOS data_dir", "data_dir: /opt/cisco/defenseclaw/runtime\n" + standaloneGatewayCheckConfig, "data_dir"},
		{"Linux data_dir", "data_dir: /var/lib/defenseclaw\n" + standaloneGatewayCheckConfig, "data_dir"},
		{"foreign API bind", strings.Replace(standaloneGatewayCheckConfig, "api_bind: 127.0.0.1", "api_bind: 0.0.0.0", 1), "gateway API must bind to exact canonical 127.0.0.1"},
		// A new gateway.api_port is accepted before the first install
		// (GAP-0601); moving the port of an installed deployment is refused
		// before any service stops by refuseWindowsEnterpriseAPIPortChange
		// (GAP-0865, TestWindowsEnterpriseAPIPortChangeIsRefusedBeforeAnyStop).
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := filepath.Join(root, strings.ReplaceAll(tc.name, " ", "-")+".yaml")
			if err := os.WriteFile(candidate, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			err := windowsEnterpriseStandaloneConfigPreflight(candidate)
			if err == nil || !strings.Contains(err.Error(), tc.key) || !strings.Contains(err.Error(), "nothing was changed") {
				t.Fatalf("preflight = %v, want a pre-swap refusal naming %s", err, tc.key)
			}
			got, readErr := os.ReadFile(installed)
			if readErr != nil || string(got) != standaloneGatewayCheckConfig {
				t.Fatalf("installed config changed: %q, %v", got, readErr)
			}
		})
	}
}

// Setup re-stamps the fixed runtime directory's ACL during ensure. An
// inherited Users write ACE there is repairable drift, so it must not stop
// a valid supplied config before Setup can do that repair.
func TestWindowsStandaloneConfigPreflightAllowsRepairableRuntimeACLDrift(t *testing.T) {
	previousLayout, previousSource := windowsEnterpriseStandaloneLayoutForPreflight, windowsEnterpriseStandaloneConfigSource
	t.Cleanup(func() {
		windowsEnterpriseStandaloneLayoutForPreflight, windowsEnterpriseStandaloneConfigSource = previousLayout, previousSource
	})
	windowsEnterpriseStandaloneConfigSource = func(string) error { return nil }
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Skipf("resolve ProgramData: %v", err)
	}
	root, err := os.MkdirTemp(programData, "dc-ensure-acl-test-")
	if err != nil {
		t.Skipf("create a fixture under ProgramData: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("icacls.exe", root, "/inheritance:r", "/grant:r",
		"*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX").CombinedOutput(); err != nil {
		t.Skipf("set trusted fixture ACL: %v: %s", err, output)
	}
	if output, err := exec.Command("icacls.exe", root, "/setowner", "*S-1-5-32-544", "/T", "/C").CombinedOutput(); err != nil {
		t.Skipf("set fixture owner: %v: %s", err, output)
	}
	const serviceUser = `NT SERVICE\DefenseClawGateway`
	if err := managed.ValidateTrustedServiceRuntimeDir(runtimeDir, "managed data_dir", serviceUser); err != nil {
		t.Fatalf("the undrifted fixed runtime directory is untrusted: %v", err)
	}
	if output, err := exec.Command("icacls.exe", runtimeDir, "/grant", "*S-1-5-32-545:(OI)(CI)M").CombinedOutput(); err != nil {
		t.Fatalf("drift runtime ACL: %v: %s", err, output)
	}
	if err := managed.ValidateTrustedServiceRuntimeDir(runtimeDir, "managed data_dir", serviceUser); err == nil {
		t.Fatal("the Users write ACE did not make the runtime directory untrusted")
	}
	installed := filepath.Join(root, "etc", "config.yaml")
	windowsEnterpriseStandaloneLayoutForPreflight = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{
			GOOS: "windows", ConfigPath: installed, DataDir: runtimeDir,
			SecretsDir: filepath.Join(root, "secrets"), ServiceUser: serviceUser,
		}, nil
	}
	candidate := filepath.Join(root, "candidate.yaml")
	if err := os.WriteFile(candidate, []byte(standaloneGatewayCheckConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := windowsEnterpriseStandaloneConfigPreflight(candidate); err != nil {
		t.Fatalf("repairable fixed runtime ACL drift refused before ensure: %v", err)
	}
}

// GAP-0966: a destination secret read from an environment variable is
// refused before anything changes, set or unset, naming the destination and
// the protected-credential fields, never the per-user `keys set`.
func TestWindowsStandaloneConfigPreflightRefusesEnvironmentSecrets(t *testing.T) {
	source, layout := windowsEnterpriseStandaloneConfigSource, windowsEnterpriseStandaloneLayoutForPreflight
	windowsEnterpriseStandaloneConfigSource = func(string) error { return nil }
	windowsEnterpriseStandaloneLayoutForPreflight = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{}, errors.New("no layout in this test")
	}
	t.Cleanup(func() {
		windowsEnterpriseStandaloneConfigSource, windowsEnterpriseStandaloneLayoutForPreflight = source, layout
	})
	path := filepath.Join(t.TempDir(), "w3-envref.yaml")
	body := "config_version: 9\nobservability:\n  destinations:\n    - name: eoi-hec\n      kind: splunk_hec\n" +
		"      endpoint: https://hec.example.test:8088/services/collector\n      token_env: EO3_REF\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "set"} {
		t.Setenv("EO3_REF", value)
		err := windowsEnterpriseStandaloneConfigPreflight(path)
		got := ""
		if err != nil {
			got = err.Error()
		}
		for _, want := range []string{"(eoi-hec) token_env reads a secret from an environment variable", "token_credential",
			"enterprise secret set", "nothing was changed"} {
			if !strings.Contains(got, want) {
				t.Fatalf("EO3_REF=%q: preflight = %q, want it to contain %q", value, got, want)
			}
		}
		if strings.Contains(got, "keys set") {
			t.Fatalf("EO3_REF=%q: preflight names the per-user keys set: %q", value, got)
		}
	}
}

// windowsEnterpriseProductionScopeSHA256 is the scope
// Get-DefenseClawStableScopeSHA256 gives the production standalone layout
// on a host whose roots are C:\Program Files and C:\ProgramData. The
// PowerShell contract (test_lifecycle_scope_hash_matches_the_cli) pins the
// same value from the module.
const windowsEnterpriseProductionScopeSHA256 = "809e5e9c874a36d15aa81e190647f223510045d58cbf5a3dc5948b2fd6c7a0e1"

func TestWindowsEnterpriseLifecycleScopeSHA256MatchesTheInstaller(t *testing.T) {
	for _, values := range [][]string{
		{`C:\Program Files\Cisco\DefenseClaw`, `C:\ProgramData\Cisco\DefenseClaw`, "DefenseClawGateway", "DefenseClawHookGuardian"},
		{`c:\program files\cisco\defenseclaw`, `C:\PROGRAMDATA\Cisco\DefenseClaw`, "defenseclawgateway", "DEFENSECLAWHOOKGUARDIAN"},
	} {
		if got := windowsEnterpriseLifecycleScopeSHA256(values...); got != windowsEnterpriseProductionScopeSHA256 {
			t.Fatalf("scope of %q = %s, want %s", values, got, windowsEnterpriseProductionScopeSHA256)
		}
	}
	roots := winpath.EnterpriseRoots{InstallRoot: `C:\Program Files\Cisco\DefenseClaw`, StateRoot: `C:\ProgramData\Cisco\DefenseClaw`,
		LifecycleDir: `C:\ProgramData\Cisco\DefenseClaw-Lifecycle`}
	for _, opts := range []*windowsEnterpriseLifecycleOptions{
		nil,
		{},
		{installRoot: `C:\Program Files\Cisco\DefenseClaw\`, stateRoot: `c:\programdata\cisco\defenseclaw\`,
			gatewayServiceName: "DefenseClawGateway", guardianServiceName: "DefenseClawHookGuardian"},
	} {
		paths := windowsEnterpriseStandaloneRecoveryRecordPaths(roots, opts)
		want := `C:\ProgramData\Cisco\DefenseClaw-Lifecycle\install-rollback-` + windowsEnterpriseProductionScopeSHA256 + ".json"
		if len(paths) != 4 || !strings.EqualFold(paths[0], `C:\ProgramData\Cisco\DefenseClaw\install\pending.json`) || paths[3] != want {
			t.Fatalf("recovery records of %+v = %q", opts, paths)
		}
	}
}

// S2 review (loop round 2): the lifecycle leaves to the installer every
// refusal it would read from the deployment record while a record of an
// interrupted lifecycle of this run's scope waits for the installer's
// recovery, which runs first and can change it: a pending transaction under
// the scope's StateRoot, and the scope's state-purge intent, self-uninstall
// receipt or install-rollback intent in the lifecycle folder. A record of
// another scope (a certification run's beside production, production's
// beside a certification run) is not the run's: the installer, which looks
// only at its own scope's paths, would refuse after the session keys went.
// The helper files a self-uninstall leaves, another receipt, a temporary
// name and a folder are no record either.
func TestWindowsEnterpriseStandaloneRecoveryRecords(t *testing.T) {
	base := t.TempDir()
	roots := winpath.EnterpriseRoots{
		InstallRoot:  filepath.Join(base, "pf", "Cisco", "DefenseClaw"),
		StateRoot:    filepath.Join(base, "pd", "Cisco", "DefenseClaw"),
		LifecycleDir: filepath.Join(base, "pd", "Cisco", "DefenseClaw-Lifecycle"),
	}
	production := &windowsEnterpriseLifecycleOptions{}
	certification := &windowsEnterpriseLifecycleOptions{
		installRoot:         filepath.Join(base, "pf", "Cisco", "DefenseClaw-Cert", "0123456789"),
		stateRoot:           filepath.Join(base, "pd", "Cisco", "DefenseClaw-Cert", "0123456789"),
		gatewayServiceName:  "DefenseClawCertGateway_0123456789",
		guardianServiceName: "DefenseClawCertGuardian_0123456789",
	}
	// The same production scope as the CLI may spell it: other case, a
	// trailing separator, the default service names given.
	spelled := &windowsEnterpriseLifecycleOptions{
		installRoot:         strings.ToUpper(roots.InstallRoot) + `\`,
		stateRoot:           strings.ToLower(roots.StateRoot) + `\`,
		gatewayServiceName:  "defenseclawgateway",
		guardianServiceName: "DefenseClawHookGuardian",
	}
	scope := func(opts *windowsEnterpriseLifecycleOptions) string {
		paths := windowsEnterpriseStandaloneRecoveryRecordPaths(roots, opts)
		name := filepath.Base(paths[len(paths)-1])
		return strings.TrimSuffix(strings.TrimPrefix(name, "install-rollback-"), ".json")
	}
	own, other := scope(production), scope(certification)
	if own == other || scope(spelled) != own {
		t.Fatalf("scopes: production %s, certification %s, spelled %s", own, other, scope(spelled))
	}
	type want struct{ production, certification bool }
	for _, tc := range []struct {
		name  string
		files []string
		dirs  []string
		want  want
	}{
		{name: "nothing recorded"},
		{name: "production pending transaction", files: []string{filepath.Join(roots.StateRoot, "install", "pending.json")},
			want: want{production: true}},
		{name: "certification pending transaction", files: []string{filepath.Join(certification.stateRoot, "install", "pending.json")},
			want: want{certification: true}},
		{name: "production state-purge intent", files: []string{"purge-" + own + ".json"}, want: want{production: true}},
		{name: "production self-uninstall receipt", files: []string{"self-uninstall-" + own + ".json"}, want: want{production: true}},
		{name: "production install-rollback intent", files: []string{"install-rollback-" + own + ".json"}, want: want{production: true}},
		{name: "certification state-purge intent", files: []string{"purge-" + other + ".json"}, want: want{certification: true}},
		{name: "certification self-uninstall receipt", files: []string{"self-uninstall-" + other + ".json"}, want: want{certification: true}},
		{name: "certification install-rollback intent", files: []string{"install-rollback-" + other + ".json"}, want: want{certification: true}},
		{name: "a third scope's records", files: []string{
			"purge-" + strings.Repeat("ab", 32) + ".json",
			"self-uninstall-" + strings.Repeat("ab", 32) + ".json",
			"install-rollback-" + strings.Repeat("ab", 32) + ".json",
		}},
		{name: "not a recovery record", files: []string{
			"lifecycle.lock",
			"managed-hook-contract-cleanup-" + own + ".json",
			"managed-hook-contract-cleanup-" + own + ".report.json",
			"self-uninstall-" + own + ".ps1",
			"install-rollback-" + own + ".json.tmp",
		}, dirs: []string{
			"purge-" + own + ".json",
			"self-uninstall-" + own + ".environment",
			filepath.Join(roots.StateRoot, "install", "pending.json"),
		}},
	} {
		if err := os.RemoveAll(base); err != nil {
			t.Fatal(err)
		}
		at := func(name string) string {
			if filepath.IsAbs(name) {
				return name
			}
			return filepath.Join(roots.LifecycleDir, name)
		}
		for _, name := range tc.dirs {
			if err := os.MkdirAll(at(name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range tc.files {
			if err := os.MkdirAll(filepath.Dir(at(name)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(at(name), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got := want{
			production:    windowsEnterpriseStandaloneRecoveryRecords(windowsEnterpriseStandaloneRecoveryRecordPaths(roots, production)),
			certification: windowsEnterpriseStandaloneRecoveryRecords(windowsEnterpriseStandaloneRecoveryRecordPaths(roots, certification)),
		}
		if spelledGot := windowsEnterpriseStandaloneRecoveryRecords(windowsEnterpriseStandaloneRecoveryRecordPaths(roots, spelled)); spelledGot != got.production {
			t.Fatalf("%s: the production scope spelled otherwise = %v, production %v", tc.name, spelledGot, got.production)
		}
		if got != tc.want {
			t.Fatalf("%s: recovery pending = %+v, want %+v", tc.name, got, tc.want)
		}
	}
	// No trusted roots: only the --state-root's pending transaction can be named.
	if paths := windowsEnterpriseStandaloneRecoveryRecordPaths(winpath.EnterpriseRoots{}, production); len(paths) != 0 {
		t.Fatalf("records without roots = %q", paths)
	}
	if paths := windowsEnterpriseStandaloneRecoveryRecordPaths(winpath.EnterpriseRoots{}, certification); len(paths) != 1 {
		t.Fatalf("certification records without roots = %q", paths)
	}
}

// GAP-0865: a config that moves gateway.api_port of an installed deployment
// is refused before any service stops: every user's hooks and the Cursor
// machine hooks name the installed port.
func TestWindowsEnterpriseAPIPortChangeIsRefusedBeforeAnyStop(t *testing.T) {
	previous := windowsEnterpriseConfigAPIPort
	t.Cleanup(func() { windowsEnterpriseConfigAPIPort = previous })
	ports := map[string]int{"": 18970, `C:\stage\same.yaml`: 18970, `C:\stage\moved.yaml`: 18000}
	windowsEnterpriseConfigAPIPort = func(path string) (int, error) { return ports[path], nil }
	opts := &windowsEnterpriseLifecycleOptions{profile: managed.ProfileStandalone, resolvedProfile: managed.ProfileStandalone}
	opts.configPath = `C:\stage\moved.yaml`
	err := refuseWindowsEnterpriseAPIPortChange(opts)
	if err == nil || !strings.Contains(err.Error(), "gateway.api_port from 18970 to 18000") ||
		!strings.Contains(err.Error(), "no service was stopped") {
		t.Fatalf("moved port = %v, want a refusal before any stop", err)
	}
	opts.configPath = `C:\stage\same.yaml`
	if err := refuseWindowsEnterpriseAPIPortChange(opts); err != nil {
		t.Fatalf("unchanged port refused: %v", err)
	}
}
