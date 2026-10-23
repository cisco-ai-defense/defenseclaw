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
		{"foreign API bind", strings.Replace(standaloneGatewayCheckConfig, "api_bind: 127.0.0.1", "api_bind: 0.0.0.0", 1), "gateway.api_bind"},
		{"foreign API port", strings.Replace(standaloneGatewayCheckConfig, "api_port: 18970", "api_port: 18000", 1), "gateway.api_port"},
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

// S2 review (loop round 2): the lifecycle leaves to the installer every
// refusal it would read from the deployment record while a record of an
// interrupted lifecycle waits for the installer's recovery, which runs
// first and can change it: a pending transaction under the run's
// --state-root, and a state-purge intent, self-uninstall receipt or
// install-rollback intent of any scope in the lifecycle folder. The helper
// files a self-uninstall leaves, another receipt, a short name and a
// folder are none of them, and an absent lifecycle folder holds none.
func TestWindowsEnterpriseStandaloneRecoveryRecords(t *testing.T) {
	scope := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name    string
		pending bool
		files   []string
		dirs    []string
		want    bool
	}{
		{name: "nothing recorded"},
		{name: "pending transaction under the state root", pending: true, want: true},
		{name: "state-purge intent", files: []string{"purge-" + scope + ".json"}, want: true},
		{name: "self-uninstall receipt", files: []string{"self-uninstall-" + scope + ".json"}, want: true},
		{name: "install-rollback intent", files: []string{"install-rollback-" + scope + ".json"}, want: true},
		{name: "upper-case scope", files: []string{"install-rollback-" + strings.ToUpper(scope) + ".json"}, want: true},
		{name: "not a recovery record", files: []string{
			"lifecycle.lock",
			"managed-hook-contract-cleanup-" + scope + ".json",
			"managed-hook-contract-cleanup-" + scope + ".report.json",
			"self-uninstall-" + scope + ".ps1",
			"self-uninstall-" + scope + ".environment",
			"purge-0.json",
			"install-rollback-" + scope + ".json.tmp",
		}, dirs: []string{"purge-" + scope + ".json"}},
	} {
		stateRoot, lifecycleDir := t.TempDir(), t.TempDir()
		if tc.pending {
			if err := os.MkdirAll(filepath.Join(stateRoot, "install"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stateRoot, "install", "pending.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range tc.files {
			if err := os.WriteFile(filepath.Join(lifecycleDir, name), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range tc.dirs {
			if err := os.Mkdir(filepath.Join(lifecycleDir, name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if got := windowsEnterpriseStandaloneRecoveryRecords(stateRoot, lifecycleDir); got != tc.want {
			t.Fatalf("%s: recovery pending = %v, want %v", tc.name, got, tc.want)
		}
	}
	if windowsEnterpriseStandaloneRecoveryRecords("", filepath.Join(t.TempDir(), "absent")) {
		t.Fatal("an absent lifecycle folder counts as a recovery record")
	}
}
