// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

func pinWindowsStandaloneProfileForTest(t *testing.T, pinned bool) {
	t.Helper()
	original := windowsEnterpriseStandaloneProcess
	windowsEnterpriseStandaloneProcess = func() bool { return pinned }
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = original })
}

func TestRegisterWindowsStandalonePerUserConnectorsRequiresStandalonePin(t *testing.T) {
	pinWindowsStandaloneProfileForTest(t, false)
	registry := connector.NewRegistry()
	RegisterWindowsStandalonePerUserConnectors(registry)
	for _, name := range WindowsStandalonePerUserConnectorNames() {
		if _, ok := registry.Get(name); ok {
			t.Fatalf("Secure Client registry gained per-user connector %s", name)
		}
	}

	pinWindowsStandaloneProfileForTest(t, true)
	registry = connector.NewRegistry()
	RegisterWindowsStandalonePerUserConnectors(registry)
	for _, name := range WindowsStandalonePerUserConnectorNames() {
		conn, ok := registry.Get(name)
		if !ok {
			t.Fatalf("standalone registry is missing %s", name)
		}
		if !isWindowsStandalonePerUserBuiltin(name, conn) {
			t.Fatalf("registered %s is not the built-in implementation", name)
		}
	}
}

// perUserManagedHarness redirects the per-user machine state into a temporary
// directory owned by the test token, as the generation tests do.
type perUserManagedHarness struct {
	base           string
	dataDir        string
	hookExecutable string
	target         *windows.SID
}

func newPerUserManagedHarness(t *testing.T) perUserManagedHarness {
	t.Helper()
	base := t.TempDir()
	dataDir := filepath.Join(base, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve test SID: %v", err)
	}
	target := user.User.Sid
	for _, path := range []string{dataDir, hookDir} {
		setWindowsTestPathExactOwner(t, path, target)
		if err := setWindowsUserPathProtection(path, target, true); err != nil {
			t.Fatalf("protect target directory %s: %v", path, err)
		}
	}
	originalDir := windowsPerUserManagedRuntimeDirResolver
	originalOwner := windowsManagedPolicyOwnerSID
	originalDirTrust := windowsManagedPolicyDirTrustCheck
	originalAncestorTrust := windowsManagedPolicyAncestorTrustCheck
	originalFileTrust := windowsManagedPolicyFileTrustCheck
	originalMutation := windowsManagedRuntimeSelectorMutationAuthorize
	originalVerify := windowsManagedRuntimeSelectorVerifyAuthorize
	originalHookTrust := windowsEnterpriseHookTrustCheck
	windowsPerUserManagedRuntimeDirResolver = func(name string) (string, error) {
		return filepath.Join(base, windowsPerUserManagedRuntimeParent, name), nil
	}
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return target, nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
	windowsManagedRuntimeSelectorVerifyAuthorize = func() error { return nil }
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		windowsPerUserManagedRuntimeDirResolver = originalDir
		windowsManagedPolicyOwnerSID = originalOwner
		windowsManagedPolicyDirTrustCheck = originalDirTrust
		windowsManagedPolicyAncestorTrustCheck = originalAncestorTrust
		windowsManagedPolicyFileTrustCheck = originalFileTrust
		windowsManagedRuntimeSelectorMutationAuthorize = originalMutation
		windowsManagedRuntimeSelectorVerifyAuthorize = originalVerify
		windowsEnterpriseHookTrustCheck = originalHookTrust
	})
	return perUserManagedHarness{
		base:           base,
		dataDir:        dataDir,
		hookExecutable: filepath.Join(base, "defenseclaw-hook.exe"),
		target:         target,
	}
}

func TestWindowsPerUserManagedRegistrationLifecycle(t *testing.T) {
	h := newPerUserManagedHarness(t)
	const name = "copilot"

	runtime, err := resolveWindowsPerUserManagedHookRuntime(h.hookExecutable, name)
	if err != nil || runtime.PolicyActive || runtime.Registered {
		t.Fatalf("absent enrollment resolved as %s err=%v", runtime, err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	publication, err := PrepareWindowsManagedRuntimeGeneration(WindowsManagedRuntimeGenerationDesired{
		Connector:                  name,
		TargetSID:                  h.target.String(),
		DataDir:                    h.dataDir,
		HookExecutable:             h.hookExecutable,
		GatewayAddr:                "127.0.0.1:18970",
		GatewayServiceName:         "DefenseClawGateway",
		ScopedToken:                "scoped-per-user-token",
		HookContractID:             connector.KnownHookContracts(name)[0].ContractID,
		HookContractLockUpdatedAt:  now,
		HookContractEntryUpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("prepare generation: %v", err)
	}
	if _, err := CommitWindowsManagedRuntimeGeneration(publication); err != nil {
		t.Fatalf("commit generation: %v", err)
	}

	// A selected generation alone never registers the SID.
	if _, err := resolveWindowsPerUserManagedHookRuntime(h.hookExecutable, name); err != nil {
		t.Fatalf("resolve before enrollment: %v", err)
	}

	add := func(current []windowsPerUserManagedEnrollmentTarget) []windowsPerUserManagedEnrollmentTarget {
		return append(current, windowsPerUserManagedEnrollmentTarget{SID: h.target.String(), DataDir: h.dataDir})
	}
	if err := updateWindowsPerUserManagedEnrollment(name, h.hookExecutable, add); err != nil {
		t.Fatalf("publish enrollment: %v", err)
	}
	runtime, err = resolveWindowsPerUserManagedHookRuntime(h.hookExecutable, name)
	if err != nil || !runtime.PolicyActive || !runtime.Registered {
		t.Fatalf("enrolled SID resolved as %s err=%v", runtime, err)
	}
	if runtime.ScopedToken != "scoped-per-user-token" || runtime.GatewayAddr != "127.0.0.1:18970" ||
		runtime.GatewayServiceName != "DefenseClawGateway" || !sameWindowsEnterprisePath(runtime.DataDir, h.dataDir) {
		t.Fatalf("resolved runtime does not match the generation: %s", runtime)
	}

	// The enrollment binds one hook executable; another invoking path fails.
	if _, err := resolveWindowsPerUserManagedHookRuntime(filepath.Join(h.base, "other", "defenseclaw-hook.exe"), name); err == nil {
		t.Fatal("foreign hook executable resolved the enrolled runtime")
	}
	// A different deployment's hook executable cannot rewrite the enrollment.
	if err := updateWindowsPerUserManagedEnrollment(name, filepath.Join(h.base, "other.exe"), add); err == nil {
		t.Fatal("enrollment accepted a second hook executable")
	}

	if err := revokeWindowsPerUserManagedRegistration(name, h.target, h.dataDir, h.hookExecutable); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	enrollmentPath := filepath.Join(h.base, windowsPerUserManagedRuntimeParent, name, windowsPerUserManagedEnrollmentFile)
	if _, err := os.Lstat(enrollmentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty enrollment survived revocation: %v", err)
	}
	snapshot, err := CaptureWindowsManagedRuntimeSelectorTarget(WindowsManagedRuntimeSelectorSnapshotOptions{
		Connector: name, TargetSID: h.target.String(), DataDir: h.dataDir, HookExecutable: h.hookExecutable,
	})
	if err != nil || snapshot.Existed {
		t.Fatalf("selector target survived revocation: existed=%t err=%v", snapshot.Existed, err)
	}
	runtime, err = resolveWindowsPerUserManagedHookRuntime(h.hookExecutable, name)
	if err != nil || runtime.PolicyActive || runtime.Registered {
		t.Fatalf("revoked SID resolved as %s err=%v", runtime, err)
	}
}

func TestWindowsPerUserManagedRuntimeRejectsUnregisteredSID(t *testing.T) {
	h := newPerUserManagedHarness(t)
	other := "S-1-5-21-1000000000-2000000000-3000000000-1234"
	if err := updateWindowsPerUserManagedEnrollment("devin", h.hookExecutable,
		func([]windowsPerUserManagedEnrollmentTarget) []windowsPerUserManagedEnrollmentTarget {
			return []windowsPerUserManagedEnrollmentTarget{{SID: other, DataDir: `C:\Users\other\.defenseclaw`}}
		}); err != nil {
		t.Fatalf("publish enrollment: %v", err)
	}
	runtime, err := resolveWindowsPerUserManagedHookRuntime(h.hookExecutable, "devin")
	if err == nil || !strings.Contains(err.Error(), WindowsManagedSIDUnregisteredReason) {
		t.Fatalf("unregistered SID error = %v", err)
	}
	if !runtime.PolicyActive || runtime.Registered {
		t.Fatalf("unregistered SID runtime = %s", runtime)
	}
}

func TestWindowsPerUserManagedEnrollmentDecodeIsStrict(t *testing.T) {
	valid := windowsPerUserManagedEnrollment{
		SchemaVersion:  windowsPerUserManagedEnrollmentSchema,
		Connector:      "hermes",
		HookExecutable: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		Targets: []windowsPerUserManagedEnrollmentTarget{
			{SID: "S-1-12-1-1111111111-2222222222-3333333333-4000000000", DataDir: `C:\Users\entra\.defenseclaw`},
			{SID: "S-1-5-21-1000000000-2000000000-3000000000-1001", DataDir: `C:\Users\ad\.defenseclaw`},
		},
	}
	data, err := marshalWindowsPerUserManagedEnrollment(valid)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeWindowsPerUserManagedEnrollment(data, "hermes")
	if err != nil {
		t.Fatalf("decode valid enrollment: %v", err)
	}
	if decoded.Targets[0].SID > decoded.Targets[1].SID {
		t.Fatalf("enrollment targets are not sorted: %+v", decoded.Targets)
	}
	for label, mutate := range map[string]func(*windowsPerUserManagedEnrollment){
		"wrong connector":     func(e *windowsPerUserManagedEnrollment) { e.Connector = "devin" },
		"wrong schema":        func(e *windowsPerUserManagedEnrollment) { e.SchemaVersion = 2 },
		"relative executable": func(e *windowsPerUserManagedEnrollment) { e.HookExecutable = `bin\defenseclaw-hook.exe` },
		"no targets":          func(e *windowsPerUserManagedEnrollment) { e.Targets = nil },
		"duplicate SID": func(e *windowsPerUserManagedEnrollment) {
			e.Targets = append(e.Targets, e.Targets[0])
		},
		"noncanonical data dir": func(e *windowsPerUserManagedEnrollment) {
			e.Targets[0].DataDir = `C:\Users\entra\data`
		},
		"bad SID": func(e *windowsPerUserManagedEnrollment) { e.Targets[0].SID = "S-1-bogus" },
	} {
		clone := valid
		clone.Targets = append([]windowsPerUserManagedEnrollmentTarget(nil), valid.Targets...)
		mutate(&clone)
		raw, err := json.Marshal(clone)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeWindowsPerUserManagedEnrollment(raw, "hermes"); err == nil {
			t.Fatalf("%s: decode accepted invalid enrollment", label)
		}
	}
	unknown := strings.Replace(string(data), `"schema_version"`, `"extra": 1, "schema_version"`, 1)
	if _, err := decodeWindowsPerUserManagedEnrollment([]byte(unknown), "hermes"); err == nil {
		t.Fatal("decode accepted an unknown field")
	}
}

func TestCertifyWindowsEnterpriseConnectorPerUserRequiresStandalone(t *testing.T) {
	pinWindowsStandaloneProfileForTest(t, false)
	if err := certifyWindowsEnterpriseConnector("copilot", connector.NewCopilotConnector()); err == nil ||
		!strings.Contains(err.Error(), "standalone") {
		t.Fatalf("Secure Client process certified copilot: %v", err)
	}
	pinWindowsStandaloneProfileForTest(t, true)
	for _, conn := range []connector.Connector{
		connector.NewCopilotConnector(), connector.NewAntigravityConnector(), connector.NewDevinConnector(),
		connector.NewHermesConnector(), connector.NewOpenCodeConnector(), connector.NewAMPConnector(),
	} {
		if err := certifyWindowsEnterpriseConnector(conn.Name(), conn); err != nil {
			t.Fatalf("certify built-in %s: %v", conn.Name(), err)
		}
	}
	if err := certifyWindowsEnterpriseConnector("copilot", connector.NewDevinConnector()); err == nil {
		t.Fatal("certified an impostor implementation under the copilot name")
	}
	if err := certifyWindowsEnterpriseConnector("openhands", connector.NewOpenHandsConnector()); err == nil ||
		!strings.Contains(err.Error(), "refused on native Windows") {
		t.Fatalf("openhands refusal = %v", err)
	}
	// Secure Client connectors keep their exact certification.
	if err := certifyWindowsEnterpriseConnector("codex", connector.NewCodexConnector()); err != nil {
		t.Fatalf("certify codex: %v", err)
	}
}

// The per-user connectors join the registry, the effective hook connectors
// and the managed runtime only in the standalone profile, and fail closed.
func TestWindowsStandalonePerUserConnectorMappings(t *testing.T) {
	pinWindowsStandaloneProfileForTest(t, false)
	if _, ok := newWindowsEnterpriseConnectorRegistry().Get("devin"); ok {
		t.Fatal("Secure Client registry gained devin")
	}
	pinWindowsStandaloneProfileForTest(t, true)
	if _, ok := newWindowsEnterpriseConnectorRegistry().Get("devin"); !ok {
		t.Fatal("standalone registry is missing devin")
	}

	// The effective hook connectors add the per-user ones only in standalone.
	cfg := &config.Config{Guardrail: config.GuardrailConfig{
		Connectors: map[string]config.PerConnectorGuardrailConfig{
			"codex": {}, "copilot": {}, "amp": {}, "openhands": {},
		},
	}}
	pinWindowsStandaloneProfileForTest(t, false)
	if got := EffectiveWindowsHookConnectors(cfg); !reflect.DeepEqual(got, []string{"codex"}) {
		t.Fatalf("Secure Client connectors = %v", got)
	}
	pinWindowsStandaloneProfileForTest(t, true)
	if got := EffectiveWindowsHookConnectors(cfg); !reflect.DeepEqual(got, []string{"amp", "codex", "copilot"}) {
		t.Fatalf("standalone connectors = %v", got)
	}

	// Per-user connectors fail closed; an unmanaged connector keeps its mode.
	for _, name := range WindowsStandalonePerUserConnectorNames() {
		if got := windowsEnterpriseHookFailMode(name, "open"); got != "closed" {
			t.Fatalf("%s fail mode = %q, want closed", name, got)
		}
	}
	if got := windowsEnterpriseHookFailMode("openhands", "open"); got != "open" {
		t.Fatalf("unmanaged connector fail mode changed to %q", got)
	}

	// The managed runtime accepts exactly the per-user connector names.
	for _, name := range []string{"copilot", "antigravity", "devin", "hermes", "kiro", "opencode", "amp"} {
		if got, err := canonicalWindowsManagedRuntimeConnector(name); err != nil || got != name {
			t.Fatalf("%s canonical = %q err=%v", name, got, err)
		}
	}
	for _, name := range []string{"Copilot", "openhands", "Kiro"} {
		if _, err := canonicalWindowsManagedRuntimeConnector(name); err == nil {
			t.Fatalf("%s accepted as a managed runtime connector", name)
		}
	}
}

func TestDiscoverWindowsStandalonePerUserAgentVersions(t *testing.T) {
	home := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	discover := func(name string) string {
		version, _ := standaloneWindowsAgentVersionExplain(home, name)
		return version
	}
	for _, name := range []string{"copilot", "opencode", "amp", "devin", "hermes", "antigravity", "kiro"} {
		if got := discover(name); got != "" {
			t.Fatalf("%s on an empty profile = %q", name, got)
		}
	}
	npm := filepath.Join(home, "AppData", "Roaming", "npm", "node_modules")
	writeWindowsAgentPackageJSON(t, filepath.Join(npm, "@github", "copilot"), "1.0.88")
	writeWindowsAgentPackageJSON(t, filepath.Join(npm, "opencode-ai"), "1.18.32")
	writeWindowsAgentPackageJSON(t, filepath.Join(npm, "@ampcode", "cli"), "0.0.1790438457-ge61352")
	devin := filepath.Join(home, "AppData", "Local", "devin", "cli", "_versions")
	write(filepath.Join(devin, "3000.4.25", "bin", "devin.exe"), "MZ")
	write(filepath.Join(devin, "3000.11.3", "bin", "devin.exe"), "MZ")
	if err := os.MkdirAll(filepath.Join(devin, "3001.0.0"), 0o755); err != nil { // no binary
		t.Fatal(err)
	}
	write(filepath.Join(home, "AppData", "Local", "hermes", "hermes-agent", "install-stamp.json"),
		`{"schemaVersion":2,"baseVersion":"0.21.5","displayVersion":"0.21.5+2583.gf077152"}`)
	write(filepath.Join(home, "AppData", "Local", "agy", "bin", "agy.exe"), "MZ")
	write(filepath.Join(home, ".gemini", "antigravity-cli", "cli.log"),
		"I0926 server.go] Language server version: 1.2.9\nI0926 server.go] Language server version: 1.2.11\n")
	for name, want := range map[string]string{
		"copilot":     "1.0.88",
		"opencode":    "1.18.32",
		"amp":         "0.0.1790438457-ge61352",
		"devin":       "3000.11.3",
		"hermes":      "0.21.5",
		"antigravity": "1.2.11",
	} {
		if got := discover(name); got != want {
			t.Fatalf("%s version = %q, want %q", name, got, want)
		}
	}
	// An Antigravity log without the installed binary is not an install.
	if err := os.Remove(filepath.Join(home, "AppData", "Local", "agy", "bin", "agy.exe")); err != nil {
		t.Fatal(err)
	}
	if got := discover("antigravity"); got != "" {
		t.Fatalf("antigravity without agy.exe = %q", got)
	}

	// Kiro: an IDE at or above the global-hooks floor enrolls a user whose
	// kiro-cli has not run yet; the run copy matching kiro-cli.exe wins.
	ide := filepath.Join(home, "AppData", "Local", "Programs", "Kiro", "resources", "app", "product.json")
	write(ide, `{"nameShort":"Kiro","applicationName":"kiro","version":"1.0.170"}`)
	if got := discover("kiro"); got != "" {
		t.Fatalf("kiro with an IDE below the floor = %q", got)
	}
	// A kiro-cli that has never run is enrolled at the standalone floor, so
	// its first chat is protected.
	kiroCLI := filepath.Join(home, "AppData", "Local", "Kiro-Cli")
	write(filepath.Join(kiroCLI, "kiro-cli.exe"), "MZ-current")
	if got := discover("kiro"); got != standaloneNotGatedAgentFloor("kiro") {
		t.Fatalf("kiro-cli before its first run = %q, want the floor", got)
	}
	write(ide, `{"nameShort":"Kiro","applicationName":"kiro","version":"1.0.190"}`)
	if got := discover("kiro"); got != "1.0.190"+KiroIDEVersionSuffix {
		t.Fatalf("kiro IDE only = %q", got)
	}
	write(filepath.Join(kiroCLI, "run", "chat-cli-2.24.1.exe"), "MZ-current")
	write(filepath.Join(kiroCLI, "run", "chat-cli-2.30.0.exe"), "MZ-other")
	if got := discover("kiro"); got != "2.24.1" {
		t.Fatalf("kiro-cli version = %q, want the run copy matching kiro-cli.exe", got)
	}
	for version, admitted := range map[string]bool{"2.24.1": true, "2.20.0": false, "1.0.190" + KiroIDEVersionSuffix: true, "1.0.170" + KiroIDEVersionSuffix: false} {
		if ok, reason := windowsStandaloneHookContractAdmitted("kiro", version); ok != admitted {
			t.Fatalf("kiro %s admitted = %v (%s), want %v", version, ok, reason, admitted)
		}
	}
}
