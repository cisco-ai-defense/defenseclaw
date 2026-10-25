// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// hotConfigHost stages an installed config and a supplied one, and stubs what
// a config-only ensure touches outside them.
type hotConfigHost struct {
	configPath  string
	next        string
	writes      []string
	adopted     bool
	recovers    int
	digestCalls int
	adoptAfter  int
	refreshes   int
	// The targets record of a refreshing apply (GAP-0847): how often it was
	// taken and put back, what fails, and the targets it says are dropped.
	targetRecords    int
	targetRestores   int
	targetRecordErr  error
	targetRestoreErr error
	dropped          []enterprisehooks.ManifestTarget
	// GAP-0905: the live proof that the dropped targets' hooks are back.
	hookProofs    [][]enterprisehooks.ManifestTarget
	hookProofErr  error
	stops         int
	closes        int
	closureHeld   bool
	releases      int
	bundleID      string
	bundleVersion uint64
}

// digest is what the installed CLI's policy digest prints: the policy the
// installed config computes to, and the one the gateway reports. The
// installed config computes to policy b while it holds the supplied config,
// and to policy a otherwise (the previous config, or the one an undo put
// back). A gateway that adopts follows config.yaml; one that does not keeps
// enforcing policy a, the previous config's.
func (host *hotConfigHost) digest(context.Context) ([]byte, error) {
	host.digestCalls++
	effective := "sha256:" + strings.Repeat("a", 64)
	if installed, err := os.ReadFile(host.configPath); err == nil && string(installed) == host.next {
		effective = "sha256:" + strings.Repeat("b", 64)
	}
	reported := "sha256:" + strings.Repeat("a", 64)
	if host.adopted {
		reported = effective
	}
	generation := len(host.writes) + 10
	gatewayGeneration := generation
	if host.adoptAfter > 0 && host.digestCalls < host.adoptAfter {
		gatewayGeneration--
	}
	return []byte(`{"effective_digest":"` + effective +
		`","config_generation":` + strconv.Itoa(generation) +
		`,"config_generation_recorded":true,"gateway_reported_digest":"` + reported +
		`","gateway_reported_config_generation":` + strconv.Itoa(gatewayGeneration) +
		`,"gateway_reported_bundle_id":"` + host.bundleID +
		`","gateway_reported_bundle_version":` + strconv.FormatUint(host.bundleVersion, 10) + `}`), nil
}

// bundleRun is a signed bundle run with a verified receipt (principal, bundle
// ID and version), the bundle the host's gateway names once it adopts the
// config: a bundle config is adopted only with that identity.
func (host *hotConfigHost) bundleRun() *windowsBundleRun {
	if host.bundleID == "" {
		host.bundleID, host.bundleVersion = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8", 2
	}
	return &windowsBundleRun{prepared: &enterprisebundle.Prepared{Receipt: &enterprisebundle.Receipt{
		BundleID: host.bundleID, Version: host.bundleVersion, Principal: "control-plane:acme/alice", SignerKeyID: "k1"}}}
}

func newHotConfigHost(t *testing.T, previous, next string) (*hotConfigHost, *windowsEnterpriseLifecycleOptions) {
	t.Helper()
	dir := t.TempDir()
	host := &hotConfigHost{configPath: filepath.Join(dir, "etc", "config.yaml"), next: next}
	supplied := filepath.Join(dir, "supplied.yaml")
	for path, body := range map[string]string{host.configPath: previous, supplied: next} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	elevatedSeam := windowsEnterpriseIsElevated
	windowsEnterpriseIsElevated = func() bool { return true }
	layoutSeam, lockSeam := windowsEnterpriseHotConfigLayout, windowsEnterpriseHotConfigLock
	validateSeam, writeSeam := windowsEnterpriseHotConfigValidate, windowsEnterpriseHotConfigWrite
	timeoutSeam, restartTimeoutSeam, pollSeam := windowsEnterpriseHotConfigTimeout, windowsEnterpriseHotConfigRestartTimeout, windowsEnterpriseHotConfigPoll
	sourceSeam, refreshSeam := windowsEnterpriseHotConfigSourceCheck, windowsEnterpriseHotConfigRefreshTargets
	runtimeCandidateSeam := windowsEnterpriseStandaloneRuntimeCandidateCheck
	recordSeam := windowsEnterpriseHotConfigTargetsRecord
	hookProofSeam := windowsEnterpriseHotConfigTargetHooksProven
	publishedTargetsSeam, renderTimeoutSeam := windowsEnterpriseHotConfigPublishedTargets, windowsEnterpriseHotConfigRenderTimeout
	reloadSeam, failClosedSeam := windowsEnterpriseHotBundleReload, windowsEnterpriseHotConfigFailClosed
	closeHooksSeam, hooksHeldSeam, releaseHooksSeam := windowsEnterpriseHotConfigCloseHooks, windowsEnterpriseHotConfigHooksHeld, windowsEnterpriseHotConfigReleaseHooks
	restartSeam, recoverSeam := windowsEnterpriseHotConfigRestart, windowsEnterpriseHotConfigRecover
	t.Cleanup(func() {
		windowsEnterpriseHotConfigRestart, windowsEnterpriseHotConfigRecover = restartSeam, recoverSeam
		windowsEnterpriseHotConfigFailClosed = failClosedSeam
		windowsEnterpriseHotConfigCloseHooks, windowsEnterpriseHotConfigHooksHeld, windowsEnterpriseHotConfigReleaseHooks = closeHooksSeam, hooksHeldSeam, releaseHooksSeam
		windowsEnterpriseHotConfigRefreshTargets = refreshSeam
		windowsEnterpriseHotConfigTargetsRecord = recordSeam
		windowsEnterpriseHotConfigTargetHooksProven = hookProofSeam
		windowsEnterpriseHotConfigPublishedTargets, windowsEnterpriseHotConfigRenderTimeout = publishedTargetsSeam, renderTimeoutSeam
		windowsEnterpriseIsElevated = elevatedSeam
		windowsEnterpriseHotConfigLayout, windowsEnterpriseHotConfigLock = layoutSeam, lockSeam
		windowsEnterpriseHotConfigValidate, windowsEnterpriseHotConfigWrite = validateSeam, writeSeam
		windowsEnterpriseHotConfigTimeout, windowsEnterpriseHotConfigPoll = timeoutSeam, pollSeam
		windowsEnterpriseHotConfigRestartTimeout = restartTimeoutSeam
		windowsEnterpriseHotConfigSourceCheck = sourceSeam
		windowsEnterpriseStandaloneRuntimeCandidateCheck = runtimeCandidateSeam
		windowsEnterpriseHotBundleReload = reloadSeam
	})
	// The supplied file stands for an administrator-only staged config.
	windowsEnterpriseHotConfigSourceCheck = func(string) error { return nil }
	windowsEnterpriseStandaloneRuntimeCandidateCheck = func(*config.Config) error { return nil }
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: host.configPath, ConfigDir: filepath.Dir(host.configPath), DataDir: dir, ServiceUser: `NT SERVICE\DefenseClawGateway`}, nil
	}
	windowsEnterpriseHotConfigLock = func(string) (func(), error) { return func() {}, nil }
	windowsEnterpriseHotConfigRefreshTargets = func(context.Context, managed.StandaloneLayout) error {
		host.refreshes++
		return nil
	}
	windowsEnterpriseHotConfigTargetsRecord = func(managed.StandaloneLayout) (windowsHotConfigPublishedTargets, error) {
		host.targetRecords++
		if host.targetRecordErr != nil {
			return windowsHotConfigPublishedTargets{}, host.targetRecordErr
		}
		return windowsHotConfigPublishedTargets{
			restore: func() error {
				host.targetRestores++
				return host.targetRestoreErr
			},
			dropped: func() []enterprisehooks.ManifestTarget { return host.dropped },
		}, nil
	}
	windowsEnterpriseHotConfigTargetHooksProven = func(_ context.Context, _ managed.StandaloneLayout, targets []enterprisehooks.ManifestTarget, _ time.Duration) error {
		host.hookProofs = append(host.hookProofs, append([]enterprisehooks.ManifestTarget(nil), targets...))
		return host.hookProofErr
	}
	windowsEnterpriseHotConfigPublishedTargets = func(managed.StandaloneLayout) ([]enterprisehooks.ManifestTarget, error) { return nil, nil }
	windowsEnterpriseHotBundleReload = func(context.Context, managed.StandaloneLayout) error { return nil }
	// No test stops or starts a real gateway service: an unproven undo and
	// a start of a stopped gateway are counted.
	windowsEnterpriseHotConfigCloseHooks = func(managed.StandaloneLayout) error {
		host.closes++
		host.closureHeld = true
		return nil
	}
	windowsEnterpriseHotConfigHooksHeld = func() (bool, error) { return host.closureHeld, nil }
	windowsEnterpriseHotConfigReleaseHooks = func(managed.StandaloneLayout) error {
		host.releases++
		host.closureHeld = false
		return nil
	}
	windowsEnterpriseHotConfigFailClosed = func() error {
		if !host.closureHeld {
			t.Fatal("unproven undo stopped the gateway before managed hooks were durably closed")
		}
		host.stops++
		return nil
	}
	windowsEnterpriseHotConfigRecover = func() (bool, error) { host.recovers++; return false, nil }
	custodySeam := windowsEnterpriseInstalledCLICustody
	t.Cleanup(func() { windowsEnterpriseInstalledCLICustody = custodySeam })
	// The installed CLI stands for an administrator-only image.
	windowsEnterpriseInstalledCLICustody = func(string, string) error { return nil }
	windowsEnterpriseHotConfigValidate = func(string, string, string, bool) (windowsServiceConfigValidation, error) {
		return windowsServiceConfigValidation{}, nil
	}
	windowsEnterpriseHotConfigWrite = func(_ context.Context, path string, raw []byte, opt configwrite.Options) error {
		if current, err := os.ReadFile(path); err != nil || configwrite.SHA256Hex(current) != opt.ExpectSHA256 {
			return errors.New("installed config changed before write")
		}
		host.writes = append(host.writes, opt.Reason)
		// The writer records a generation with every write.
		if err := os.WriteFile(configwrite.GenerationPath(path), []byte(`{"generation":`+strconv.Itoa(len(host.writes)+10)+`}`), 0o600); err != nil {
			return err
		}
		return os.WriteFile(path, raw, 0o600)
	}
	windowsEnterpriseHotConfigTimeout, windowsEnterpriseHotConfigRestartTimeout, windowsEnterpriseHotConfigPoll = 50*time.Millisecond, 50*time.Millisecond, 5*time.Millisecond
	opts := ensureTestOptions()
	opts.configPath, opts.manifestPath, opts.noStart = supplied, "", false
	return host, opts
}

func runHotConfigEnsure(t *testing.T, host *hotConfigHost, opts *windowsEnterpriseLifecycleOptions, stub *ensureStub) *enterprisestatus.Result {
	t.Helper()
	stub.install(t)
	windowsEnterprisePolicyDigest = host.digest
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "config", nil }
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return &result
}

func TestWindowsEnterpriseHotConfigClosureSurvivesUntilPolicyProof(t *testing.T) {
	const config = "config_version: 9\nguardrail:\n  hook_fail_mode: open\n"
	for _, tc := range []struct {
		name         string
		verified     bool
		digestFails  bool
		releaseFails bool
		wantRelease  bool
	}{
		{name: "failed ensure leaves closure", verified: false},
		{name: "policy readback unavailable leaves closure", verified: true, digestFails: true},
		{name: "release failure leaves closure", verified: true, releaseFails: true},
		{name: "proven recovery releases closure", verified: true, wantRelease: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, _ := newHotConfigHost(t, config, config)
			host.closureHeld = true
			host.adopted = true
			digest := windowsEnterprisePolicyDigest
			t.Cleanup(func() { windowsEnterprisePolicyDigest = digest })
			windowsEnterprisePolicyDigest = host.digest
			if tc.digestFails {
				windowsEnterprisePolicyDigest = func(context.Context) ([]byte, error) { return nil, errors.New("readback unavailable") }
			}
			if tc.releaseFails {
				windowsEnterpriseHotConfigReleaseHooks = func(managed.StandaloneLayout) error { return errors.New("release refused") }
			}
			result := newWindowsEnterpriseStandaloneResult("ensure", ensureTestOptions())
			result.OK, result.Installed = tc.verified, true
			code := 1
			if tc.verified {
				code = 0
			}
			err := windowsEnterpriseReleaseHotConfigClosureIfProven(context.Background(), result, code)
			if tc.wantRelease {
				if err != nil || host.closureHeld || host.releases != 1 {
					t.Fatalf("proven recovery: err=%v held=%t releases=%d", err, host.closureHeld, host.releases)
				}
			} else if !host.closureHeld || host.releases != 0 || (tc.verified && err == nil) {
				t.Fatalf("unproven recovery: err=%v held=%t releases=%d", err, host.closureHeld, host.releases)
			}
		})
	}
}

// GAP-0135: a change the running gateway applies as a generation swap no
// longer runs the upgrade transaction (130 seconds with the gateway down).
// One the gateway cannot take, or does not adopt, still does, with the
// previous config back in place first.
func TestWindowsEnterpriseEnsureAppliesAConfigOnlyChangeInTheRunningGateway(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  mode: observe\n"
	const next = "config_version: 9\nguardrail:\n  mode: action\n"

	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify")}}
	result := runHotConfigEnsure(t, host, opts, stub)
	if len(stub.calls) != 2 || stub.calls[1][1] != "Verify" || len(host.writes) != 1 {
		t.Fatalf("installer runs %q, writes %q: want status and verify only, one write", stub.calls, host.writes)
	}
	if got, _ := os.ReadFile(host.configPath); string(got) != next {
		t.Fatalf("config.yaml = %q, want the supplied config", got)
	}
	if !result.OK || result.Policy == nil || !result.Policy.Applied || !strings.Contains(strings.Join(result.Changes, "\n"), "it was not restarted") {
		t.Fatalf("result = %+v", result)
	}

	// GAP-0312: a supplied config a standard user can write is not
	// installed by the hot path; the transaction gets it and refuses it.
	host, opts = newHotConfigHost(t, previous, next)
	host.adopted = true
	windowsEnterpriseHotConfigSourceCheck = func(string) error { return errors.New("writable by BUILTIN\\Users") }
	stub = &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
	runHotConfigEnsure(t, host, opts, stub)
	if len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" || len(host.writes) != 0 {
		t.Fatalf("untrusted source: installer runs %q, writes %q", stub.calls, host.writes)
	}

	// GAP-0716: an edit of who is enrolled is applied in place too, and
	// refreshes the enrolled targets.
	enrolled := "config_version: 9\nenterprise:\n  enrollment:\n    exclude_users: [dcw-eo1]\n"
	host, opts = newHotConfigHost(t, enrolled, strings.Replace(enrolled, "[dcw-eo1]", "[dcw-eo1, dcw-eo5]", 1))
	host.adopted = true
	stub = &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify")}}
	result = runHotConfigEnsure(t, host, opts, stub)
	if len(stub.calls) != 2 || stub.calls[1][1] != "Verify" || host.refreshes != 1 ||
		!strings.Contains(fmt.Sprint(result.Warnings), "enterprise.enrollment.exclude_users") {
		t.Fatalf("enrollment edit: installer runs %q, target refreshes %d, warnings %v", stub.calls, host.refreshes, result.Warnings)
	}

	// A key the gateway reads once at start goes through the upgrade.
	host, opts = newHotConfigHost(t, previous, strings.Replace(previous, "mode: observe", "mode: observe\ngateway:\n  api_port: 18971", 1))
	host.adopted = true
	stub = &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
	runHotConfigEnsure(t, host, opts, stub)
	if len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" || len(host.writes) != 0 {
		t.Fatalf("restart-required change: installer runs %q, writes %q", stub.calls, host.writes)
	}

	// A gateway that does not adopt the change gets the old config back and
	// the upgrade. The apply and the restore each record a generation, so the
	// counter moves past the recorded 3 and never reuses a number.
	host, opts = newHotConfigHost(t, previous, next)
	recorded := `{"generation":3,"config_sha256":"` + configwrite.SHA256Hex([]byte(previous)) + `"}`
	if err := os.WriteFile(configwrite.GenerationPath(host.configPath), []byte(recorded), 0o600); err != nil {
		t.Fatal(err)
	}
	stub = &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
	runHotConfigEnsure(t, host, opts, stub)
	got, _ := os.ReadFile(host.configPath)
	generation, _ := os.ReadFile(configwrite.GenerationPath(host.configPath))
	if string(got) != previous || string(generation) == recorded || len(host.writes) != 2 ||
		len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" {
		t.Fatalf("gateway never adopted: config %q, generation %q, writes %q, installer runs %q", got, generation, host.writes, stub.calls)
	}
}

// GAP-0646: a byte-only edit still goes through the running gateway path.
func TestWindowsEnterpriseEnsureAppliesFormattingOnlyConfigWithoutRestart(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  mode: observe\n"
	const next = "config_version: 9\r\nguardrail:\r\n  mode: observe # reviewed\r\n"
	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify")}}
	result := runHotConfigEnsure(t, host, opts, stub)
	if len(stub.calls) != 2 || stub.calls[1][1] != "Verify" || len(host.writes) != 1 {
		t.Fatalf("installer runs %q, writes %q: want status and verify only, one write", stub.calls, host.writes)
	}
	if got, _ := os.ReadFile(host.configPath); string(got) != next {
		t.Fatalf("config.yaml = %q, want supplied bytes", got)
	}
	if !result.OK || result.Policy == nil || !result.Policy.Applied {
		t.Fatalf("result = %+v", result)
	}
}

// GAP-0647: a credential edit can keep the digest while the gateway still
// uses the previous generation. Ensure waits for the new generation.
func TestWindowsEnterpriseEnsureWaitsForCredentialGeneration(t *testing.T) {
	const previous = "config_version: 9\nllm:\n  provider: openai\n  api_key: old-test-key\n"
	const next = "config_version: 9\nllm:\n  provider: openai\n  api_key: new-test-key\n"
	host, opts := newHotConfigHost(t, previous, next)
	host.adopted, host.adoptAfter = true, 3
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify")}}
	result := runHotConfigEnsure(t, host, opts, stub)
	if host.digestCalls < 3 || len(stub.calls) != 2 || stub.calls[1][1] != "Verify" {
		t.Fatalf("digest polls %d, installer runs %q: want adoption before verify", host.digestCalls, stub.calls)
	}
	if !result.OK || result.Policy == nil || !result.Policy.Applied {
		t.Fatalf("result = %+v", result)
	}
}

// GAP-0145: the config.yaml an ensure replaces after a hand edit is kept as
// rejected-config.yaml beside it.
func TestWindowsEnterpriseEnsureKeepsAHandEditedConfig(t *testing.T) {
	host, _ := newHotConfigHost(t, "config_version: 9\nguardrail:\n  mode: observe\n", "config_version: 9\n")
	if kept := keepInstalledWindowsEnterpriseEditedConfig(); kept != "" {
		t.Fatalf("a config with no recorded generation was kept: %s", kept)
	}
	recorded := configwrite.GenerationPath(host.configPath)
	if err := os.WriteFile(recorded, []byte(`{"generation":3,"config_sha256":"`+strings.Repeat("0", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	kept := keepInstalledWindowsEnterpriseEditedConfig()
	if want := filepath.Join(filepath.Dir(host.configPath), "rejected-config.yaml"); kept != want {
		t.Fatalf("kept = %q, want %q", kept, want)
	}
	if got, _ := os.ReadFile(kept); !strings.Contains(string(got), "mode: observe") {
		t.Fatalf("rejected-config.yaml = %q", got)
	}
}

// GAP-0948: ensure CONFIG= over an installed config.yaml that does not parse
// keeps it as rejected-config.yaml and installs the supplied config before
// the upgrade transaction, which loaded the installed file first, refused
// it, and wrote its bytes back on rollback.
func TestWindowsEnterpriseEnsureInstallsTheSuppliedConfigOverAnUnparseableOne(t *testing.T) {
	const broken = "an administrator edit left this line instead of YAML\n"
	next := strings.Replace(
		strings.Replace(standaloneGatewayCheckConfig, "config_version: 8\n", "config_version: 9\n", 1),
		`  rule_pack_dir: ""`+"\n", "", 1)
	host, opts := newHotConfigHost(t, broken, next)
	originalLayout, originalSource := windowsEnterpriseStandaloneLayoutForPreflight, windowsEnterpriseStandaloneConfigSource
	t.Cleanup(func() {
		windowsEnterpriseStandaloneLayoutForPreflight, windowsEnterpriseStandaloneConfigSource = originalLayout, originalSource
	})
	windowsEnterpriseStandaloneLayoutForPreflight = windowsEnterpriseHotConfigLayout
	windowsEnterpriseStandaloneConfigSource = func(string) error { return nil }
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
	result := runHotConfigEnsure(t, host, opts, stub)
	got, _ := os.ReadFile(host.configPath)
	kept, _ := os.ReadFile(filepath.Join(filepath.Dir(host.configPath), "rejected-config.yaml"))
	if len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" || string(got) != next || string(kept) != broken ||
		!strings.Contains(strings.Join(result.Changes, "\n"), "did not parse") {
		t.Fatalf("installer runs %q, config.yaml %q, rejected-config.yaml %q, changes %q", stub.calls, got, kept, result.Changes)
	}
}

// GAP-0994: a replacement whose YAML parses but whose rule-pack pin is
// invalid must never become the transaction rollback snapshot.
func TestWindowsEnterpriseRepairRefusesInvalidSuppliedConfigBeforeSnapshot(t *testing.T) {
	const broken = "invalid: [\n"
	pack := t.TempDir()
	if err := os.WriteFile(filepath.Join(pack, "suppressions.yaml"),
		[]byte("version: 1\npre_judge_strips: []\nfinding_suppressions: []\ntool_suppressions: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := strings.Replace(
		strings.Replace(standaloneGatewayCheckConfig, "config_version: 8\n", "config_version: 9\n", 1),
		`  rule_pack_dir: ""`,
		"  rule_pack: acme\n  custom_packs:\n    acme:\n      path: "+strconv.Quote(pack)+
			"\n      digest: sha256:"+strings.Repeat("0", 64), 1)
	host, opts := newHotConfigHost(t, broken, candidate)
	originalLayout, originalSource, originalTrust, originalRead := windowsEnterpriseStandaloneLayoutForPreflight,
		windowsEnterpriseStandaloneConfigSource, windowsEnterpriseStandaloneRulePackTrust, standaloneServiceCanReadTree
	t.Cleanup(func() {
		windowsEnterpriseStandaloneLayoutForPreflight = originalLayout
		windowsEnterpriseStandaloneConfigSource = originalSource
		windowsEnterpriseStandaloneRulePackTrust = originalTrust
		standaloneServiceCanReadTree = originalRead
	})
	windowsEnterpriseStandaloneLayoutForPreflight = windowsEnterpriseHotConfigLayout
	windowsEnterpriseStandaloneConfigSource = func(string) error { return nil }
	windowsEnterpriseStandaloneRulePackTrust = func(string, string, string) error { return nil }
	standaloneServiceCanReadTree = func(string, string, string) error { return nil }

	kept, err := installWindowsEnterpriseSuppliedConfigOverUnparseable(opts.configPath)
	if err == nil || !strings.Contains(err.Error(), "does not match guardrail.custom_packs.acme.digest") || kept != "" {
		t.Fatalf("repair preflight = (%q, %v), want the bad pin refused before copying", kept, err)
	}
	if got, readErr := os.ReadFile(host.configPath); readErr != nil || string(got) != broken {
		t.Fatalf("installed config = %q, %v, want original bytes", got, readErr)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(host.configPath), "rejected-config.yaml")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rejected-config.yaml created before validation: %v", statErr)
	}
}

// GAP-0180: the policy digest call carries the service pins whichever console
// runs it. An administrator or SYSTEM console carries none of them and the
// managed-host guard refused the call there, so status, verify and every
// ensure but the hot config path left policy out of the result.
func TestWindowsEnterprisePolicyDigestRunsUnderTheServicePins(t *testing.T) {
	host, _ := newHotConfigHost(t, "config_version: 9\n", "config_version: 9\n")
	t.Setenv(managed.ConfigPathEnv, "C:\\console\\other.yaml")
	t.Setenv(managed.DeploymentModeEnv, "")

	// The console environment must not choose the elevated subprocess image.
	programFiles, err := trustedWindowsEnterpriseProgramFiles()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ProgramFiles", filepath.Join(t.TempDir(), "untrusted"))
	command, err := windowsEnterprisePolicyDigestCommand(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantCLI := filepath.Join(programFiles, "Cisco", "DefenseClaw", "bin", "defenseclaw.exe")
	if !strings.EqualFold(command.Path, wantCLI) {
		t.Fatalf("policy digest executable = %q, want trusted installed CLI %q", command.Path, wantCLI)
	}
	got := map[string][]string{}
	for _, entry := range command.Env {
		name, value, _ := strings.Cut(entry, "=")
		got[strings.ToUpper(name)] = append(got[strings.ToUpper(name)], value)
	}
	layout, _ := windowsEnterpriseHotConfigLayout()
	for name, want := range windowsEnterpriseServicePins(layout) {
		if values := got[strings.ToUpper(name)]; len(values) != 1 || values[0] != want {
			t.Fatalf("%s = %q, want exactly %q", name, values, want)
		}
	}
	if got[managed.ConfigPathEnv][0] != host.configPath || len(got["PATH"]) != 1 {
		t.Fatalf("config %q, PATH %q: want the installed config and the console PATH kept", got[managed.ConfigPathEnv], got["PATH"])
	}
}

// GAP-0492: a lifecycle that commits while the hot path waits must become
// the rollback baseline if the candidate fails validation.
func TestWindowsEnterpriseHotConfigValidationRollbackUsesLockedSnapshot(t *testing.T) {
	const old = "config_version: 9\nguardrail:\n  mode: observe\n"
	const committed = "config_version: 9\nguardrail:\n  mode: action\n"
	const candidate = "config_version: 9\nguardrail:\n  mode: disabled\n"
	host, opts := newHotConfigHost(t, old, candidate)
	windowsEnterpriseHotConfigLock = func(string) (func(), error) {
		if err := os.WriteFile(host.configPath, []byte(committed), 0o600); err != nil {
			t.Fatal(err)
		}
		return func() {}, nil
	}
	windowsEnterpriseHotConfigValidate = func(string, string, string, bool) (windowsServiceConfigValidation, error) {
		return windowsServiceConfigValidation{}, errors.New("invalid candidate")
	}
	applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, &enterprisestatus.Result{})
	if applied {
		t.Fatal("invalid candidate applied")
	}
	got, err := os.ReadFile(host.configPath)
	if err != nil || string(got) != committed {
		t.Fatalf("rollback replaced committed config: %q, %v", got, err)
	}
}

// GAP-0493: adoption failure has the same rollback baseline as validation.
func TestWindowsEnterpriseHotConfigAdoptionRollbackUsesLockedSnapshot(t *testing.T) {
	const old = "config_version: 9\nguardrail:\n  mode: observe\n"
	const committed = "config_version: 9\nguardrail:\n  mode: action\n"
	const candidate = "config_version: 9\nguardrail:\n  mode: disabled\n"
	host, opts := newHotConfigHost(t, old, candidate)
	windowsEnterpriseHotConfigLock = func(string) (func(), error) {
		if err := os.WriteFile(host.configPath, []byte(committed), 0o600); err != nil {
			t.Fatal(err)
		}
		return func() {}, nil
	}
	previousDigest := windowsEnterprisePolicyDigest
	windowsEnterprisePolicyDigest = host.digest
	t.Cleanup(func() { windowsEnterprisePolicyDigest = previousDigest })
	applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, &enterprisestatus.Result{})
	if applied {
		t.Fatal("unadopted candidate applied")
	}
	got, err := os.ReadFile(host.configPath)
	if err != nil || string(got) != committed {
		t.Fatalf("rollback replaced committed config: %q, %v", got, err)
	}
}

// Enabling a connector in a hot ensure must name sessions that predate its
// hooks, even if they started after the original deployment activation.
func TestWindowsEnterpriseHotConnectorEnableWarnsOpenSessions(t *testing.T) {
	previous := "config_version: 9\nguardrail:\n  connectors:\n    claudecode:\n      enabled: false\n    codex: {}\n"
	next := strings.Replace(previous, "enabled: false", "enabled: true", 1)
	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	original, originalMetadata := windowsEnterpriseAgentProcesses, windowsEnterpriseActivationMetadata
	t.Cleanup(func() {
		windowsEnterpriseAgentProcesses, windowsEnterpriseActivationMetadata = original, originalMetadata
	})
	windowsEnterpriseActivationMetadata = func() (string, bool) { return "", false }
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		started := time.Now().Add(-time.Minute)
		return []inventory.AgentProcess{
			{PID: 41, Connector: "claudecode", User: `DCFC\alice`, StartedAt: started},
			{PID: 42, Connector: "codex", User: `DCFC\alice`, StartedAt: started},
		}, nil
	}
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify")}}
	result := runHotConfigEnsure(t, host, opts, stub)
	if !result.OK || host.refreshes != 1 {
		t.Fatalf("hot ensure = %+v, target refreshes = %d", result, host.refreshes)
	}
	var warnings []string
	for _, warning := range result.Warnings {
		if warning.Code == windowsAgentSessionsRestartCode {
			warnings = append(warnings, warning.Message)
		}
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "claudecode (pid 41)") ||
		strings.Contains(warnings[0], "codex (pid 42)") {
		t.Fatalf("session warnings = %q", warnings)
	}
}

// GAP-1435: a hot ensure that only enrolls an account leaves the connector
// set as it was; the open sessions of that account still need a restart, in
// the ensure and in every later status.
func TestWindowsEnterpriseHotEnrollmentWarnsOpenSessions(t *testing.T) {
	const previous = "config_version: 9\nenterprise:\n  enrollment:\n    exclude_users:\n      - alice\nguardrail:\n  connectors:\n    claudecode: {}\n"
	const next = "config_version: 9\nenterprise:\n  enrollment:\n    exclude_users: []\nguardrail:\n  connectors:\n    claudecode: {}\n"
	const aliceSID = "S-1-5-21-1-2-3-1001"
	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	metadata := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(metadata, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	original, originalMetadata := windowsEnterpriseAgentProcesses, windowsEnterpriseActivationMetadata
	originalConnectors, originalTargets, originalSID := windowsEnterpriseEnrolledConnectors, windowsEnterpriseEnrolledTargets, windowsEnterpriseAccountSID
	t.Cleanup(func() {
		windowsEnterpriseAgentProcesses, windowsEnterpriseActivationMetadata = original, originalMetadata
		windowsEnterpriseEnrolledConnectors, windowsEnterpriseEnrolledTargets, windowsEnterpriseAccountSID = originalConnectors, originalTargets, originalSID
	})
	alice := windowsEnterpriseManifestRowKey(enterprisehooks.ManifestTarget{SID: aliceSID, Connector: "claudecode"})
	windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"claudecode"}, nil }
	windowsEnterpriseEnrolledTargets = func() (map[string]bool, error) { return map[string]bool{alice: true}, nil }
	windowsEnterpriseAccountSID = func(account string) string {
		if account == `DCFC\alice` {
			return aliceSID
		}
		return ""
	}
	started := time.Now().Add(-time.Minute)
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{{PID: 41, Connector: "claudecode", User: `DCFC\alice`, StartedAt: started}}, nil
	}
	// What the change-action preflight records before the run.
	opts.activationStartedAt, opts.installedBeforeRun = started.Add(-time.Hour), true
	opts.previousConnectors, opts.previousConnectorsKnown = []string{"claudecode"}, true
	opts.previousTargets, opts.previousTargetsKnown = map[string]bool{}, true
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify")}}
	ensure := runHotConfigEnsure(t, host, opts, stub)
	if !ensure.OK || host.refreshes != 1 {
		t.Fatalf("hot ensure = %+v, target refreshes = %d", ensure, host.refreshes)
	}
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	status.Installed = true
	applyWindowsEnterpriseAgentSessions(status, &windowsEnterpriseLifecycleOptions{})
	for _, result := range []*enterprisestatus.Result{ensure, status} {
		var warnings []string
		for _, warning := range result.Warnings {
			if warning.Code == windowsAgentSessionsRestartCode {
				warnings = append(warnings, warning.Message)
			}
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], `user DCFC\alice runs claudecode (pid 41), started before the account was enrolled`) {
			t.Fatalf("%s session warnings = %q", result.Action, warnings)
		}
	}
}

// GAP-0104: a bundle the hot path cannot take names the reason, and a held
// lifecycle lock is retried (1618) instead of failing as 1603.
func TestWindowsBundleHotApplyRefusalNamesItsCause(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: HIGH\n"
	const next = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	for _, tc := range []struct {
		name, code, detail string
		status             *windowsEnterpriseInstallerReport
		lock               error
	}{
		{"gateway not ready", "bundle_hot_apply_unavailable", "the gateway is not ready",
			&windowsEnterpriseInstallerReport{OK: true, Installed: true}, nil},
		{"lock held", "lifecycle_busy", "holds lifecycle.lock",
			&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, windows.ERROR_SHARING_VIOLATION},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, opts := newHotConfigHost(t, previous, next)
			opts.bundle = host.bundleRun()
			if tc.lock != nil {
				windowsEnterpriseHotConfigLock = func(string) (func(), error) { return nil, tc.lock }
			}
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			if applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "", tc.status, result); applied {
				t.Fatal("refused bundle applied")
			}
			if len(result.Errors) != 1 || result.Errors[0].Code != tc.code || !strings.Contains(result.Errors[0].Message, tc.detail) {
				t.Fatalf("errors = %+v, want %s naming %q", result.Errors, tc.code, tc.detail)
			}
			if got := windowsEnterpriseFailureCodeFor(result); got != enterprisestatus.WindowsExitBusy && tc.code == "lifecycle_busy" {
				t.Fatalf("exit = %d, want retryable %d", got, enterprisestatus.WindowsExitBusy)
			}
			if raw, err := os.ReadFile(host.configPath); err != nil || string(raw) != previous {
				t.Fatalf("installed config changed: %q, %v", raw, err)
			}
		})
	}
	// An ordinary CONFIG= change keeps its silent fallback to the transaction.
	_, opts := newHotConfigHost(t, previous, next)
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	if applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true}, result); applied || len(result.Errors) != 0 {
		t.Fatalf("config fallback applied=%t errors=%+v", applied, result.Errors)
	}
}

func TestWindowsBundleConfigApplyUsesSharedRestartClassification(t *testing.T) {
	for _, tc := range []struct {
		name, next string
		restarts   int
	}{
		{"policy only", "config_version: 9\nguardrail:\n  block_at: HIGH\n  hook_self_heal_debounce_ms: 500\n", 0},
		{"start only", "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 500\n"
			host, opts := newHotConfigHost(t, previous, tc.next)
			host.adopted = true
			opts.bundle = host.bundleRun()
			savedRestart, savedDigest := windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest
			t.Cleanup(func() { windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest = savedRestart, savedDigest })
			restarts := 0
			windowsEnterpriseHotConfigRestart = func() (bool, error) { restarts++; return true, nil }
			stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("Verify")}}
			stub.install(t)
			windowsEnterprisePolicyDigest = host.digest
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			command := &cobra.Command{}
			applied, _ := windowsEnterpriseHotConfigApply(context.Background(), command, opts, "installer.ps1",
				&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
			if !applied || restarts != tc.restarts || opts.bundle.gatewayRestarted != (tc.restarts == 1) || len(stub.calls) != 1 {
				t.Fatalf("applied=%t restarts=%d receiptRestart=%t installerCalls=%q", applied, restarts, opts.bundle.gatewayRestarted, stub.calls)
			}
		})
	}
}

// A signed config that never reached a responding gateway cannot be kept as
// an applied receipt. If the gateway remains unavailable through adoption,
// restore the previous bytes and stop it when the restored policy cannot be
// proven either. A later outage after adoption is covered by Finish tests.
func TestWindowsHotBundleNeverAdoptedDuringOutageRestoresPreviousConfig(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 500\n"
	const candidate = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n"
	const enrolled = "config_version: 9\nenterprise:\n  enrollment:\n    exclude_users: [dcw-eo1]\n"
	for _, tc := range []struct {
		name, previous, candidate string
	}{
		{name: "restart setting", previous: previous, candidate: candidate},
		{name: "enrollment", previous: enrolled, candidate: strings.Replace(enrolled, "[dcw-eo1]", "[dcw-eo1, dcw-eo5]", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, opts := newHotConfigHost(t, tc.previous, tc.candidate)
			opts.bundle = host.bundleRun()
			savedRestart, savedDigest := windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest
			t.Cleanup(func() { windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest = savedRestart, savedDigest })
			windowsEnterpriseHotConfigRestart = func() (bool, error) { return true, nil }
			windowsEnterprisePolicyDigest = func(context.Context) ([]byte, error) { return nil, errors.New("gateway stopped") }
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
				&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
			installed, err := os.ReadFile(host.configPath)
			if applied || err != nil || string(installed) != tc.previous ||
				!windowsBundleHasCode(result.Errors, "bundle_policy_not_adopted") ||
				!opts.hotConfigRestoreFailed || host.stops != 1 || host.refreshes != 0 {
				t.Fatalf("unadopted bundle: applied=%t config=%q stops=%d refreshes=%d errors=%+v read=%v",
					applied, installed, host.stops, host.refreshes, result.Errors, err)
			}
		})
	}
}

// A repeated delivery has no new receipt. Its previous confirmed receipt
// remains true, but a repair during an outage cannot claim this run adopted
// the policy. The administrator gets the retry exit after the signed config
// is restored.
func TestWindowsRepeatedBundleGatewayOutageRequiresRetry(t *testing.T) {
	const drifted = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 700\n"
	const confirmed = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n"
	host, opts := newHotConfigHost(t, drifted, confirmed)
	opts.bundle = host.bundleRun()
	prepared := opts.bundle.prepared
	prepared.Receipt, prepared.AlreadyApplied, prepared.Config = nil, true, []byte(confirmed)
	savedConfirmed, savedRestart, savedDigest := windowsHotConfirmedBundle, windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest
	t.Cleanup(func() {
		windowsHotConfirmedBundle, windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest = savedConfirmed, savedRestart, savedDigest
	})
	windowsHotConfirmedBundle = func(_ *enterprisebundle.Driver, _ []byte) (configwrite.Options, []byte, *enterprisebundle.Ref, error) {
		opt, _ := enterprisebundle.GenerationOptions(&enterprisebundle.Receipt{BundleID: host.bundleID, Version: host.bundleVersion,
			Principal: "control-plane:acme/alice", SignerKeyID: "k1"})
		return opt, []byte(confirmed), &enterprisebundle.Ref{BundleID: host.bundleID, Version: host.bundleVersion, SignerKeyID: "k1"}, nil
	}
	windowsEnterpriseHotConfigRestart = func() (bool, error) { return true, nil }
	windowsEnterprisePolicyDigest = func(context.Context) ([]byte, error) { return nil, errors.New("gateway stopped") }
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
	installed, err := os.ReadFile(host.configPath)
	if !applied || err != nil || string(installed) != confirmed || len(host.writes) != 1 ||
		!windowsBundleHasCode(result.Errors, string(enterprisebundle.CodeNotConfirmed)) || result.Readiness.Gateway || result.Policy != nil {
		t.Fatalf("repeat outage: applied=%t config=%q writes=%q readiness=%+v policy=%+v errors=%+v read=%v",
			applied, installed, host.writes, result.Readiness, result.Policy, result.Errors, err)
	}
	if code := windowsEnterpriseFailureCodeFor(result); code != enterprisestatus.WindowsExitBusy {
		t.Fatalf("repeat outage exit=%d, want retry", code)
	}
}

// GAP-0008: the rollback of a bundle that `enterprise bundle apply` (the
// installed CLI, no payload) could not confirm puts the last good config
// back on the running deployment, restarting only the gateway for a key it
// reads at start. It used to be refused for the missing payload, which left
// the refused bundle config installed and enforcing.
func TestWindowsBundleRollbackByTheInstalledCLIPutsTheLastGoodConfigBack(t *testing.T) {
	const bundleConfig = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 500\n"
	for _, tc := range []struct {
		name, lastGood string
		restarts       int
	}{
		{"policy only", "config_version: 9\nguardrail:\n  block_at: HIGH\n  hook_self_heal_debounce_ms: 500\n", 0},
		{"start only", "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, opts := newHotConfigHost(t, bundleConfig, tc.lastGood)
			host.adopted = true
			opts.gatewayBinary, opts.acpBinary, opts.hookBinary, opts.sensorHelperBinary, opts.policyCompiler = "", "", "", "", ""
			opts.bundleRollback = true
			savedRestart := windowsEnterpriseHotConfigRestart
			t.Cleanup(func() { windowsEnterpriseHotConfigRestart = savedRestart })
			restarts := 0
			windowsEnterpriseHotConfigRestart = func() (bool, error) { restarts++; return true, nil }
			stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify")}}
			result := runHotConfigEnsure(t, host, opts, stub)
			installed, _ := os.ReadFile(host.configPath)
			if string(installed) != tc.lastGood || restarts != tc.restarts || len(stub.calls) != 2 || stub.calls[1][1] != "Verify" || !result.OK {
				t.Fatalf("rollback installed %q, restarts %d, installer runs %q, ok %t errors %+v", installed, restarts, stub.calls, result.OK, result.Errors)
			}
		})
	}

	// The installed CLI can name a last good bundle only when its store
	// proves the signed principal. The earlier dummy target had no current
	// bundle and correctly failed the tightened principal check.
	t.Run("signed last good bundle", func(t *testing.T) {
		host := newWindowsBundleRestoreHost(t)
		ctx := context.Background()
		host.tamper(t, false)
		if restore := restoreWindowsBundleConfig(ctx, ""); restore.failed() {
			t.Fatalf("record the confirmed bundle: %+v", restore)
		}
		before, err := configwrite.ReadGenerationState(host.layout.ConfigPath)
		if err != nil || before.BundleID != host.bundleID {
			t.Fatalf("confirmed bundle generation = %+v (%v)", before, err)
		}
		failed := append(append([]byte(nil), host.bundleConfig...), []byte("# refused next bundle\n")...)
		if err := windowsEnterpriseHotConfigWrite(ctx, host.layout.ConfigPath, failed, configwrite.Options{
			Actor: configwrite.ActorLifecycle, Reason: "next bundle", ExpectSHA256: configwrite.SHA256Hex(host.bundleConfig),
		}); err != nil {
			t.Fatal(err)
		}
		stub := host.installer(t, installedStatus("status"), installedStatus("Verify"))
		windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "config", nil }
		source, validate := windowsEnterpriseHotConfigSourceCheck, windowsEnterpriseHotConfigValidate
		t.Cleanup(func() { windowsEnterpriseHotConfigSourceCheck, windowsEnterpriseHotConfigValidate = source, validate })
		windowsEnterpriseHotConfigSourceCheck = func(string) error { return nil }
		windowsEnterpriseHotConfigValidate = func(string, string, string, bool) (windowsServiceConfigValidation, error) {
			return windowsServiceConfigValidation{}, nil
		}
		opts := windowsBundleRestoreOptions()
		opts.gatewayBinary, opts.acpBinary, opts.hookBinary, opts.sensorHelperBinary, opts.policyCompiler = "", "", "", "", ""
		opts.noStart, opts.resolvedInstaller = false, `C:\stage\install-enterprise.ps1`
		cmd, _ := windowsBundleCommand()
		run := &windowsBundleRun{ctx: ctx, layout: host.layout, driver: newWindowsBundleDriver(host.layout),
			previous: host.bundleConfig, previousGeneration: before}
		if _, ok := rollbackWindowsBundle(cmd, opts, run); !ok {
			t.Fatal("the installed CLI did not restore the signed last good bundle")
		}
		installed, err := os.ReadFile(host.layout.ConfigPath)
		state, stateErr := configwrite.ReadGenerationState(host.layout.ConfigPath)
		if err != nil || !bytes.Equal(installed, host.bundleConfig) || stateErr != nil || state.BundleID != host.bundleID ||
			state.BundleVersion != 5 || state.SignerKeyID != "k1" || !configwrite.IsPrincipalActor(state.Actor) || len(stub.calls) != 2 {
			t.Fatalf("rollback config=%q read=%v generation=%+v state=%v installer calls=%q", installed, err, state, stateErr, stub.calls)
		}
	})
}

func TestWindowsHotConfigDoesNotApplyFleetEnablementWithoutCompilerLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, previous, next string
	}{
		{"enable", "config_version: 9\nfleet:\n  enabled: false\n", "config_version: 9\nfleet:\n  enabled: true\n"},
		{"disable", "config_version: 9\nfleet:\n  enabled: true\n", "config_version: 9\nfleet:\n  enabled: false\n"},
	} {
		for _, bundle := range []bool{false, true} {
			name := tc.name + " Setup"
			if bundle {
				name = tc.name + " bundle"
			}
			t.Run(name, func(t *testing.T) {
				host, opts := newHotConfigHost(t, tc.previous, tc.next)
				if bundle {
					opts.bundle = host.bundleRun()
				}
				result := newWindowsEnterpriseStandaloneResult("ensure", opts)
				applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
					&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
				installed, err := os.ReadFile(host.configPath)
				if err != nil || applied || len(host.writes) != 0 || string(installed) != tc.previous {
					t.Fatalf("Fleet transition applied=%t writes=%q installed=%q read=%v", applied, host.writes, installed, err)
				}
				if got := windowsBundleHasCode(result.Errors, "fleet_setup_required"); got != bundle {
					t.Fatalf("Fleet transition bundle=%t setup-required=%t errors=%v", bundle, got, result.Errors)
				}
			})
		}
	}
}

func TestWindowsHotBundleReloadsWhenWatcherMissesConfigWrite(t *testing.T) {
	for _, identical := range []bool{false, true} {
		t.Run(fmt.Sprintf("identical-base=%t", identical), func(t *testing.T) {
			testWindowsHotBundleReload(t, identical)
		})
	}
}

func testWindowsHotBundleReload(t *testing.T, identical bool) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	next := "config_version: 9\nguardrail:\n  block_at: LOW\n"
	if identical {
		next = previous
	}
	host, opts := newHotConfigHost(t, previous, next)
	// Equal bytes already have the same policy digest. The prior gateway
	// still names the old bundle, so only adoption of the new identity after
	// the reload can confirm this delivery.
	host.adopted = identical
	host.bundleID, host.bundleVersion = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8", 2
	opts.bundle = host.bundleRun()
	wantBundleID, wantBundleVersion := host.bundleID, host.bundleVersion
	host.bundleID, host.bundleVersion = "previous-bundle", 1
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("Verify")}}
	stub.install(t)
	savedDigest := windowsEnterprisePolicyDigest
	t.Cleanup(func() { windowsEnterprisePolicyDigest = savedDigest })
	windowsEnterprisePolicyDigest = host.digest
	reloads := 0
	windowsEnterpriseHotBundleReload = func(context.Context, managed.StandaloneLayout) error {
		reloads++
		host.adopted = true
		host.bundleID, host.bundleVersion = wantBundleID, wantBundleVersion
		return nil
	}
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
	if !applied || reloads != 1 || host.digestCalls == 0 || opts.bundle.gatewayRestarted || len(host.writes) != 1 {
		t.Fatalf("applied=%t reloads=%d digestCalls=%d restarted=%t writes=%q errors=%v", applied, reloads, host.digestCalls, opts.bundle.gatewayRestarted, host.writes, result.Errors)
	}
	for _, warning := range result.Warnings {
		if warning.Code == "bundle_reload_request_failed" {
			t.Fatalf("successful hot bundle reload reported a failure: %+v", result.Warnings)
		}
	}
}

func TestWindowsHotBundleReloadCannotConfirmWrongDigest(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	const next = "config_version: 9\nguardrail:\n  block_at: LOW\n"
	host, opts := newHotConfigHost(t, previous, next)
	host.bundleID, host.bundleVersion = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8", 2
	opts.bundle = host.bundleRun()
	// A managed config has a matching prior generation. Rollback records a
	// new generation for the restored bytes through the writer seam.
	recorded := `{"generation":10,"config_sha256":"` + configwrite.SHA256Hex([]byte(previous)) + `"}`
	if err := os.WriteFile(configwrite.GenerationPath(host.configPath), []byte(recorded), 0o600); err != nil {
		t.Fatal(err)
	}
	savedDigest := windowsEnterprisePolicyDigest
	t.Cleanup(func() { windowsEnterprisePolicyDigest = savedDigest })
	windowsEnterprisePolicyDigest = host.digest
	windowsEnterpriseHotBundleReload = func(context.Context, managed.StandaloneLayout) error { return nil }
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
	got, _ := os.ReadFile(host.configPath)
	if applied || string(got) != previous || len(host.writes) != 2 || !windowsBundleHasCode(result.Errors, "bundle_policy_not_adopted") {
		t.Fatalf("mismatched gateway confirmed=%t config=%q writes=%q errors=%v", applied, got, host.writes, result.Errors)
	}
}

func TestWindowsHotBundleWaitsForGatewayBundleIdentity(t *testing.T) {
	savedDigest, savedPoll := windowsEnterprisePolicyDigest, windowsEnterpriseHotConfigPoll
	t.Cleanup(func() { windowsEnterprisePolicyDigest, windowsEnterpriseHotConfigPoll = savedDigest, savedPoll })
	windowsEnterpriseHotConfigPoll = time.Millisecond
	const bundleID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8"
	calls := 0
	windowsEnterprisePolicyDigest = func(context.Context) ([]byte, error) {
		calls++
		id := "previous-bundle"
		if calls > 1 {
			id = bundleID
		}
		return []byte(`{"effective_digest":"sha256:abc","gateway_reported_digest":"sha256:abc","config_generation":3,"config_generation_recorded":true,"gateway_reported_config_generation":3,"gateway_reported_bundle_id":"` + id + `","gateway_reported_bundle_version":2}`), nil
	}
	if !windowsEnterpriseHotConfigAdopted(context.Background(), time.Second, configwrite.BundleRef{ID: bundleID, Version: 2}) || calls < 2 {
		t.Fatalf("gateway bundle identity was not awaited; calls=%d", calls)
	}
}

// Review loop round 2: a repeated delivery of the confirmed bundle over a
// drifted restart setting restarts the gateway, then is adopted only once the
// gateway names the confirmed bundle's ID and version. A gateway that names
// another bundle, another version or none is undone and fails the run; a
// store that no longer holds that confirmed bundle fails before the write.
func TestWindowsRepeatedBundleRestartRequiresTheGatewayBundleIdentity(t *testing.T) {
	const drifted = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 700\n"
	const confirmed = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n"
	const bundleID, other = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8", "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T9"
	for _, tc := range []struct {
		name      string
		reportID  string
		reportVer uint64
		current   string
		applied   bool
		code      string
		writes    int
	}{
		{name: "gateway names the confirmed bundle", reportID: bundleID, reportVer: 4, current: confirmed, applied: true, writes: 1},
		// The previous config is unrecorded in this fixture, so undo restores
		// its bytes directly rather than recording a second writer call.
		{name: "gateway names another bundle", reportID: other, reportVer: 4, current: confirmed, code: "bundle_policy_not_adopted", writes: 1},
		{name: "gateway names another version", reportID: bundleID, reportVer: 3, current: confirmed, code: "bundle_policy_not_adopted", writes: 1},
		{name: "gateway names no bundle", current: confirmed, code: "bundle_policy_not_adopted", writes: 1},
		{name: "confirmed bundle moved", reportID: bundleID, reportVer: 4, current: drifted, code: "bundle_state_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, opts := newHotConfigHost(t, drifted, confirmed)
			host.adopted = true
			host.bundleID, host.bundleVersion = tc.reportID, tc.reportVer
			opts.bundle = &windowsBundleRun{prepared: &enterprisebundle.Prepared{AlreadyApplied: true,
				Config: []byte(confirmed), ConfigSHA256: configwrite.SHA256Hex([]byte(confirmed))}}
			savedConfirmed, savedRestart, savedDigest := windowsHotConfirmedBundle, windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest
			t.Cleanup(func() {
				windowsHotConfirmedBundle, windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest = savedConfirmed, savedRestart, savedDigest
			})
			windowsHotConfirmedBundle = func(_ *enterprisebundle.Driver, config []byte) (configwrite.Options, []byte, *enterprisebundle.Ref, error) {
				opt, _ := enterprisebundle.GenerationOptions(&enterprisebundle.Receipt{BundleID: bundleID, Version: 4,
					Principal: "control-plane:acme/alice", SignerKeyID: "k1"})
				return opt, []byte(tc.current), &enterprisebundle.Ref{BundleID: bundleID, Version: 4, SignerKeyID: "k1"}, nil
			}
			restarts := 0
			windowsEnterpriseHotConfigRestart = func() (bool, error) { restarts++; return true, nil }
			stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("Verify")}}
			stub.install(t)
			windowsEnterprisePolicyDigest = host.digest
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
				&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
			installed, _ := os.ReadFile(host.configPath)
			if applied != tc.applied || len(host.writes) != tc.writes {
				t.Fatalf("applied=%t writes=%q errors=%+v", applied, host.writes, result.Errors)
			}
			if tc.applied {
				if string(installed) != confirmed || restarts != 1 || len(result.Errors) != 0 || !strings.Contains(host.writes[0], bundleID+" version 4") {
					t.Fatalf("adopted repeat: config=%q restarts=%d writes=%q errors=%+v", installed, restarts, host.writes, result.Errors)
				}
				return
			}
			if string(installed) != drifted || !windowsBundleHasCode(result.Errors, tc.code) {
				t.Fatalf("refused repeat: config=%q restarts=%d errors=%+v, want %s and the previous config", installed, restarts, result.Errors, tc.code)
			}
			if tc.code == "bundle_state_invalid" && restarts != 0 {
				t.Fatalf("a repeat that could not name its bundle restarted the gateway %d time(s)", restarts)
			}
		})
	}
}

func TestWindowsConfirmedBundleReturnsAlreadyAppliedBeforeDriftPlanning(t *testing.T) {
	const current = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	host, opts := newHotConfigHost(t, current, current)
	installedRoot := filepath.Join(t.TempDir(), "installed")
	installedScript := filepath.Join(installedRoot, "libexec", "install-enterprise.ps1")
	stagedScript := `C:\stage\install-enterprise.ps1`
	unlocks := 0
	opts.bundle = &windowsBundleRun{
		layout:   managed.StandaloneLayout{InstallRoot: installedRoot, ConfigPath: host.configPath},
		driver:   &enterprisebundle.Driver{Store: enterprisebundle.NewStore(t.TempDir(), t.TempDir())},
		prepared: &enterprisebundle.Prepared{AlreadyApplied: true, ConfigSHA256: configwrite.SHA256Hex([]byte(current))},
		unlock:   func() { unlocks++ },
	}
	// Setup's staged hash pins belong to its embedded release. Verify must
	// run the protected installed release with its recorded pins instead.
	opts.trustMode = windowsEnterpriseTrustHashPinned
	opts.payloadManifest = filepath.Join(t.TempDir(), "setup-payload-trust.json")
	opts.allowedSigners = []string{strings.Repeat("a", 64)}
	previousFinder := windowsEnterpriseScriptFinder
	windowsEnterpriseScriptFinder = func(path string) (string, error) {
		if path != installedScript {
			t.Fatalf("installed installer lookup = %q, want %q", path, installedScript)
		}
		return installedScript, nil
	}
	t.Cleanup(func() { windowsEnterpriseScriptFinder = previousFinder })
	previousDir := windowsEnterpriseHookRuntimeDir
	windowsEnterpriseHookRuntimeDir = func() (string, error) { return filepath.Join(t.TempDir(), "missing"), nil }
	t.Cleanup(func() { windowsEnterpriseHookRuntimeDir = previousDir })
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify")}}
	stub.install(t)
	windowsEnterprisePolicyDigest = host.digest
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) {
		t.Fatal("already-applied bundle reached drift planning")
		return "", nil
	}
	runner := windowsEnterpriseStandaloneRunner
	var scripts []string
	windowsEnterpriseStandaloneRunner = func(ctx context.Context, cmd *cobra.Command, script string, args []string) (windowsEnterpriseStandaloneRun, error) {
		scripts = append(scripts, script)
		return runner(ctx, cmd, script, args)
	}
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, stagedScript); err != nil {
		t.Fatalf("Setup ensure: %v\n%s", err, stdout.String())
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Noop || result.NoopReason != "already_applied" || len(stub.calls) != 2 || len(host.writes) != 0 || unlocks != 1 {
		t.Fatalf("same bundle = %+v, installer calls=%q writes=%q unlocks=%d", result, stub.calls, host.writes, unlocks)
	}
	if len(scripts) != 2 || scripts[0] != stagedScript || scripts[1] != installedScript {
		t.Fatalf("status/verify installers = %q", scripts)
	}
	verifyArgs := stub.calls[1]
	if !containsString(verifyArgs, "-TrustMode") || !containsString(verifyArgs, "Authenticode") ||
		containsString(verifyArgs, "-PayloadManifest") || containsString(verifyArgs, "-AllowedSigners") {
		t.Fatalf("installed verify received Setup trust inputs: %q", verifyArgs)
	}
	if opts.trustMode != windowsEnterpriseTrustHashPinned || opts.payloadManifest == "" || len(opts.allowedSigners) != 1 {
		t.Fatal("the read-only probe changed Setup's payload trust inputs")
	}
}

func TestWindowsConfirmedBundleCompilerMismatchRequiresSetup(t *testing.T) {
	for _, tc := range []struct {
		name, current string
	}{
		{"Fleet on missing compiler hash", "config_version: 9\nfleet:\n  enabled: true\n"},
		{"Fleet off stale compiler hash", "config_version: 9\nfleet:\n  enabled: false\n"},
	} {
		for _, setup := range []bool{false, true} {
			name := tc.name + " via installed CLI"
			if setup {
				name = tc.name + " via Setup"
			}
			t.Run(name, func(t *testing.T) {
				host, opts := newHotConfigHost(t, tc.current, tc.current)
				if !setup {
					opts.policyCompiler = ""
				}
				opts.bundle = &windowsBundleRun{
					layout: managed.StandaloneLayout{InstallRoot: filepath.Join(t.TempDir(), "installed"), ConfigPath: host.configPath},
					driver: &enterprisebundle.Driver{Store: enterprisebundle.NewStore(t.TempDir(), t.TempDir())},
					prepared: &enterprisebundle.Prepared{
						AlreadyApplied: true, Config: []byte(tc.current), ConfigSHA256: configwrite.SHA256Hex([]byte(tc.current)),
					},
					unlock: func() {},
				}
				originalFinder := windowsEnterpriseScriptFinder
				windowsEnterpriseScriptFinder = func(path string) (string, error) { return path, nil }
				t.Cleanup(func() { windowsEnterpriseScriptFinder = originalFinder })
				replies := []map[string]any{installedStatus("status"), installedStatus("verify")}
				if setup {
					replies = append(replies, installedStatus("upgrade"))
				}
				stub := &ensureStub{t: t, replies: replies}
				stub.install(t)
				windowsEnterpriseConfirmedBundleCompilerDrift = func(*windowsBundleRun) (bool, error) { return true, nil }
				windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) {
					if !setup {
						t.Fatal("installed CLI reached drift planning without a compiler source")
					}
					return "compiler", nil
				}
				command := &cobra.Command{}
				var stdout bytes.Buffer
				command.SetOut(&stdout)
				command.SetErr(&bytes.Buffer{})
				err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`)
				var result enterprisestatus.Result
				if jsonErr := json.Unmarshal(stdout.Bytes(), &result); jsonErr != nil {
					t.Fatalf("decode result: %v: %s", jsonErr, stdout.String())
				}
				if result.Noop || len(host.writes) != 0 {
					t.Fatalf("compiler mismatch was treated as a no-op or wrote config: %+v, writes=%q", result, host.writes)
				}
				if setup {
					if err != nil || len(stub.calls) != 3 || stub.calls[2][1] != "Upgrade" ||
						!strings.Contains(strings.Join(stub.calls[2], " "), `-PolicyCompiler C:\stage\policy_compiler.py`) {
						t.Fatalf("Setup did not upgrade with compiler: err=%v, calls=%q, result=%+v", err, stub.calls, result)
					}
				} else if err == nil || len(stub.calls) != 2 || !result.Installed ||
					!windowsBundleHasCode(result.Errors, "fleet_setup_required") {
					t.Fatalf("installed CLI did not refuse before mutation: err=%v, calls=%q, result=%+v", err, stub.calls, result)
				}
			})
		}
	}
}

func TestWindowsConfirmedBundleRepairsVerifiedInstallDamageWithReason(t *testing.T) {
	const current = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	host, opts := newHotConfigHost(t, current, current)
	previousLayout := windowsEnterpriseStandaloneLayoutForPreflight
	previousPending := windowsEnterpriseStandaloneTransactionPending
	previousVersion := windowsEnterpriseInstalledProductVersion
	previousRestoredVersion := windowsEnterprisePendingRestoredVersion
	windowsEnterpriseStandaloneLayoutForPreflight = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: filepath.Join(t.TempDir(), "missing.yaml")}, nil
	}
	windowsEnterpriseStandaloneTransactionPending = func() bool { return false }
	windowsEnterpriseInstalledProductVersion = func(*windowsEnterpriseLifecycleOptions) (string, error) { return "1.4.0", nil }
	windowsEnterprisePendingRestoredVersion = func(*windowsEnterpriseLifecycleOptions) (string, bool) { return "", false }
	t.Cleanup(func() {
		windowsEnterpriseStandaloneLayoutForPreflight = previousLayout
		windowsEnterpriseStandaloneTransactionPending = previousPending
		windowsEnterpriseInstalledProductVersion = previousVersion
		windowsEnterprisePendingRestoredVersion = previousRestoredVersion
	})
	installedRoot := filepath.Join(t.TempDir(), "installed")
	opts.bundle = &windowsBundleRun{
		layout:   managed.StandaloneLayout{InstallRoot: installedRoot, ConfigPath: host.configPath},
		driver:   &enterprisebundle.Driver{Store: enterprisebundle.NewStore(t.TempDir(), t.TempDir())},
		prepared: &enterprisebundle.Prepared{AlreadyApplied: true, ConfigSHA256: configwrite.SHA256Hex([]byte(current))},
		unlock:   func() {},
	}
	previousFinder := windowsEnterpriseScriptFinder
	windowsEnterpriseScriptFinder = func(path string) (string, error) { return path, nil }
	t.Cleanup(func() { windowsEnterpriseScriptFinder = previousFinder })
	failed := installedStatus("verify")
	failed["ok"] = false
	failed["errors"] = []string{"managed ACL is invalid"}
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), failed, installedStatus("repair")}}
	stub.install(t)
	windowsEnterprisePolicyDigest = host.digest
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) {
		t.Fatal("already-applied bundle reached drift planning")
		return "", nil
	}
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`); err != nil {
		t.Fatalf("repair damaged install: %v\n%s", err, stdout.String())
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Noop || len(stub.calls) != 3 || stub.calls[2][1] != "Repair" {
		t.Fatalf("unhealthy bundle result = %+v, installer calls = %q", result, stub.calls)
	}
	found := false
	for _, warning := range result.Warnings {
		found = found || warning.Code == "ensure_repair" && strings.Contains(warning.Message, "verify_failed: managed ACL is invalid")
	}
	if !found {
		t.Fatalf("repair did not name the failed check: %+v", result.Warnings)
	}
}

// GAP-0033: the lifecycle transaction owns Codex's machine policy on Windows.
// A config that turns Codex protection on or off is not written in the
// running gateway, so the guardian never writes Codex requirements and their
// ownership record for a deployment record that does not attest them; the
// upgrade transaction applies it instead, a signed bundle's included.
func TestWindowsHotConfigRoutesCodexTargetChangeToTransaction(t *testing.T) {
	const claudeOnly = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  connectors:\n    claudecode:\n      enabled: true\n"
	const withCodex = "config_version: 9\nguardrail:\n  block_at: LOW\n  connectors:\n    claudecode:\n      enabled: true\n    codex:\n      enabled: true\n"
	for _, tc := range []struct {
		name, previous, next string
	}{
		{"enable", claudeOnly, withCodex},
		{"disable", withCodex, claudeOnly},
	} {
		for _, bundle := range []bool{false, true} {
			name := tc.name + " Setup"
			if bundle {
				name = tc.name + " bundle"
			}
			t.Run(name, func(t *testing.T) {
				host, opts := newHotConfigHost(t, tc.previous, tc.next)
				host.adopted = true
				if bundle {
					opts.bundle = host.bundleRun()
				}
				result := newWindowsEnterpriseStandaloneResult("ensure", opts)
				applied, keys := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
					&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
				installed, err := os.ReadFile(host.configPath)
				if err != nil || applied || len(keys) != 0 || len(host.writes) != 0 || host.refreshes != 0 || string(installed) != tc.previous {
					t.Fatalf("Codex %s applied=%t keys=%q writes=%q refreshes=%d installed=%q read=%v",
						tc.name, applied, keys, host.writes, host.refreshes, installed, err)
				}
				if !opts.codexTargetTransaction || len(result.Errors) != 0 {
					t.Fatalf("Codex %s transaction=%t errors=%v", tc.name, opts.codexTargetTransaction, result.Errors)
				}
			})
		}
	}

	// A policy change that keeps Codex on stays in the running gateway, and
	// the flag a previous attempt of the run set does not carry over.
	host, opts := newHotConfigHost(t, withCodex, strings.Replace(withCodex, "block_at: LOW", "block_at: HIGH", 1))
	host.adopted = true
	opts.codexTargetTransaction = true
	opts.bundle = host.bundleRun()
	savedDigest := windowsEnterprisePolicyDigest
	t.Cleanup(func() { windowsEnterprisePolicyDigest = savedDigest })
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("Verify")}}
	stub.install(t)
	windowsEnterprisePolicyDigest = host.digest
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
	if !applied || opts.codexTargetTransaction || len(host.writes) != 1 || len(stub.calls) != 1 {
		t.Fatalf("Codex kept on: applied=%t transaction=%t writes=%q installerCalls=%q errors=%v",
			applied, opts.codexTargetTransaction, host.writes, stub.calls, result.Errors)
	}
}

// GAP-0033: an ordinary CONFIG= ensure that turns Codex on runs the upgrade
// transaction without writing the config first, and says why.
func TestWindowsEnterpriseEnsureUpgradesForCodexTargetChange(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  connectors:\n    claudecode: {}\n"
	const next = "config_version: 9\nguardrail:\n  connectors:\n    claudecode: {}\n    codex: {}\n"
	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
	result := runHotConfigEnsure(t, host, opts, stub)
	if len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" || len(host.writes) != 0 || host.refreshes != 0 {
		t.Fatalf("Codex enable: installer runs %q, writes %q, target refreshes %d", stub.calls, host.writes, host.refreshes)
	}
	if !strings.Contains(fmt.Sprint(result.Warnings), "turns Codex protection on or off") {
		t.Fatalf("Codex enable warnings = %v", result.Warnings)
	}
}

// GAP-0033: Setup carries the payload and upgrades; the installed CLI's
// `enterprise bundle apply` carries none, so its Codex change is a repair
// with the bundle config, which runs the same transaction.
func TestWindowsEnterpriseCodexTargetAction(t *testing.T) {
	setup := ensureTestOptions()
	if got := windowsEnterpriseCodexTargetAction(setup); got != "upgrade" {
		t.Fatalf("Setup payload: action %q, want upgrade", got)
	}
	installedCLI := ensureTestOptions()
	installedCLI.gatewayBinary, installedCLI.acpBinary, installedCLI.hookBinary, installedCLI.sensorHelperBinary = "", "", "", ""
	if got := windowsEnterpriseCodexTargetAction(installedCLI); got != "repair" {
		t.Fatalf("installed CLI: action %q, want repair", got)
	}
}

// GAP-0360: deployment metadata can lag the configured target when a vendor
// client was discovered after installation. A payload-less first bundle
// repairs through the lifecycle instead of asking the guardian to own it.
func TestWindowsEnsureReconcilesRecordedCodexTarget(t *testing.T) {
	for _, payload := range []bool{false, true} {
		t.Run(fmt.Sprintf("payload=%t", payload), func(t *testing.T) {
			_, opts := newHotConfigHost(t, "config_version: 9\nguardrail:\n  connectors:\n    codex: {}\n", "config_version: 9\nguardrail:\n  connectors:\n    codex: {}\n")
			if !payload {
				configPath := opts.configPath
				clearWindowsEnterpriseSources(opts)
				opts.configPath = configPath
			}
			saved := windowsEnterpriseEnsureDriftDetector
			t.Cleanup(func() { windowsEnterpriseEnsureDriftDetector = saved })
			windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "codex_target", nil }
			status := &windowsEnterpriseInstallerReport{OK: true, Installed: true, InstalledVersion: opts.productVersion}
			plan, err := planWindowsEnterpriseEnsure(status, opts, "installer.ps1")
			want := "repair"
			if payload {
				want = "upgrade"
			}
			if err != nil || plan.Action != want || !opts.codexTargetTransaction {
				t.Fatalf("plan=%+v transaction=%t error=%v", plan, opts.codexTargetTransaction, err)
			}
		})
	}
}

func TestWindowsEqualBaseFirstBundleStillPlansApply(t *testing.T) {
	const raw = "config_version: 9\nguardrail:\n  connectors:\n    claudecode: {}\n"
	_, opts := newHotConfigHost(t, raw, raw)
	configPath := opts.configPath
	clearWindowsEnterpriseSources(opts)
	opts.configPath = configPath
	opts.bundle = &windowsBundleRun{prepared: &enterprisebundle.Prepared{Receipt: &enterprisebundle.Receipt{}}}
	saved := windowsEnterpriseEnsureDriftDetector
	t.Cleanup(func() { windowsEnterpriseEnsureDriftDetector = saved })
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "", nil }
	status := &windowsEnterpriseInstallerReport{OK: true, Installed: true, InstalledVersion: opts.productVersion}
	plan, err := planWindowsEnterpriseEnsure(status, opts, "installer.ps1")
	if err != nil || plan.Action != "upgrade" || plan.Reason != "drift:bundle" {
		t.Fatalf("first bundle plan=%+v, %v", plan, err)
	}
	opts.bundle.prepared.AlreadyApplied = true
	plan, err = planWindowsEnterpriseEnsure(status, opts, "installer.ps1")
	if err != nil || plan.Action != "" || plan.Reason != "compliant" {
		t.Fatalf("confirmed repeat plan=%+v, %v", plan, err)
	}
}

// GAP-1418: the hook guardian renders a changed hook fail mode into every
// enrolled target's runtime sidecars on its next pass. A signed bundle that
// takes an explicit open back to the default closed (or closed to open, or
// changes the mode anywhere it can be set) waits for that render before its
// post-apply verify; one that leaves every hook fail mode alone does not
// wait, and a render that never comes fails the bundle with the previous
// config back.
func TestWindowsHotBundleWaitsForGuardianHookFailModeRender(t *testing.T) {
	const base = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  connectors:\n    codex: {}\n    claudecode: {}\n"
	const explicitOpen = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  connectors:\n    codex:\n      hook_fail_mode: open\n    claudecode:\n      hook_fail_mode: open\n"
	targets := []enterprisehooks.ManifestTarget{
		{SID: "S-1-5-21-1-2-3-1001", Connector: "codex"},
		{SID: "S-1-5-21-1-2-3-1001", Connector: "claudecode"},
		{SID: "S-1-5-21-1-2-3-1002", Connector: "codex"},
		{SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode"},
	}
	for _, tc := range []struct {
		name, previous, next string
		wantProof            bool
		proofErr             error
	}{
		{name: "explicit open back to the default closed", previous: explicitOpen, next: base, wantProof: true},
		{name: "default closed to explicit open", previous: base, next: explicitOpen, wantProof: true},
		{name: "explicit open to explicit closed", previous: explicitOpen, next: strings.ReplaceAll(explicitOpen, "hook_fail_mode: open", "hook_fail_mode: Closed"), wantProof: true},
		{name: "one connector only", previous: explicitOpen, next: strings.Replace(explicitOpen, "    claudecode:\n      hook_fail_mode: open\n", "    claudecode: {}\n", 1), wantProof: true},
		{name: "global hook fail mode", previous: base, next: strings.Replace(base, "  block_at: MEDIUM\n", "  block_at: MEDIUM\n  hook_fail_mode: open\n", 1), wantProof: true},
		{name: "hook fail modes unchanged", previous: explicitOpen, next: strings.Replace(explicitOpen, "MEDIUM", "LOW", 1)},
		{name: "the render never comes", previous: explicitOpen, next: base, wantProof: true, proofErr: errors.New("no verified DefenseClaw hook for S-1-5-21-1-2-3-1001/codex")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, opts := newHotConfigHost(t, tc.previous, tc.next)
			host.adopted = true
			host.hookProofErr = tc.proofErr
			opts.bundle = host.bundleRun()
			windowsEnterpriseHotConfigPublishedTargets = func(managed.StandaloneLayout) ([]enterprisehooks.ManifestTarget, error) {
				return targets, nil
			}
			restart := windowsEnterpriseHotConfigRestart
			t.Cleanup(func() { windowsEnterpriseHotConfigRestart = restart })
			windowsEnterpriseHotConfigRestart = func() (bool, error) {
				t.Fatal("a hook fail mode change restarted the gateway")
				return false, nil
			}
			stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("Verify")}}
			stub.install(t)
			savedDigest := windowsEnterprisePolicyDigest
			t.Cleanup(func() { windowsEnterprisePolicyDigest = savedDigest })
			windowsEnterprisePolicyDigest = host.digest
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
				&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
			if !tc.wantProof {
				if !applied || len(host.hookProofs) != 0 {
					t.Fatalf("applied=%t hook proofs=%d errors=%v", applied, len(host.hookProofs), result.Errors)
				}
				return
			}
			if len(host.hookProofs) != 1 || len(host.hookProofs[0]) != len(targets) {
				t.Fatalf("the post-apply verify did not wait for the guardian to render every target: proofs %v", host.hookProofs)
			}
			got, _ := os.ReadFile(host.configPath)
			if tc.proofErr == nil {
				if !applied || string(got) != tc.next || len(stub.calls) != 1 || stub.calls[0][1] != "Verify" {
					t.Fatalf("applied=%t config=%q installer=%q errors=%v", applied, got, stub.calls, result.Errors)
				}
				return
			}
			if applied || string(got) != tc.previous || len(stub.calls) != 0 || !windowsBundleHasCode(result.Errors, "bundle_post_verify_failed") {
				t.Fatalf("an unrendered fail mode: applied=%t config=%q installer=%q errors=%v", applied, got, stub.calls, result.Errors)
			}
		})
	}
}

func TestWindowsHotConfigHookFailModesChanged(t *testing.T) {
	for _, tc := range []struct {
		name, previous, next string
		want                 bool
	}{
		{name: "identical", previous: "guardrail:\n  hook_fail_mode: open\n", next: "guardrail:\n  hook_fail_mode: open\n"},
		{name: "case and spacing", previous: "guardrail:\n  hook_fail_mode: open\n", next: "guardrail:\n  hook_fail_mode: ' OPEN '\n"},
		{name: "removed", previous: "guardrail:\n  hook_fail_mode: open\n", next: "guardrail: {}\n", want: true},
		{name: "added under a connector", previous: "guardrail:\n  connectors:\n    codex: {}\n", next: "guardrail:\n  connectors:\n    codex:\n      hook_fail_mode: open\n", want: true},
		{name: "application protection override", previous: "application_protection:\n  connectors:\n    codex:\n      guardrail:\n        hook_fail_mode: open\n", next: "application_protection:\n  connectors:\n    codex:\n      guardrail:\n        hook_fail_mode: closed\n", want: true},
		{name: "other keys only", previous: "guardrail:\n  block_at: LOW\n", next: "guardrail:\n  block_at: HIGH\n"},
		{name: "unparseable", previous: "guardrail:\n  hook_fail_mode: open\n", next: "guardrail: [\n", want: true},
	} {
		if got := windowsHotConfigHookFailModesChanged([]byte(tc.previous), []byte(tc.next)); got != tc.want {
			t.Errorf("%s: changed = %t, want %t", tc.name, got, tc.want)
		}
	}
}
