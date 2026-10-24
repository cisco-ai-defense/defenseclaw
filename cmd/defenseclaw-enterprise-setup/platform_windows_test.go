// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// An implicit deferred install over an active deployment must be rejected by
// Setup itself, before the lifecycle can publish an unclaimed rollback intent.
func TestStandaloneSetupRefusesDeferredInstallOverDeployment(t *testing.T) {
	previousFlavor, previousPayload, previousDeployment := enterpriseSetupStandaloneFlavor, enterpriseSetupPayloadLoader, standaloneSetupDeployment
	t.Cleanup(func() {
		enterpriseSetupStandaloneFlavor, enterpriseSetupPayloadLoader, standaloneSetupDeployment = previousFlavor, previousPayload, previousDeployment
	})
	enterpriseSetupStandaloneFlavor = func() bool { return true }
	payloadFS, _ := newEnterprisePayloadFixtureForFlavor(t, false, true)
	enterpriseSetupPayloadLoader = func() (enterprisePayload, error) { return loadEnterprisePayload(payloadFS) }
	for _, state := range []winpath.EnterpriseDeploymentState{
		winpath.EnterpriseDeploymentInstalled,
		winpath.EnterpriseDeploymentUnknown,
	} {
		t.Run(string(state), func(t *testing.T) {
			standaloneSetupDeployment = func() (winpath.EnterpriseDeployment, error) {
				return winpath.EnterpriseDeployment{State: state}, nil
			}
			var stdout, stderr bytes.Buffer
			code := runEnterpriseSetup([]string{"/install", "JSON=1"}, &stdout, &stderr)
			var result struct {
				OK       bool `json:"ok"`
				ExitCode int  `json:"exit_code"`
				Errors   []struct {
					Code string `json:"code"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || code != enterpriseInvalidArgsExitCode ||
				result.OK || result.ExitCode != code || len(result.Errors) != 1 || result.Errors[0].Code != "invalid_arguments" ||
				!strings.Contains(stdout.String(), "nothing was changed") || stderr.Len() != 0 {
				t.Fatalf("state=%s code=%d stdout=%q stderr=%q parse=%v", state, code, stdout.String(), stderr.String(), err)
			}
		})
	}
	for _, state := range []winpath.EnterpriseDeploymentState{
		winpath.EnterpriseDeploymentAbsent,
		winpath.EnterpriseDeploymentTombstone,
	} {
		standaloneSetupDeployment = func() (winpath.EnterpriseDeployment, error) {
			return winpath.EnterpriseDeployment{State: state}, nil
		}
		if err := requireStandaloneDeferredInstallAbsent(); err != nil {
			t.Fatalf("a %s standalone deployment cannot start a fresh deferred Install: %v", state, err)
		}
	}
}

func TestTimedOutStandaloneSetupRecoveryUsesBoundedJournalReplay(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	opts := enterpriseSetupOptions{Action: "uninstall", Standalone: true, JSON: true,
		Force: true, Purge: true, LifecycleTimeout: time.Minute}
	previous := enterpriseSetupRecoveryRunner
	t.Cleanup(func() { enterpriseSetupRecoveryRunner = previous })
	called := 0
	enterpriseSetupRecoveryRunner = func(ctx context.Context, path string, args []string, dir string, env []string) ([]byte, error) {
		called++
		if _, deadline := ctx.Deadline(); !deadline || ctx.Err() != nil {
			t.Fatal("recovery must have a fresh bounded context after the install timeout")
		}
		if path != filepath.Join(stage, "defenseclaw.exe") || dir != stage ||
			!reflect.DeepEqual(args, enterpriseLifecycleArguments(stage, enterpriseSetupOptions{
				Action: "recover", Standalone: true, JSON: true,
			})) || !reflect.DeepEqual(env, []string{"trusted=test"}) {
			t.Fatalf("recovery child path=%q args=%q dir=%q env=%q", path, args, dir, env)
		}
		return []byte(`{"schema_version":2,"action":"recover","profile":"standalone","platform":"windows","ok":true,"installed":true,"transaction_pending":false,"services":[{"name":"DefenseClawGateway","kind":"gateway","state":"running","required":true}]}`), nil
	}
	parent, cancel := context.WithCancel(context.Background())
	cancel() // The timed-out lifecycle context cannot bound its recovery.
	recoverChild := func(env []string) func(context.Context) ([]byte, error) {
		return func(ctx context.Context) ([]byte, error) {
			return enterpriseSetupRecoveryRunner(ctx, filepath.Join(stage, "defenseclaw.exe"),
				enterpriseLifecycleArguments(stage, standaloneRecoveryOptions(opts)), stage, env)
		}
	}
	recovered, err := recoverTimedOutStandaloneLifecycle(parent, recoverChild([]string{"trusted=test"}))
	if err != nil || called != 1 || recovered == nil {
		t.Fatalf("recovery call=%d error=%v", called, err)
	}
	var output bytes.Buffer
	writeEnterpriseSetupFailureFor(&output, &bytes.Buffer{}, true, standaloneSetupArtifactName, opts,
		standaloneEnterpriseSetupTimeoutWithRecovery(opts, context.DeadlineExceeded, recovered), enterpriseFailureExitCode)
	var result struct {
		Action             string `json:"action"`
		OK                 bool   `json:"ok"`
		Installed          bool   `json:"installed"`
		TransactionPending bool   `json:"transaction_pending"`
		Services           []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"services"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Action != "uninstall" ||
		result.OK || !result.Installed || result.TransactionPending || len(result.Services) != 1 ||
		result.Services[0].Name != "DefenseClawGateway" || result.Services[0].State != "running" {
		t.Fatalf("Setup did not retain the recovered deployment proof: %s (%v)", output.String(), err)
	}
	enterpriseSetupRecoveryRunner = func(context.Context, string, []string, string, []string) ([]byte, error) {
		return []byte(`{"schema_version":2,"action":"recover","profile":"standalone","platform":"windows","ok":true,"transaction_pending":true}`), nil
	}
	if _, err := recoverTimedOutStandaloneLifecycle(parent, recoverChild(nil)); err == nil {
		t.Fatal("a pending transaction was reported as restored")
	}
}

func TestSignedStandaloneTrustRejectsUnsignedOuterSetup(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := verifySignedEnterpriseSetup(file, path); err == nil {
		t.Fatal("WinVerifyTrust accepted the unsigned Go test image as signed Setup")
	}
}

func TestEnterpriseLifecycleArgumentsUsePublicMachineTransaction(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	opts := enterpriseSetupOptions{
		Action:                        "install",
		Config:                        `C:\staging\config.yaml`,
		Manifest:                      `C:\staging\targets.yaml`,
		AttestAgentApplicationControl: true,
		AttestClaudeEffectivePolicy:   true,
		NoStart:                       true,
		JSON:                          true,
	}
	want := []string{
		"enterprise", "windows", "install",
		"--installer", filepath.Join(stage, "install-enterprise.ps1"),
		"--broker-binary", filepath.Join(stage, "defenseclaw-cmid-broker.exe"),
		"--gateway-binary", filepath.Join(stage, "defenseclaw-gateway.exe"),
		"--acp-binary", filepath.Join(stage, "defenseclaw-acp.exe"),
		"--hook-binary", filepath.Join(stage, "defenseclaw-hook.exe"),
		"--sensor-helper-binary", filepath.Join(stage, "defenseclaw-sensor-helper.exe"),
		"--cli-binary", filepath.Join(stage, "defenseclaw.exe"),
		"--config", opts.Config,
		"--manifest", opts.Manifest,
		"--bootstrap-parent", filepath.Join(stage, enterpriseSetupScratchDirName),
		"--no-start", "--json",
		"--attest-agent-application-control",
		"--attest-claude-effective-policy",
	}
	if got := enterpriseLifecycleArguments(stage, opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("enterpriseLifecycleArguments() = %#v, want %#v", got, want)
	}
}

func TestEnterpriseLifecycleReadOnlyDoesNotSupplyReplacementArtifacts(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	got := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{Action: "status", JSON: true})
	want := []string{
		"enterprise", "windows", "status",
		"--installer", filepath.Join(stage, "install-enterprise.ps1"),
		"--bootstrap-parent", filepath.Join(stage, enterpriseSetupScratchDirName),
		"--json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enterpriseLifecycleArguments() = %#v, want %#v", got, want)
	}
}

func TestEnterpriseLifecycleArgumentsForStandalonePayload(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	signer := "ab" + strings.Repeat("0", 62)
	got := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{
		Action:             "ensure",
		Config:             `C:\staging\config.yaml`,
		JSON:               true,
		Standalone:         true,
		StandaloneUnsigned: true,
		ProductVersion:     "1.4.0",
		AllowedSigners:     strings.ToUpper(signer),
	})
	want := []string{
		"enterprise", "windows", "ensure",
		"--installer", filepath.Join(stage, "install-enterprise.ps1"),
		"--gateway-binary", filepath.Join(stage, "defenseclaw-gateway.exe"),
		"--acp-binary", filepath.Join(stage, "defenseclaw-acp.exe"),
		"--hook-binary", filepath.Join(stage, "defenseclaw-hook.exe"),
		"--sensor-helper-binary", filepath.Join(stage, "defenseclaw-sensor-helper.exe"),
		"--cli-binary", filepath.Join(stage, "defenseclaw.exe"),
		"--config", `C:\staging\config.yaml`,
		// --bootstrap-parent is unconditional post-#839 (Authenticode-
		// aware trailer reader + protected bootstrap parent): the
		// standalone and Secure Client lifecycles both spin up the
		// isolated bootstrap environment, so this flag is forwarded for
		// every action and flavor.
		"--bootstrap-parent", filepath.Join(stage, enterpriseSetupScratchDirName),
		"--json",
		"--profile", "standalone",
		"--product-version", "1.4.0",
		"--trust-mode", "hash_pinned",
		"--payload-manifest", filepath.Join(stage, standalonePayloadTrustName),
		"--allowed-signer", signer,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enterpriseLifecycleArguments() = %#v, want %#v", got, want)
	}
}

// Managed Setup never forwards a Fleet compiler.
func TestEnterpriseLifecycleArgumentsOmitPolicyCompiler(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	for _, action := range []string{"install", "upgrade", "repair", "ensure"} {
		got := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{
			Action: action, Standalone: true,
		})
		for _, argument := range got {
			if argument == "--policy-compiler" {
				t.Fatalf("%s forwarded a withheld compiler: %#v", action, got)
			}
		}
	}
}

func TestStandaloneSetupReportsMalformedInputPathsAsInvalidArguments(t *testing.T) {
	for _, value := range []string{
		"config.yaml",
		` C:\dc\config.yaml`,
		`%ProgramData%\config.yaml`,
		filepath.Join(t.TempDir(), "missing", "config.yaml"),
	} {
		_, err := validateEnterpriseSetupInput(value, "config")
		if err == nil {
			t.Fatalf("%q accepted", value)
		}
		var invalid enterpriseSetupInvalidArguments
		if standalone := standaloneEnterpriseSetupInputError(true, err); !errors.As(standalone, &invalid) || standalone.Error() != err.Error() {
			t.Fatalf("%q: standalone error %v is not invalid arguments with the same text", value, standalone)
		}
		if secureClient := standaloneEnterpriseSetupInputError(false, err); errors.As(secureClient, &invalid) || secureClient != err {
			t.Fatalf("%q: Secure Client error changed: %v", value, secureClient)
		}
	}
	// An existing input that fails the trust check stays a 1603 security
	// refusal for the Secure Client Setup. The standalone Setup refuses it
	// as every config the lifecycle will not take (1639) and names the
	// account and the icacls fix, not a bare SID (GAP-0528, GAP-0562).
	untrusted := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(untrusted, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := validateEnterpriseSetupInput(untrusted, "config")
	var invalid enterpriseSetupInvalidArguments
	if err == nil || errors.As(standaloneEnterpriseSetupInputError(false, err), &invalid) {
		t.Fatalf("untrusted config: %v", err)
	}
	standalone := standaloneEnterpriseSetupInputError(true, err)
	if !errors.As(standalone, &invalid) || !strings.Contains(standalone.Error(), "icacls \""+filepath.Dir(untrusted)+"\"") ||
		strings.Contains(standalone.Error(), "access mask") {
		t.Fatalf("standalone untrusted config error = %v", standalone)
	}
}

// GAP-0525: Setup takes the staging folders interrupted runs left once they
// are old enough, but never one a running Setup holds as its lifecycle's
// working directory, nor a name that is not a stage capability.
func TestRemoveStaleEnterpriseSetupStagesSkipsYoungAndBusyFolders(t *testing.T) {
	programData := t.TempDir()
	stale := filepath.Join(programData, enterpriseSetupStagePrefix+strings.Repeat("a", 32))
	busy := filepath.Join(programData, enterpriseSetupStagePrefix+strings.Repeat("b", 32))
	other := filepath.Join(programData, enterpriseSetupStagePrefix+"notours")
	for _, dir := range []string{stale, busy, other} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var progress, diagnostics bytes.Buffer
	removeStaleEnterpriseSetupStages(programData, time.Now(), &progress, &diagnostics)
	for _, dir := range []string{stale, busy, other} {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("a young folder was taken: %v", err)
		}
	}
	name, err := windows.UTF16PtrFromString(busy)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	removeStaleEnterpriseSetupStages(programData, time.Now().Add(time.Hour), &progress, &diagnostics)
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the stale folder stayed: %v", err)
	}

	for _, dir := range []string{busy, other} {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("a held or foreign folder was taken: %v", err)
		}
	}
	if !strings.Contains(diagnostics.String(), "an interrupted Setup run left") {
		t.Fatalf("diagnostics = %q", diagnostics.String())
	}
}

// A removed stale stage is progress: an MDM reads any stderr output as a
// failed Setup, so nothing goes to diagnostics (GAP-1353).
func TestRemoveStaleEnterpriseSetupStagesReportsRemovalOffStderr(t *testing.T) {
	programData := t.TempDir()
	if err := os.Mkdir(filepath.Join(programData, enterpriseSetupStagePrefix+strings.Repeat("c", 32)), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := cleanupStaleEnterpriseSetupStage
	t.Cleanup(func() { cleanupStaleEnterpriseSetupStage = previous })
	cleanupStaleEnterpriseSetupStage = func(stage, _ string) error { return os.RemoveAll(stage) }
	var progress, diagnostics bytes.Buffer
	removeStaleEnterpriseSetupStages(programData, time.Now().Add(time.Hour), &progress, &diagnostics)
	if diagnostics.Len() != 0 || !strings.Contains(progress.String(), "removed the staging folder") {
		t.Fatalf("progress = %q, diagnostics = %q", progress.String(), diagnostics.String())
	}
}

// The outer signed DefenseClawSetup EXE always forwards its own protected
// %ProgramData%\DefenseClaw-Enterprise-Setup-<hex>\scratch directory as
// install-enterprise.ps1's -BootstrapParent, so the one-shot bootstrap
// dir does not land under C:\Windows\Temp. On Azure-AD-joined hosts,
// C:\Windows\Temp carries an inherited Allow ACE for the interactive AAD
// principal with replacement rights, which fails the module's later
// trusted-ancestor walk on rendered YAML content.
func TestEnterpriseLifecycleArgumentsAlwaysForwardsBootstrapParent(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	wantParent := filepath.Join(stage, enterpriseSetupScratchDirName)
	for _, action := range []string{"install", "upgrade", "repair", "reconcile", "status", "verify", "uninstall"} {
		t.Run(action, func(t *testing.T) {
			got := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{Action: action})
			foundIndex := -1
			for index := 0; index < len(got)-1; index++ {
				if got[index] == "--bootstrap-parent" {
					foundIndex = index
					break
				}
			}
			if foundIndex < 0 {
				t.Fatalf("%s: --bootstrap-parent missing from args: %#v", action, got)
			}
			if got[foundIndex+1] != wantParent {
				t.Fatalf("%s: --bootstrap-parent value = %q, want %q", action, got[foundIndex+1], wantParent)
			}
		})
	}
}

// GAP-0608: the lifecycle receives TRUSTANCHORS= with the CONFIG= it is
// refused with (and on any mutation), so it refuses the run and records the
// refused anchor install.
func TestEnterpriseLifecycleForwardsTrustAnchorsItRefuses(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	for _, action := range []string{"ensure", "repair"} {
		got := strings.Join(enterpriseLifecycleArguments(stage, enterpriseSetupOptions{Action: action, Standalone: true,
			Config: `C:\c.yaml`, TrustAnchors: `C:\b\a.json`, JSON: true}), " ")
		for _, want := range []string{`--config C:\c.yaml`, `--trust-anchors C:\b\a.json`, "--profile standalone"} {
			if !strings.Contains(got, want) {
				t.Fatalf("%s arguments %q lack %q", action, got, want)
			}
		}
	}
}
