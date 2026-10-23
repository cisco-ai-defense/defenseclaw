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

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1178: a failed hot apply whose restore of the previous config fails
// reports it and stops. Before, the restore error was ignored and the
// upgrade transaction ran with the config the attempt left behind as its
// preimage.
func TestWindowsEnterpriseHotConfigFailedRestoreStopsTheEnsure(t *testing.T) {
	for _, writeFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("initial write fails=%t", writeFails), func(t *testing.T) {
			const previous = "config_version: 9\nguardrail:\n  block_at: HIGH\n"
			const next = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
			host, opts := newHotConfigHost(t, previous, next)
			recorded := `{"generation":3,"config_sha256":"` + configwrite.SHA256Hex([]byte(previous)) + `"}`
			if err := os.WriteFile(configwrite.GenerationPath(host.configPath), []byte(recorded), 0o600); err != nil {
				t.Fatal(err)
			}
			apply := windowsEnterpriseHotConfigWrite
			windowsEnterpriseHotConfigWrite = func(ctx context.Context, path string, raw []byte, opt configwrite.Options) error {
				if strings.Contains(opt.Reason, "not applied") {
					return errors.New("config writer busy")
				}
				if err := apply(ctx, path, raw, opt); err != nil {
					return err
				}
				if writeFails {
					return configwrite.AfterPublication(errors.New("initial write failed after config publication"))
				}
				return nil
			}
			// The gateway never adopts the change, so the attempt is undone.
			stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status")}}
			stub.install(t)
			windowsEnterprisePolicyDigest = host.digest
			windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "config", nil }
			command := &cobra.Command{}
			var stdout bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(&bytes.Buffer{})
			err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`)
			var result enterprisestatus.Result
			if jsonErr := json.Unmarshal(stdout.Bytes(), &result); jsonErr != nil {
				t.Fatalf("decode result: %v: %s", jsonErr, stdout.String())
			}
			if len(stub.calls) != 1 {
				t.Fatalf("installer runs %q: want status only, no upgrade transaction after a failed restore", stub.calls)
			}
			if err == nil || result.OK || !windowsBundleHasCode(result.Errors, "config_restore_failed") {
				t.Fatalf("err=%v ok=%t errors=%+v, want config_restore_failed", err, result.OK, result.Errors)
			}
		})
	}
}

// GAP-1494: a failed hot apply that refreshed the enrolled targets for the
// new config publishes them again for the restored one.
func TestWindowsEnterpriseHotConfigUndoRepublishesTheTargets(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\nenterprise:\n  enrollment:\n    include_users:\n      - alice\n      - bob\n"
	const next = "config_version: 9\nguardrail:\n  block_at: MEDIUM\nenterprise:\n  enrollment:\n    include_users:\n      - alice\n"
	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	var refreshedWith []string
	windowsEnterpriseHotConfigRefreshTargets = func(context.Context, managed.StandaloneLayout) error {
		raw, err := os.ReadFile(host.configPath)
		if err != nil {
			return err
		}
		refreshedWith = append(refreshedWith, string(raw))
		return nil
	}
	failedVerify := installedStatus("Verify")
	failedVerify["ok"], failedVerify["gateway_ready"] = false, false
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), failedVerify, installedStatus("Upgrade")}}
	runHotConfigEnsure(t, host, opts, stub)
	if got, _ := os.ReadFile(host.configPath); string(got) != previous {
		t.Fatalf("config.yaml = %q, want the previous config back", got)
	}
	if len(refreshedWith) != 2 || refreshedWith[0] != next || refreshedWith[1] != previous {
		t.Fatalf("targets refreshed with %q, want the new config and then the restored one", refreshedWith)
	}
}

// GAP-1177: the unparseable-config rescue reads the installed config again
// under lifecycle.lock. A config another run committed while the preflight
// ran stays installed, and the stale broken bytes are not kept.
func TestWindowsEnterpriseUnparseableRescueKeepsAConcurrentCommit(t *testing.T) {
	const broken = "invalid: [\n"
	const committed = "config_version: 9\nguardrail:\n  block_at: HIGH\n"
	candidate := strings.Replace(standaloneGatewayCheckConfig, "config_version: 8\n", "config_version: 9\n", 1)
	originalLayout, originalSource := windowsEnterpriseStandaloneLayoutForPreflight, windowsEnterpriseStandaloneConfigSource
	t.Cleanup(func() {
		windowsEnterpriseStandaloneLayoutForPreflight = originalLayout
		windowsEnterpriseStandaloneConfigSource = originalSource
	})
	// No layout for the compile step: the rescue's own reads are what is tested.
	windowsEnterpriseStandaloneLayoutForPreflight = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{}, errors.New("no preflight layout in this test")
	}
	windowsEnterpriseStandaloneConfigSource = func(string) error { return nil }

	// Control: with no concurrent commit the supplied config replaces the
	// broken one, which is kept.
	host, opts := newHotConfigHost(t, broken, candidate)
	kept, err := installWindowsEnterpriseSuppliedConfigOverUnparseable(opts.configPath)
	if err != nil || kept == "" {
		t.Fatalf("rescue = (%q, %v), want the broken config kept", kept, err)
	}
	if got, _ := os.ReadFile(host.configPath); string(got) != candidate {
		t.Fatalf("config.yaml = %q, want the supplied config", got)
	}

	host, opts = newHotConfigHost(t, broken, candidate)
	windowsEnterpriseHotConfigLock = func(string) (func(), error) {
		// Another lifecycle run commits a valid config before this one gets the lock.
		if err := os.WriteFile(host.configPath, []byte(committed), 0o600); err != nil {
			return nil, err
		}
		return func() {}, nil
	}
	kept, err = installWindowsEnterpriseSuppliedConfigOverUnparseable(opts.configPath)
	if err != nil || kept != "" {
		t.Fatalf("rescue = (%q, %v), want nothing to do after the concurrent commit", kept, err)
	}
	if got, _ := os.ReadFile(host.configPath); string(got) != committed {
		t.Fatalf("config.yaml = %q, want the concurrently committed config", got)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(host.configPath), "rejected-config.yaml")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rejected-config.yaml written from stale bytes: %v", statErr)
	}
}

// Review loop round 3: a failed hot apply whose undo cannot be proven stops
// the gateway (verified stopped) instead of leaving a config no one verified
// enforcing, and reports what is really installed: which config config.yaml
// holds, and whose targets are published. Each way the undo can stay
// unproven is covered: the config bytes do not go back (after the gateway
// adopted the change and its targets were refreshed, after the refresh
// itself failed, and before adoption), the targets cannot be published
// again, and the gateway does not report the restored policy. Before, the
// undo returned after a failed restore, said nothing else was changed, and
// never checked the gateway. The proven undo is the control: nothing is
// stopped.
func TestWindowsEnterpriseHotConfigUnprovenUndoFailsClosed(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\nenterprise:\n  enrollment:\n    include_users:\n      - alice\n      - bob\n"
	const next = "config_version: 9\nguardrail:\n  block_at: MEDIUM\nenterprise:\n  enrollment:\n    include_users:\n      - alice\n"
	failedVerify := installedStatus("Verify")
	failedVerify["ok"], failedVerify["gateway_ready"] = false, false
	for _, tc := range []struct {
		name           string
		restoreFails   bool
		refreshFails   int // the refresh call (1: the apply's, 2: the undo's) that fails
		adopted        bool
		gatewayStays   bool // the gateway keeps reporting the new config's policy
		verify         bool // a post-apply verify runs and fails
		code           string
		installed      string
		stops          int
		state, targets string
	}{
		{name: "restore fails after adoption and target refresh", restoreFails: true, adopted: true, verify: true,
			code: "config_restore_failed", installed: next, stops: 1,
			state: "still holds the config that was not applied", targets: "a user it does not enroll has no DefenseClaw hooks"},
		{name: "restore fails after the target refresh failed", restoreFails: true, refreshFails: 1, adopted: true,
			code: "config_restore_failed", installed: next, stops: 1,
			state: "still holds the config that was not applied", targets: "a user it does not enroll has no DefenseClaw hooks"},
		{name: "restore fails before adoption", restoreFails: true,
			code: "config_restore_failed", installed: next, stops: 1,
			state: "still holds the config that was not applied", targets: "the enrolled targets were not changed"},
		{name: "targets cannot be published again", refreshFails: 2, adopted: true, verify: true,
			code: "targets_restore_failed", installed: previous, stops: 1,
			state: "holds the previous config", targets: "a user it does not enroll has no DefenseClaw hooks"},
		{name: "gateway keeps the new policy", adopted: true, gatewayStays: true, verify: true,
			code: "config_restore_failed", installed: previous, stops: 1,
			state: "holds the previous config", targets: "published again for the previous config"},
		{name: "proven undo", adopted: true, verify: true, installed: previous},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, opts := newHotConfigHost(t, previous, next)
			recorded := `{"generation":3,"config_sha256":"` + configwrite.SHA256Hex([]byte(previous)) + `"}`
			if err := os.WriteFile(configwrite.GenerationPath(host.configPath), []byte(recorded), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.restoreFails {
				apply := windowsEnterpriseHotConfigWrite
				windowsEnterpriseHotConfigWrite = func(ctx context.Context, path string, raw []byte, opt configwrite.Options) error {
					if strings.Contains(opt.Reason, "not applied") {
						return errors.New("config writer busy")
					}
					return apply(ctx, path, raw, opt)
				}
			}
			refreshes := 0
			windowsEnterpriseHotConfigRefreshTargets = func(context.Context, managed.StandaloneLayout) error {
				refreshes++
				if refreshes == tc.refreshFails {
					return errors.New("enumerator refused")
				}
				return nil
			}
			replies := []map[string]any{installedStatus("status")}
			if tc.verify {
				replies = append(replies, failedVerify)
			}
			if tc.code == "" {
				// A proven undo hands the change to the upgrade transaction.
				replies = append(replies, installedStatus("Upgrade"))
			}
			stub := &ensureStub{t: t, replies: replies}
			stub.install(t)
			// The installed CLI's digest: the policy config.yaml computes to,
			// and the one the gateway enforces, which follows config.yaml
			// unless the gateway stays on the new config.
			nextDigest := "sha256:" + configwrite.SHA256Hex([]byte(next))
			adoptedNext := false
			windowsEnterprisePolicyDigest = func(context.Context) ([]byte, error) {
				installed, err := os.ReadFile(host.configPath)
				if err != nil {
					return nil, err
				}
				effective := "sha256:" + configwrite.SHA256Hex(installed)
				// The healthy gateway enforces the previous policy before
				// publication, even in the row where it never adopts next.
				enforced := "sha256:" + configwrite.SHA256Hex([]byte(previous))
				if tc.adopted {
					enforced = effective
					adoptedNext = adoptedNext || effective == nextDigest
					if tc.gatewayStays && adoptedNext {
						enforced = nextDigest
					}
				}
				generation := strconv.Itoa(len(host.writes) + 10)
				return []byte(`{"effective_digest":"` + effective + `","config_generation":` + generation +
					`,"config_generation_recorded":true,"gateway_reported_digest":"` + enforced +
					`","gateway_reported_config_generation":` + generation + `}`), nil
			}
			windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "config", nil }
			command := &cobra.Command{}
			var stdout bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(&bytes.Buffer{})
			_ = runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`)
			var result enterprisestatus.Result
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("decode result: %v: %s", err, stdout.String())
			}
			if got, _ := os.ReadFile(host.configPath); string(got) != tc.installed {
				t.Fatalf("config.yaml = %q, want %q", got, tc.installed)
			}
			if host.stops != tc.stops {
				t.Fatalf("gateway stopped %d times, want %d; errors %+v", host.stops, tc.stops, result.Errors)
			}
			if tc.code == "" {
				if windowsBundleHasCode(result.Errors, "config_restore_failed") || windowsBundleHasCode(result.Errors, "targets_restore_failed") {
					t.Fatalf("a proven undo reported a failed restore: %+v", result.Errors)
				}
				return
			}
			if result.OK || !windowsBundleHasCode(result.Errors, tc.code) {
				t.Fatalf("ok=%t errors=%+v, want %s", result.OK, result.Errors, tc.code)
			}
			if len(stub.calls) != len(replies) {
				t.Fatalf("installer runs %q: no upgrade transaction may follow an unproven undo", stub.calls)
			}
			message := fmt.Sprint(result.Errors)
			for _, want := range []string{tc.state, tc.targets, "gateway service was stopped"} {
				if !strings.Contains(message, want) {
					t.Fatalf("errors %s do not say %q", message, want)
				}
			}
			if strings.Contains(message, "nothing else was changed") {
				t.Fatalf("errors %s claim nothing else changed", message)
			}
		})
	}
}

// Review loop round 3: a bundle whose gateway restart failed, and whose undo
// could not put the previous config back, leaves the gateway stopped: the
// restart recovery does not start it again on the config it left. A gateway
// that cannot be stopped is reported as such.
func TestWindowsEnterpriseHotConfigUnprovenUndoIsNotRestarted(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 500\n"
	const next = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n"
	for _, stopErr := range []error{nil, errors.New("access denied")} {
		host, opts := newHotConfigHost(t, previous, next)
		recorded := `{"generation":3,"config_sha256":"` + configwrite.SHA256Hex([]byte(previous)) + `"}`
		if err := os.WriteFile(configwrite.GenerationPath(host.configPath), []byte(recorded), 0o600); err != nil {
			t.Fatal(err)
		}
		opts.bundle = host.bundleRun()
		apply := windowsEnterpriseHotConfigWrite
		windowsEnterpriseHotConfigWrite = func(ctx context.Context, path string, raw []byte, opt configwrite.Options) error {
			if strings.Contains(opt.Reason, "not applied") {
				return errors.New("config writer busy")
			}
			return apply(ctx, path, raw, opt)
		}
		savedRestart, savedRecover, savedDigest := windowsEnterpriseHotConfigRestart, windowsEnterpriseHotConfigRecover, windowsEnterprisePolicyDigest
		t.Cleanup(func() {
			windowsEnterpriseHotConfigRestart, windowsEnterpriseHotConfigRecover, windowsEnterprisePolicyDigest = savedRestart, savedRecover, savedDigest
		})
		recovers := 0
		windowsEnterpriseHotConfigRestart = func() (bool, error) { return false, errors.New("start failed") }
		windowsEnterpriseHotConfigRecover = func() (bool, error) { recovers++; return true, nil }
		stopFails := stopErr
		windowsEnterpriseHotConfigFailClosed = func() error { host.stops++; return stopFails }
		stub := &ensureStub{t: t}
		stub.install(t)
		windowsEnterprisePolicyDigest = host.digest
		result := newWindowsEnterpriseStandaloneResult("ensure", opts)
		applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
			&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
		message := fmt.Sprint(result.Errors)
		if applied || host.stops != 1 || recovers != 0 || !opts.hotConfigRestoreFailed || !windowsBundleHasCode(result.Errors, "config_restore_failed") {
			t.Fatalf("stop error %v: applied=%t stops=%d recovers=%d errors=%s", stopErr, applied, host.stops, recovers, message)
		}
		want := "gateway service was stopped"
		if stopErr != nil {
			want = "could not be stopped (access denied); it may still enforce"
		}
		if !strings.Contains(message, want) {
			t.Fatalf("stop error %v: errors %s do not say %q", stopErr, message, want)
		}
	}
}
