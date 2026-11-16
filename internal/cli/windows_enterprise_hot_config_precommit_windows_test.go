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
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A confirmed signed bundle is the recovery source when installed config
// drifts from the gateway's live generation. A new delivery has no such
// established last-good identity and keeps the prewrite proof requirement.
func TestWindowsConfirmedBundleReplayRepairsDriftWithPriorPolicyMismatch(t *testing.T) {
	const drifted = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 700\n"
	const confirmed = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n"
	const bundleID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8"
	for _, repeat := range []bool{false, true} {
		name := "new delivery"
		if repeat {
			name = "confirmed replay"
		}
		t.Run(name, func(t *testing.T) {
			host, opts := newHotConfigHost(t, drifted, confirmed)
			host.adopted = true
			host.bundleID, host.bundleVersion = bundleID, 4
			if repeat {
				opts.bundle = &windowsBundleRun{prepared: &enterprisebundle.Prepared{AlreadyApplied: true,
					Config: []byte(confirmed), ConfigSHA256: configwrite.SHA256Hex([]byte(confirmed))}}
			} else {
				opts.bundle = host.bundleRun()
			}
			savedConfirmed, savedRestart, savedDigest := windowsHotConfirmedBundle, windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest
			t.Cleanup(func() {
				windowsHotConfirmedBundle, windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest = savedConfirmed, savedRestart, savedDigest
			})
			windowsHotConfirmedBundle = func(_ *enterprisebundle.Driver, _ []byte) (configwrite.Options, []byte, *enterprisebundle.Ref, error) {
				opt, _ := enterprisebundle.GenerationOptions(&enterprisebundle.Receipt{BundleID: bundleID, Version: 4,
					Principal: "control-plane:acme/alice", SignerKeyID: "k1"})
				return opt, []byte(confirmed), &enterprisebundle.Ref{BundleID: bundleID, Version: 4, SignerKeyID: "k1"}, nil
			}
			restarts := 0
			windowsEnterpriseHotConfigRestart = func() (bool, error) { restarts++; return true, nil }
			stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("Verify")}}
			stub.install(t)
			windowsEnterprisePolicyDigest = func(ctx context.Context) ([]byte, error) {
				if len(host.writes) == 0 {
					proof := []byte(`{"effective_digest":"sha256:drift","gateway_reported_digest":"sha256:live",` +
						`"gateway_reported_bundle_id":"` + bundleID + `","gateway_reported_bundle_version":4}`)
					var parsed policyDigestReport
					if err := json.Unmarshal(proof, &parsed); err != nil || parsed.Digest == "" || parsed.GatewayReportedDigest == "" {
						t.Fatalf("invalid prior proof %q: %+v, %v", proof, parsed, err)
					}
					return proof, nil
				}
				return host.digest(ctx)
			}
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
				&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
			installed, err := os.ReadFile(host.configPath)
			if err != nil {
				t.Fatal(err)
			}
			if repeat {
				if !applied || string(installed) != confirmed || len(host.writes) != 1 || restarts != 1 || len(result.Errors) != 0 {
					t.Fatalf("confirmed replay: applied=%t config=%q writes=%q restarts=%d errors=%+v",
						applied, installed, host.writes, restarts, result.Errors)
				}
			} else if applied || string(installed) != drifted || len(host.writes) != 0 || restarts != 0 ||
				!windowsBundleHasCode(result.Errors, "bundle_hot_apply_unavailable") {
				t.Fatalf("new delivery: applied=%t config=%q writes=%q restarts=%d errors=%+v",
					applied, installed, host.writes, restarts, result.Errors)
			}
		})
	}
}

// A config writer conflict occurs before publication. An MDM write made
// after the lifecycle's snapshot belongs to that writer; undoing the old
// snapshot would overwrite it, and an unprovable undo would stop a healthy
// gateway. Setup may continue through its full transaction; a signed bundle
// reports a retryable conflict without touching the gateway.
func TestWindowsHotConfigPrecommitConflictKeepsConcurrentConfigAndGateway(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	const next = "config_version: 9\nguardrail:\n  block_at: LOW\n"
	const concurrent = "config_version: 9\nguardrail:\n  block_at: HIGH\n"
	for _, bundle := range []bool{false, true} {
		name := "Setup"
		if bundle {
			name = "bundle"
		}
		t.Run(name, func(t *testing.T) {
			host, opts := newHotConfigHost(t, previous, next)
			recorded := []byte(`{"generation":3,"config_sha256":"` + configwrite.SHA256Hex([]byte(previous)) + `"}`)
			if err := os.WriteFile(configwrite.GenerationPath(host.configPath), recorded, 0o600); err != nil {
				t.Fatal(err)
			}
			writes, reloads := 0, 0
			windowsEnterpriseHotConfigWrite = func(ctx context.Context, path string, raw []byte, opt configwrite.Options) error {
				writes++
				if err := os.WriteFile(path, []byte(concurrent), 0o600); err != nil {
					return err
				}
				_, err := configwrite.ReplaceDocument(ctx, path, raw, opt)
				if !errors.Is(err, configwrite.ErrConflict) {
					t.Fatalf("writer error = %v, want its precommit conflict", err)
				}
				return fmt.Errorf("the installed config changed: %w", err)
			}
			windowsEnterpriseHotBundleReload = func(context.Context, managed.StandaloneLayout) error {
				reloads++
				return nil
			}
			if bundle {
				opts.bundle = host.bundleRun()
				originalDigest := windowsEnterprisePolicyDigest
				t.Cleanup(func() { windowsEnterprisePolicyDigest = originalDigest })
				windowsEnterprisePolicyDigest = host.digest
				result := newWindowsEnterpriseStandaloneResult("ensure", opts)
				applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
					&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
				if applied || !windowsBundleHasCode(result.Errors, "bundle_config_write_failed") ||
					!strings.Contains(fmt.Sprint(result.Errors), "retry") {
					t.Fatalf("applied=%t errors=%+v, want a bundle write conflict", applied, result.Errors)
				}
			} else {
				stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
				result := runHotConfigEnsure(t, host, opts, stub)
				if len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" || !result.OK {
					t.Fatalf("installer calls=%q result=%+v, want Setup transaction fallback", stub.calls, result)
				}
			}
			installed, err := os.ReadFile(host.configPath)
			if err != nil {
				t.Fatal(err)
			}
			generation, err := os.ReadFile(configwrite.GenerationPath(host.configPath))
			if err != nil {
				t.Fatal(err)
			}
			if string(installed) != concurrent || !bytes.Equal(generation, recorded) || writes != 1 || reloads != 0 ||
				host.stops != 0 || opts.hotConfigRestoreFailed {
				t.Fatalf("installed=%q generation=%q writes=%d reloads=%d stops=%d restoreFailed=%t",
					installed, generation, writes, reloads, host.stops, opts.hotConfigRestoreFailed)
			}
		})
	}
}

// The same error kind can occur on either side of the config publication.
// Only the postpublication rows may restore a config or reload a gateway.
func TestWindowsHotConfigWriteFailuresFollowPublicationPhase(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	const next = "config_version: 9\nguardrail:\n  block_at: LOW\n"
	for _, failure := range []struct {
		name string
		err  error
	}{
		{"conflict", configwrite.ErrConflict},
		{"lock busy", configwrite.ErrLockBusy},
		{"write", errors.New("write failed")},
		{"read", errors.New("read failed")},
		{"validation", errors.New("validation failed")},
		{"permission", os.ErrPermission},
	} {
		for _, published := range []bool{false, true} {
			for _, bundle := range []bool{false, true} {
				name := failure.name + "/before/Setup"
				if published {
					name = failure.name + "/after/Setup"
				}
				if bundle {
					name = strings.TrimSuffix(name, "Setup") + "bundle"
				}
				t.Run(name, func(t *testing.T) {
					host, opts := newHotConfigHost(t, previous, next)
					host.adopted = true
					if bundle {
						opts.bundle = host.bundleRun()
					}
					generation := []byte(`{"generation":3,"config_sha256":"` + configwrite.SHA256Hex([]byte(previous)) + `"}`)
					if err := os.WriteFile(configwrite.GenerationPath(host.configPath), generation, 0o600); err != nil {
						t.Fatal(err)
					}
					attempts, reloads := 0, 0
					write := windowsEnterpriseHotConfigWrite
					windowsEnterpriseHotConfigWrite = func(ctx context.Context, path string, raw []byte, opt configwrite.Options) error {
						attempts++
						if attempts == 1 {
							if !published {
								return failure.err
							}
							if err := write(ctx, path, raw, opt); err != nil {
								return err
							}
							return configwrite.AfterPublication(failure.err)
						}
						return write(ctx, path, raw, opt)
					}
					windowsEnterpriseHotBundleReload = func(context.Context, managed.StandaloneLayout) error {
						reloads++
						return nil
					}
					oldDigest := windowsEnterprisePolicyDigest
					t.Cleanup(func() { windowsEnterprisePolicyDigest = oldDigest })
					windowsEnterprisePolicyDigest = host.digest
					result := newWindowsEnterpriseStandaloneResult("ensure", opts)
					applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
						&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
					installed, readErr := os.ReadFile(host.configPath)
					if readErr != nil {
						t.Fatal(readErr)
					}
					afterGeneration, readErr := os.ReadFile(configwrite.GenerationPath(host.configPath))
					if readErr != nil {
						t.Fatal(readErr)
					}
					wantAttempts, wantReloads := 1, 0
					if published {
						wantAttempts, wantReloads = 2, 1
					}
					generationCorrect := bytes.Equal(afterGeneration, generation)
					if published {
						generationCorrect = !generationCorrect
					}
					if applied || string(installed) != previous || !generationCorrect ||
						attempts != wantAttempts || reloads != wantReloads || host.stops != 0 || opts.hotConfigRestoreFailed {
						t.Fatalf("applied=%t config=%q generation=%q writes=%d reloads=%d stops=%d restoreFailed=%t errors=%+v",
							applied, installed, afterGeneration, attempts, reloads, host.stops, opts.hotConfigRestoreFailed, result.Errors)
					}
				})
			}
		}
	}
}

// If the installed CLI disappears after the initial policy proof, undo can
// still prove the previous policy through the service's authenticated health.
// A gateway that already kept that policy continues running; one that loaded
// the candidate is restarted on the restored config.
func TestWindowsHotConfigUndoSurvivesInstalledCLILoss(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	const next = "config_version: 9\nguardrail:\n  block_at: LOW\n"
	for _, candidateLoaded := range []bool{false, true} {
		for _, bundle := range []bool{false, true} {
			name := fmt.Sprintf("candidate-loaded=%t/bundle=%t", candidateLoaded, bundle)
			t.Run(name, func(t *testing.T) {
				host, opts := newHotConfigHost(t, previous, next)
				if bundle {
					opts.bundle = host.bundleRun()
				}
				recorded := []byte(`{"generation":3,"config_sha256":"` + configwrite.SHA256Hex([]byte(previous)) + `"}`)
				if err := os.WriteFile(configwrite.GenerationPath(host.configPath), recorded, 0o600); err != nil {
					t.Fatal(err)
				}
				loadedCandidate := false
				write := windowsEnterpriseHotConfigWrite
				windowsEnterpriseHotConfigWrite = func(ctx context.Context, path string, raw []byte, opt configwrite.Options) error {
					if err := write(ctx, path, raw, opt); err != nil {
						return err
					}
					if bytes.Equal(raw, []byte(next)) {
						loadedCandidate = candidateLoaded
					}
					return nil
				}
				windowsEnterpriseHotConfigValidate = func(string, string, string, bool) (windowsServiceConfigValidation, error) {
					return windowsServiceConfigValidation{}, errors.New("postpublication validation failed")
				}
				proofCalls := 0
				oldDigest, oldHealth := windowsEnterprisePolicyDigest, windowsEnterpriseHotConfigGatewayPolicy
				t.Cleanup(func() {
					windowsEnterprisePolicyDigest, windowsEnterpriseHotConfigGatewayPolicy = oldDigest, oldHealth
				})
				windowsEnterprisePolicyDigest = func(ctx context.Context) ([]byte, error) {
					proofCalls++
					if proofCalls == 1 {
						return host.digest(ctx)
					}
					return nil, os.ErrNotExist
				}
				priorDigest := "sha256:" + strings.Repeat("a", 64)
				nextDigest := "sha256:" + strings.Repeat("b", 64)
				healthCalls := 0
				windowsEnterpriseHotConfigGatewayPolicy = func(context.Context, managed.StandaloneLayout) (gateway.PolicyHealth, error) {
					healthCalls++
					if loadedCandidate {
						return gateway.PolicyHealth{EffectiveDigest: nextDigest, BundleID: host.bundleID, BundleVersion: host.bundleVersion}, nil
					}
					return gateway.PolicyHealth{EffectiveDigest: priorDigest, BundleID: host.bundleID, BundleVersion: host.bundleVersion}, nil
				}
				reloads, restarts := 0, 0
				windowsEnterpriseHotBundleReload = func(context.Context, managed.StandaloneLayout) error {
					reloads++
					return os.ErrNotExist
				}
				windowsEnterpriseHotConfigRestart = func() (bool, error) {
					restarts++
					loadedCandidate = false
					return true, nil
				}
				result := newWindowsEnterpriseStandaloneResult("ensure", opts)
				applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
					&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
				installed, err := os.ReadFile(host.configPath)
				if err != nil {
					t.Fatal(err)
				}
				wantRestarts := 0
				if candidateLoaded {
					wantRestarts = 1
				}
				if applied || string(installed) != previous || reloads != 1 || restarts != wantRestarts ||
					healthCalls == 0 || host.stops != 0 || opts.hotConfigRestoreFailed || loadedCandidate {
					t.Fatalf("applied=%t config=%q reloads=%d restarts=%d healthCalls=%d stops=%d restoreFailed=%t candidateLive=%t errors=%+v",
						applied, installed, reloads, restarts, healthCalls, host.stops, opts.hotConfigRestoreFailed, loadedCandidate, result.Errors)
				}
			})
		}
	}
}

// The installed CLI is the authority used after publication to prove both
// adoption and undo. If it is absent, fails custody or execution, or cannot
// report the running policy, the hot path has no safe post-write proof.
func TestWindowsHotConfigRequiresInstalledPolicyProofBeforeWrite(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	const next = "config_version: 9\nguardrail:\n  block_at: LOW\n"
	for _, tc := range []struct {
		name  string
		probe func(context.Context) ([]byte, error)
	}{
		{"installed CLI missing", func(context.Context) ([]byte, error) { return nil, os.ErrNotExist }},
		{"installed CLI execution failed", func(context.Context) ([]byte, error) { return nil, errors.New("exit status 1") }},
		{"invalid report", func(context.Context) ([]byte, error) { return []byte("{"), nil }},
		{"incomplete report", func(context.Context) ([]byte, error) { return []byte(`{"effective_digest":"sha256:old"}`), nil }},
		{"gateway reports another policy", func(context.Context) ([]byte, error) {
			return []byte(`{"effective_digest":"sha256:old","gateway_reported_digest":"sha256:other"}`), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, opts := newHotConfigHost(t, previous, next)
			stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
			stub.install(t)
			windowsEnterprisePolicyDigest = func(ctx context.Context) ([]byte, error) {
				if len(stub.calls) == 2 {
					return host.digest(ctx)
				}
				return tc.probe(ctx)
			}
			windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "config", nil }
			command := &cobra.Command{}
			var stdout bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(&bytes.Buffer{})
			if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`); err != nil {
				t.Fatalf("Setup fallback: %v\n%s", err, stdout.String())
			}
			var result enterprisestatus.Result
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("decode result: %v: %s", err, stdout.String())
			}
			installed, err := os.ReadFile(host.configPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" || !result.OK ||
				string(installed) != previous || len(host.writes) != 0 || host.stops != 0 || opts.hotConfigRestoreFailed {
				t.Fatalf("installer calls=%q result=%+v installed=%q writes=%q stops=%d restoreFailed=%t",
					stub.calls, result, installed, host.writes, host.stops, opts.hotConfigRestoreFailed)
			}
		})
	}

	t.Run("installed CLI custody failure", func(t *testing.T) {
		host, opts := newHotConfigHost(t, previous, next)
		windowsEnterpriseInstalledCLICustody = func(string, string) error { return errors.New("CLI custody failed") }
		stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
		stub.install(t)
		windowsEnterprisePolicyDigest = func(ctx context.Context) ([]byte, error) {
			if len(stub.calls) == 2 {
				return host.digest(ctx)
			}
			_, err := windowsEnterprisePolicyDigestCommand(ctx)
			return nil, err
		}
		windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "config", nil }
		command := &cobra.Command{}
		var stdout bytes.Buffer
		command.SetOut(&stdout)
		command.SetErr(&bytes.Buffer{})
		if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`); err != nil {
			t.Fatalf("Setup fallback: %v\n%s", err, stdout.String())
		}
		installed, err := os.ReadFile(host.configPath)
		if err != nil {
			t.Fatal(err)
		}
		if len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" || string(installed) != previous ||
			len(host.writes) != 0 || host.stops != 0 || opts.hotConfigRestoreFailed {
			t.Fatalf("installer calls=%q installed=%q writes=%q stops=%d restoreFailed=%t",
				stub.calls, installed, host.writes, host.stops, opts.hotConfigRestoreFailed)
		}
	})

	t.Run("bundle refusal", func(t *testing.T) {
		host, opts := newHotConfigHost(t, previous, next)
		opts.bundle = host.bundleRun()
		// A guardian-recorded hand edit would be copied to rejected-config.yaml
		// if the hot path made any file changes before testing CLI availability.
		recorded := []byte(`{"generation":3,"config_sha256":"` + configwrite.SHA256Hex([]byte(previous)) +
			`","actor":"` + configwrite.ActorUnattributedHandEdit + `"}`)
		if err := os.WriteFile(configwrite.GenerationPath(host.configPath), recorded, 0o600); err != nil {
			t.Fatal(err)
		}
		originalDigest := windowsEnterprisePolicyDigest
		t.Cleanup(func() { windowsEnterprisePolicyDigest = originalDigest })
		windowsEnterprisePolicyDigest = func(context.Context) ([]byte, error) { return nil, os.ErrNotExist }
		result := newWindowsEnterpriseStandaloneResult("ensure", opts)
		applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
			&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
		installed, err := os.ReadFile(host.configPath)
		if err != nil {
			t.Fatal(err)
		}
		if applied || !windowsBundleHasCode(result.Errors, "bundle_hot_apply_unavailable") ||
			!strings.Contains(fmt.Sprint(result.Errors), "installed CLI") || string(installed) != previous ||
			len(host.writes) != 0 || host.stops != 0 || opts.hotConfigRestoreFailed {
			t.Fatalf("applied=%t errors=%+v installed=%q writes=%q stops=%d restoreFailed=%t",
				applied, result.Errors, installed, host.writes, host.stops, opts.hotConfigRestoreFailed)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(host.configPath), "rejected-config.yaml")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the unavailable CLI left rejected-config.yaml behind: %v", err)
		}
	})
}
