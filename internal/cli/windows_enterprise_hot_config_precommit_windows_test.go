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
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

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
