// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	launchdstandalone "github.com/defenseclaw/defenseclaw/packaging/launchd-standalone"
)

// On Linux a bundle the gateway did not confirm is settled by a deferred
// start of the apply service: the transaction stopped the path unit while it
// wrote config.yaml, so that write never starts it. macOS needs none (its
// apply LaunchDaemon watches config.yaml).
func TestBundleNotConfirmedSchedulesTheSettleOnLinux(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, _ := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			b.env.bundleFault = func(phase string) error {
				if phase == enterprisebundle.StateApplied {
					b.healthy = false
				}
				return nil
			}
			before := len(b.runner.calls)
			r := b.apply(b.dir(2, v2))
			b.env.bundleFault = nil
			requireError(t, r, codeBundleNotConfirmed)
			var scheduled []string
			for _, call := range b.runner.calls[before:] {
				if strings.HasPrefix(call, "systemd-run ") && strings.HasSuffix(call, " systemctl start --no-block "+unitApplyService) {
					scheduled = append(scheduled, call)
				}
			}
			if goos == "darwin" {
				if len(scheduled) != 0 || settleWarning(r) {
					t.Fatalf("darwin scheduled a settle: %v %+v", scheduled, r.Warnings)
				}
				return
			}
			if len(scheduled) != 1 || !settleWarning(r) {
				t.Fatalf("linux: want one deferred apply start and its warning, got %v %+v", scheduled, r.Warnings)
			}
		})
	}
}

// A package postinstall and an explicit payload upgrade must both get past
// settlement while the old gateway still reports the bundle digest it knew.
// The gateway begins reporting the new build's digest only after restart.
func TestPendingBundleDoesNotBlockProductUpgrade(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, sourceVersion := range []string{"0.8.10", "1.0.0", "1.0.1", "1.0.2", "1.0.3"} {
			for _, channel := range []string{"package", "payload"} {
				t.Run(goos+"/"+sourceVersion+"/"+channel, func(t *testing.T) {
					b := pendingBundleHost(t, goos, sourceVersion)
					before := b.receipt(bundleID(2))
					installed := b.read(b.env.Layout.ConfigPath)
					upgradeBundleHostDigest(b)
					b.frozen = before.EffectivePolicyDigest
					gateway := unitGateway
					if goos == "darwin" {
						gateway = labelGateway
					}
					originalHealth := b.env.HealthGet
					callsBefore := len(b.services.calls)
					b.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
						for _, call := range b.services.calls[callsBefore:] {
							if call == "start "+gateway || call == "restart "+gateway {
								b.frozen = ""
							}
						}
						return originalHealth(ctx)
					}
					options := Options{Action: ActionUpgrade, PayloadDir: b.payload("1.0.4")}
					if channel == "package" {
						if goos == "linux" {
							stagePackage(t, b.testHost, "1.0.4")
						} else {
							stageDarwinBundlePackage(t, b, "1.0.4")
						}
						options = Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}
					}
					result := b.run(options)
					requireOK(t, result)
					if hasWarning(result, enterprisebundle.WarnBundlePending) || result.Bundle == nil || result.Bundle.State != enterprisebundle.StateConfirmed {
						t.Fatalf("successful upgrade still reports a pending receipt: bundle=%+v warnings=%+v", result.Bundle, result.Warnings)
					}
					if result.InstalledVersion != "1.0.4" || b.frozen != "" {
						t.Fatalf("upgrade did not restart the new gateway: version=%s frozen=%q", result.InstalledVersion, b.frozen)
					}
					if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateConfirmed || got.RolledBack ||
						got.EffectivePolicyDigest != before.EffectivePolicyDigest || b.state().Current.BundleID != bundleID(2) ||
						b.read(b.env.Layout.ConfigPath) != installed {
						t.Fatalf("upgrade changed or failed the carried bundle: receipt=%+v state=%+v", got, b.state())
					}
				})
			}
		}
	}
}

func stageDarwinBundlePackage(t *testing.T, b *bundleHost, version string) {
	t.Helper()
	staged := b.payload(version)
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := b.env.copyFileAtomic(filepath.Join(staged, name), b.env.P(filepath.Join(b.env.Layout.BinDir, name)), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
	for _, unit := range b.services.Units() {
		data, err := launchdstandalone.ReadPlist(unit.Name)
		if err != nil {
			t.Fatal(err)
		}
		writeHostFile(t, b.testHost, b.services.DefinitionPath(unit, ChannelPackage), string(data))
	}
}

// Repair is the way back from a stopped gateway and a damaged hook binary.
// An applied receipt cannot prevent repair from restarting that gateway.
func TestPendingBundleDoesNotBlockGatewayRepair(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := pendingBundleHost(t, goos, "1.0.3")
			installed := b.read(b.env.Layout.ConfigPath)
			hookPath := b.env.P(filepath.Join(b.env.Layout.BinDir, binHook))
			hook, err := os.ReadFile(hookPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(hookPath, []byte("damaged hook binary"), 0o755); err != nil {
				t.Fatal(err)
			}
			gateway := unitGateway
			if goos == "darwin" {
				gateway = labelGateway
			}
			for _, unit := range b.services.Units() {
				if unit.Name == gateway {
					if err := b.services.Stop(context.Background(), unit); err != nil {
						t.Fatal(err)
					}
				}
			}
			repair := b.run(Options{Action: ActionRepair})
			requireOK(t, repair)
			if hasWarning(repair, enterprisebundle.WarnBundlePending) || repair.Bundle == nil || repair.Bundle.State != enterprisebundle.StateConfirmed {
				t.Fatalf("repair still reports a pending receipt: bundle=%+v warnings=%+v", repair.Bundle, repair.Warnings)
			}
			restoredHook, err := os.ReadFile(hookPath)
			if err != nil {
				t.Fatal(err)
			}
			if !b.services.isActive(gateway) || b.read(b.env.Layout.ConfigPath) != installed || string(restoredHook) != string(hook) {
				t.Fatal("repair did not restore the gateway while retaining the applied bundle")
			}
			if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateConfirmed || got.RolledBack || b.state().Current.BundleID != bundleID(2) {
				t.Fatalf("repair did not settle the enforced receipt: receipt=%+v state=%+v", got, b.state())
			}
		})
	}
}

// Losing trust anchors while a receipt is applied leaves that receipt open.
// Lifecycle work can still repair or upgrade the host, but an unsigned
// --config must not become a way to replace the pending signed policy.
func TestPendingBundleWithMissingAnchorsKeepsSignedConfig(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := pendingBundleHost(t, goos, "1.0.3")
			installed := b.read(b.env.Layout.ConfigPath)
			anchorPath := b.env.bundleAnchorsPath()
			anchors, err := os.ReadFile(anchorPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(anchorPath); err != nil {
				t.Fatal(err)
			}
			v1, _, _ := bundleConfigs(b.testHost)
			requireError(t, b.run(Options{Action: ActionEnsure, ConfigFile: writeTempConfig(t, []byte(v1))}), codeBundleRequired)
			ensure := b.run(Options{Action: ActionEnsure})
			requireOK(t, ensure)
			if !hasWarning(ensure, enterprisebundle.WarnBundlePending) {
				t.Fatalf("missing anchors were not reported as pending: %+v", ensure.Warnings)
			}
			if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateApplied || b.read(b.env.Layout.ConfigPath) != installed {
				t.Fatalf("ensure replaced the pending signed policy: %+v", got)
			}
			b.env.ProductVersion = "1.0.4"
			requireOK(t, b.run(Options{Action: ActionUpgrade, PayloadDir: b.payload("1.0.4")}))
			if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateApplied || got.RolledBack || b.read(b.env.Layout.ConfigPath) != installed {
				t.Fatalf("upgrade confirmed without anchors or replaced the policy: %+v", got)
			}
			writeRooted(t, anchorPath, string(anchors))
			requireOK(t, b.run(Options{Action: ActionEnsure}))
			if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateConfirmed || b.state().Current.BundleID != bundleID(2) {
				t.Fatalf("restored anchors did not allow confirmation: receipt=%+v state=%+v", got, b.state())
			}
		})
	}
}

func pendingBundleHost(t *testing.T, goos, sourceVersion string) *bundleHost {
	t.Helper()
	b := newBundleHost(t, goos)
	b.env.ProductVersion = sourceVersion
	requireOK(t, b.run(Options{Action: ActionUpgrade, PayloadDir: b.payload(sourceVersion), AllowDowngrade: sourceVersion == "0.8.10"}))
	v1, v2, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	b.env.bundleFault = func(phase string) error {
		if phase == enterprisebundle.StateApplied {
			b.healthy = false
		}
		return nil
	}
	requireError(t, b.apply(b.dir(2, v2)), codeBundleNotConfirmed)
	b.env.bundleFault = nil
	b.healthy = true
	if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateApplied || b.state().Current.BundleID != bundleID(1) {
		t.Fatalf("setup did not leave an applied, unconfirmed receipt: %+v", got)
	}
	return b
}

func settleWarning(r *enterprisestatus.Result) bool {
	for _, w := range r.Warnings {
		if w.Code == codeInputChanged && strings.Contains(w.Message, "applied but the gateway has not confirmed it") {
			return true
		}
	}
	return false
}

// A carried applied receipt stays pending through an outage, then confirms
// from the upgraded gateway's digest of its verified stored bundle. The
// receipt keeps the digest recorded by the old build.
func TestBundleSettleAfterProductUpgradeKeepsAnEnforcedReceipt(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, sourceVersion := range []string{"1.0.2", "1.0.3"} {
			t.Run(goos+"/"+sourceVersion, func(t *testing.T) {
				b := newBundleHost(t, goos)
				b.env.ProductVersion = sourceVersion
				requireOK(t, b.run(Options{Action: ActionUpgrade, PayloadDir: b.payload(sourceVersion)}))
				v1, v2, _ := bundleConfigs(b.testHost)
				requireOK(t, b.apply(b.dir(1, v1)))
				b.env.bundleFault = func(phase string) error {
					if phase == enterprisebundle.StateApplied {
						b.healthy = false
					}
					return nil
				}
				requireError(t, b.apply(b.dir(2, v2)), codeBundleNotConfirmed)
				b.env.bundleFault = nil
				before := b.receipt(bundleID(2))
				installed := b.read(b.env.Layout.ConfigPath)
				if before.State != enterprisebundle.StateApplied || before.EffectivePolicyDigest == "" || b.state().Current.BundleID != bundleID(1) {
					t.Fatalf("outage did not leave B applied and A current: receipt=%+v state=%+v", before, b.state())
				}
				upgradeBundleHostDigest(b)
				requireError(t, b.run(Options{Action: ActionEnsure}), codeActivate)
				if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateApplied ||
					b.read(b.env.Layout.ConfigPath) != installed || b.state().Current.BundleID != bundleID(1) {
					t.Fatalf("an outage after upgrade undid the applied bundle: receipt=%+v state=%+v", got, b.state())
				}
				b.healthy = true
				b.frozen = before.EffectivePolicyDigest
				requireOK(t, b.run(Options{Action: ActionEnsure}))
				if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateApplied ||
					b.read(b.env.Layout.ConfigPath) != installed {
					t.Fatalf("the older gateway still enforces the pending bundle: receipt=%+v", got)
				}
				b.frozen = ""
				requireOK(t, b.run(Options{Action: ActionEnsure}))
				if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateConfirmed ||
					got.EffectivePolicyDigest != before.EffectivePolicyDigest || b.state().Current.BundleID != bundleID(2) ||
					b.read(b.env.Layout.ConfigPath) != installed {
					t.Fatalf("the upgraded gateway did not confirm the historical receipt: receipt=%+v state=%+v", got, b.state())
				}
			})
		}
	}
}
