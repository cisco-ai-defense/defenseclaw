// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
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

// Losing trust anchors while a receipt is applied leaves that receipt open
// with its reason. Lifecycle work still repairs or upgrades the host with
// the pending signed config, and the receipt confirms once anchors return.
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
			ensure := b.run(Options{Action: ActionEnsure})
			requireOK(t, ensure)
			if !hasPendingReason(ensure, "trust anchors are unavailable") {
				t.Fatalf("missing anchors were not reported as pending with their reason: %+v", ensure.Warnings)
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

// Without trust anchors the device is not in bundle mode: the base config
// an administrator delivers with --config (the management contract's anchor
// removal after a failed first apply) is applied, never refused because a
// receipt is pending. The receipt it replaced is failed with a truthful
// message: no transaction was rolled back.
func TestPendingBundleWithMissingAnchorsTakesTheDeliveredConfig(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, action := range []string{ActionEnsure, ActionRepair} {
			t.Run(goos+"/"+action, func(t *testing.T) {
				b := pendingBundleHost(t, goos, "1.0.3")
				if err := os.Remove(b.env.bundleAnchorsPath()); err != nil {
					t.Fatal(err)
				}
				base := append(DefaultConfig(b.env.Layout), []byte("# base config\n")...)
				result := b.run(Options{Action: action, ConfigFile: writeTempConfig(t, base)})
				requireOK(t, result)
				if b.read(b.env.Layout.ConfigPath) != string(base) {
					t.Fatalf("the delivered config was not applied without anchors")
				}
				got := b.receipt(bundleID(2))
				if got.State != enterprisebundle.StateFailed || !got.RolledBack || strings.Contains(got.ErrorMessage, "the transaction was rolled back") {
					t.Fatalf("replaced receipt = %+v", got)
				}
				if hasWarning(result, enterprisebundle.WarnBundlePending) {
					t.Fatalf("a replaced receipt is still reported pending: %+v", result.Warnings)
				}
			})
		}
	}
}

// The re-settle after an upgrade checks the carried receipt against the new
// gateway. When that gateway proves another policy, the run installs the
// last good bundle again before the receipt says rolled_back.
func TestDeferredResettleRestoresLastGoodBundle(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, sourceVersion := range []string{"1.0.2", "1.0.3"} {
			for _, channel := range []string{"package", "payload"} {
				t.Run(goos+"/"+sourceVersion+"/"+channel, func(t *testing.T) {
					b := pendingBundleHost(t, goos, sourceVersion)
					before := b.receipt(bundleID(2))
					pendingConfig := b.read(b.env.Layout.ConfigPath)
					lastGood, _, err := b.env.currentBundleConfig(b.env.bundleStore())
					if err != nil || lastGood == nil || string(lastGood) == pendingConfig {
						t.Fatalf("last good config: %v", err)
					}
					upgradeBundleHostDigest(b)
					gateway := unitGateway
					if goos == "darwin" {
						gateway = labelGateway
					}
					// The old gateway reports the historical digest; once
					// restarted on 1.0.4 it enforces another policy for the
					// pending config and the real one for any other config.
					const disproved = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
					originalHealth := b.env.HealthGet
					callsBefore := len(b.services.calls)
					b.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
						restarted := false
						for _, call := range b.services.calls[callsBefore:] {
							restarted = restarted || call == "start "+gateway || call == "restart "+gateway
						}
						switch {
						case !restarted:
							b.frozen = before.EffectivePolicyDigest
						case b.read(b.env.Layout.ConfigPath) == pendingConfig:
							b.frozen = disproved
						default:
							b.frozen = ""
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
					if result.InstalledVersion != "1.0.4" {
						t.Fatalf("upgrade did not finish: %s", result.InstalledVersion)
					}
					got := b.receipt(bundleID(2))
					if got.State != enterprisebundle.StateFailed || !got.RolledBack {
						t.Fatalf("disproved receipt = %+v", got)
					}
					if b.read(b.env.Layout.ConfigPath) != string(lastGood) || b.state().Current.BundleID != bundleID(1) {
						t.Fatalf("receipt says rolled_back but the last good bundle is not installed: receipt=%+v state=%+v", got, b.state())
					}
					if want, _ := installedPolicy(b); got.EnforcingDigest != want {
						t.Fatalf("enforcing digest %s, want the last good bundle's %s", got.EnforcingDigest, want)
					}
					if hasWarning(result, enterprisebundle.WarnBundlePending) {
						t.Fatalf("a disproved receipt is still reported pending: %+v", result.Warnings)
					}
				})
			}
		}
	}
}

func hasPendingReason(r *enterprisestatus.Result, reason string) bool {
	for _, w := range r.Warnings {
		if w.Code == enterprisebundle.WarnBundlePending && strings.Contains(w.Message, reason) {
			return true
		}
	}
	return false
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

// An apply run of the previous binary that waited through an upgrade must
// not settle the receipt the upgrade carried: the digest it computes for the
// stored bundle is the old build's, while the upgraded gateway reports the
// new build's. A superseded run stands down without settling (with the
// gateway up, and after an outage at its first settle, when the deferred
// re-settle would install the last good bundle). Any other run of an older
// binary keeps the receipt pending. The installed binary confirms it.
func TestAnOlderBinaryDoesNotSettleAnUpgradedPendingBundle(t *testing.T) {
	type variant struct {
		name    string
		options Options
		outage  bool
	}
	variants := []variant{
		{"superseded", Options{Action: ActionEnsure, Reason: "path"}, false},
		{"superseded-after-outage", Options{Action: ActionEnsure, Reason: "path"}, true},
		{"ensure", Options{Action: ActionEnsure}, false},
		{"ensure-after-outage", Options{Action: ActionEnsure}, true},
		{"repair-after-outage", Options{Action: ActionRepair}, true},
	}
	for _, goos := range []string{"linux", "darwin"} {
		for _, v := range variants {
			t.Run(goos+"/"+v.name, func(t *testing.T) {
				b := pendingBundleHost(t, goos, "1.0.3")
				before := b.receipt(bundleID(2))
				pendingConfig := b.read(b.env.Layout.ConfigPath)
				oldDigester := b.env.BundleDigester
				// The upgrade keeps B pending: the gateway reports B's
				// historical digest throughout.
				upgradeBundleHostDigest(b)
				newDigester := b.env.BundleDigester
				b.frozen = before.EffectivePolicyDigest
				upgrade := b.run(Options{Action: ActionUpgrade, PayloadDir: b.payload("1.0.4")})
				requireOK(t, upgrade)
				if upgrade.InstalledVersion != "1.0.4" || b.receipt(bundleID(2)).State != enterprisebundle.StateApplied {
					t.Fatalf("setup: the upgrade did not keep B pending: version=%s receipt=%+v", upgrade.InstalledVersion, b.receipt(bundleID(2)))
				}
				// The upgraded gateway now reports B's 1.0.4 digest; the run
				// is the 1.0.3 binary, which computes B's 1.0.3 digest.
				b.frozen = ""
				b.env.ProductVersion, b.env.BundleDigester = "1.0.3", oldDigester
				originalHealth := b.env.HealthGet
				calls := 0
				b.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
					calls++
					if v.outage && calls == 1 {
						return 0, nil, errors.New("connection refused")
					}
					return originalHealth(ctx)
				}
				result := b.run(v.options)
				b.env.HealthGet = originalHealth
				if v.options.Reason == "path" && result.NoopReason != "superseded" {
					t.Fatalf("the older apply run did not stand down: warnings=%+v errors=%+v changes=%+v", result.Warnings, result.Errors, result.Changes)
				}
				got := b.receipt(bundleID(2))
				if got.State != enterprisebundle.StateApplied || got.RolledBack {
					t.Fatalf("the older binary settled the upgraded receipt: receipt=%+v warnings=%+v", got, result.Warnings)
				}
				if b.read(b.env.Layout.ConfigPath) != pendingConfig || b.state().Current.BundleID != bundleID(1) {
					t.Fatalf("the older binary replaced the pending bundle: state=%+v warnings=%+v", b.state(), result.Warnings)
				}
				if v.options.Reason != "path" && !hasPendingReason(result, "older than the installed deployment") {
					t.Fatalf("the older binary did not say why the receipt stays pending: %+v", result.Warnings)
				}
				// The installed binary settles it.
				b.env.ProductVersion, b.env.BundleDigester = "1.0.4", newDigester
				requireOK(t, b.run(Options{Action: ActionEnsure}))
				if got := b.receipt(bundleID(2)); got.State != enterprisebundle.StateConfirmed || b.state().Current.BundleID != bundleID(2) ||
					b.read(b.env.Layout.ConfigPath) != pendingConfig {
					t.Fatalf("the installed binary did not confirm the receipt: receipt=%+v state=%+v", got, b.state())
				}
			})
		}
	}
}
