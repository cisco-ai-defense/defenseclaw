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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// An older delivery never writes over a newer bundle another run applied
// and no run has confirmed yet, kept through a gateway outage or carried
// through a product upgrade: a lower version, a repeat of the confirmed
// bundle and other content under the pending version are version_not_newer.
// The pending config, receipt and current bundle stay, and the next ensure
// confirms the pending bundle.
func TestAnOlderDeliveryDoesNotReplaceANewerPendingBundle(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, kept := range []string{"outage", "upgrade"} {
			for _, older := range []string{"lower version", "repeat of the confirmed bundle", "other content at the pending version"} {
				t.Run(goos+"/"+kept+"/"+older, func(t *testing.T) {
					b := newBundleHost(t, goos)
					if kept == "upgrade" {
						b.env.ProductVersion = "1.0.3"
						requireOK(t, b.run(Options{Action: ActionUpgrade, PayloadDir: b.payload("1.0.3")}))
					}
					v1, v2, _ := bundleConfigs(b.testHost)
					pathA := b.dir(1, v1)
					requireOK(t, b.apply(pathA))
					b.env.bundleFault = func(phase string) error {
						if phase == enterprisebundle.StateApplied {
							b.healthy = false
						}
						return nil
					}
					requireError(t, b.apply(b.dir(3, v2)), codeBundleNotConfirmed)
					b.env.bundleFault = nil
					b.healthy = true
					pending := b.receipt(bundleID(3))
					pendingConfig := b.read(b.env.Layout.ConfigPath)
					if pending.State != enterprisebundle.StateApplied {
						t.Fatalf("setup: receipt = %+v", pending)
					}
					if kept == "upgrade" {
						// The old gateway reports B's historical digest, so the
						// upgrade carries B pending.
						upgradeBundleHostDigest(b)
						b.frozen = pending.EffectivePolicyDigest
						requireOK(t, b.run(Options{Action: ActionUpgrade, PayloadDir: b.payload("1.0.4")}))
						if got := b.receipt(bundleID(3)); got.State != enterprisebundle.StateApplied {
							t.Fatalf("setup: the upgrade did not carry B pending: %+v", got)
						}
					}
					var path string
					switch older {
					case "lower version":
						path = b.dir(2, v1)
					case "repeat of the confirmed bundle":
						path = pathA
					default:
						path = b.dir(3, v1)
					}
					// The older run's first settle cannot prove B (outage, or the
					// gateway still on the historical digest); the gateway then
					// answers, so a run that went ahead would commit its config.
					original := b.env.HealthGet
					calls := 0
					b.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
						calls++
						if calls == 1 && kept == "outage" {
							return 0, nil, errors.New("connection refused")
						}
						if calls > 1 {
							b.frozen = ""
						}
						return original(ctx)
					}
					refused := b.apply(path)
					b.env.HealthGet = original
					b.frozen = ""
					requireError(t, refused, string(enterprisebundle.CodeVersionNotNewer))
					if !messagesContain(refused.Errors, bundleID(3)) {
						t.Fatalf("the refusal does not name the pending bundle: %+v", refused.Errors)
					}
					var kept3 *enterprisebundle.Receipt
					receipts, err := b.env.bundleStore().Receipts()
					if err != nil {
						t.Fatal(err)
					}
					for _, rc := range receipts {
						if rc.ReceiptID == pending.ReceiptID {
							kept3 = rc
						}
					}
					if kept3 == nil || kept3.State != enterprisebundle.StateApplied || kept3.RolledBack {
						t.Fatalf("the older delivery settled the pending receipt: %+v", kept3)
					}
					if b.read(b.env.Layout.ConfigPath) != pendingConfig || b.state().Current.BundleID != bundleID(1) {
						t.Fatalf("the older delivery replaced the pending bundle: state=%+v errors=%+v", b.state(), refused.Errors)
					}
					requireOK(t, b.run(Options{Action: ActionEnsure}))
					if b.state().Current.BundleID != bundleID(3) || b.read(b.env.Layout.ConfigPath) != pendingConfig {
						t.Fatalf("the pending bundle was not confirmed afterwards: state=%+v", b.state())
					}
				})
			}
		}
	}
}

func messagesContain(messages []enterprisestatus.Message, text string) bool {
	for _, m := range messages {
		if strings.Contains(m.Message, text) {
			return true
		}
	}
	return false
}

// A receipt records rolled_back only when the gateway enforces the last good
// bundle again, never because its config is back in the deployment
// (GAP-1100): a deferred re-settle whose gateway keeps the rejected policy,
// refuses the reload or reports a config error records rolled_back false
// and the digest the gateway enforces. The first settle of a run fails a
// disproved receipt before anything is put back, so it records false too.
func TestABundleRollbackIsRecordedOnlyWhenTheGatewayEnforcesIt(t *testing.T) {
	const disproved = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	for _, goos := range []string{"linux", "darwin"} {
		for _, gateway := range []string{"keeps the rejected policy", "refuses the reload", "config error"} {
			t.Run(goos+"/deferred/"+gateway, func(t *testing.T) {
				b := pendingBundleHost(t, goos, "1.0.3")
				before := b.receipt(bundleID(2))
				pendingConfig := b.read(b.env.Layout.ConfigPath)
				lastGood, _, err := b.env.currentBundleConfig(b.env.bundleStore())
				if err != nil || lastGood == nil {
					t.Fatalf("last good config: %v", err)
				}
				upgradeBundleHostDigest(b)
				unit := unitGateway
				if goos == "darwin" {
					unit = labelGateway
				}
				original := b.env.HealthGet
				callsBefore := len(b.services.calls)
				b.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
					restarted := false
					for _, call := range b.services.calls[callsBefore:] {
						restarted = restarted || call == "start "+unit || call == "restart "+unit
					}
					b.frozen, b.reloadError, b.configError = "", "", ""
					switch {
					case !restarted:
						b.frozen = before.EffectivePolicyDigest
					case b.read(b.env.Layout.ConfigPath) == pendingConfig || gateway == "keeps the rejected policy":
						b.frozen = disproved
					case gateway == "refuses the reload":
						b.frozen, b.reloadError = disproved, "rule pack refused"
					default:
						b.configError = "permission denied"
					}
					return original(ctx)
				}
				result := b.run(Options{Action: ActionUpgrade, PayloadDir: b.payload("1.0.4")})
				b.env.HealthGet = original
				got := b.receipt(bundleID(2))
				if got.State != enterprisebundle.StateFailed || got.RolledBack {
					t.Fatalf("receipt says rolled_back while the gateway does not enforce the last good bundle: %+v warnings=%+v", got, result.Warnings)
				}
				if gateway != "config error" && got.EnforcingDigest != disproved {
					t.Fatalf("enforcing digest %s, want what the gateway reports (%s)", got.EnforcingDigest, disproved)
				}
				if !hasMessageCode(result.Warnings, codeBundleUnconfirmed) || !messagesContain(result.Warnings, "does not enforce it") {
					t.Fatalf("the run does not say the last good bundle is not enforced: %+v", result.Warnings)
				}
				if b.read(b.env.Layout.ConfigPath) != string(lastGood) || b.state().Current.BundleID != bundleID(1) {
					t.Fatalf("the last good config is not installed: state=%+v", b.state())
				}
			})
		}
		t.Run(goos+"/first settle", func(t *testing.T) {
			b := pendingBundleHost(t, goos, "1.0.3")
			original := b.env.HealthGet
			calls := 0
			b.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
				calls++
				b.frozen = ""
				if calls == 1 {
					b.frozen = disproved
				}
				return original(ctx)
			}
			result := b.run(Options{Action: ActionEnsure})
			b.env.HealthGet = original
			got := b.receipt(bundleID(2))
			if got.State != enterprisebundle.StateFailed || got.RolledBack || got.EnforcingDigest != disproved {
				t.Fatalf("the first settle recorded a rollback nothing had done: %+v warnings=%+v", got, result.Warnings)
			}
		})
	}
}
