// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0271: a bundle apply that fails after it wrote config.yaml must leave
// the receipt, the bundle state, the installed config and the policy the
// gateway enforces in agreement. A failure before the commit restores the
// last good config and generation; a failure after the commit, once the
// gateway reported the bundle policy, confirms the bundle.

func setLifecycleTestFault(t *testing.T, h *testHost, stage string) {
	t.Helper()
	fault := filepath.Join(h.env.Layout.LifecycleDir, testFaultFileName)
	writeHostFile(t, h, fault, stage+"\n")
	if err := os.Chmod(h.env.P(fault), 0o600); err != nil {
		t.Fatal(err)
	}
	h.owners[h.env.P(fault)] = [2]int{0, 0}
}

func clearLifecycleTestFault(t *testing.T, h *testHost) {
	t.Helper()
	if err := os.Remove(h.env.P(filepath.Join(h.env.Layout.LifecycleDir, testFaultFileName))); err != nil {
		t.Fatal(err)
	}
}

// afterWriteCase is the host a case starts from: no bundle current (the
// first bundle, as on the GAP-0271 Mac) or bundle 1 current.
type afterWriteCase struct {
	goos   string
	second bool
}

func afterWriteCases() []afterWriteCase {
	var cases []afterWriteCase
	for _, goos := range []string{"linux", "darwin"} {
		cases = append(cases, afterWriteCase{goos, false}, afterWriteCase{goos, true})
	}
	return cases
}

func (c afterWriteCase) name() string {
	if c.second {
		return c.goos + "/second bundle"
	}
	return c.goos + "/first bundle"
}

// start prepares the host and returns the version and config of the bundle
// the case applies.
func (c afterWriteCase) start(t *testing.T) (*bundleHost, uint64, string) {
	b := newBundleHost(t, c.goos)
	v1, v2, _ := bundleConfigs(b.testHost)
	if !c.second {
		return b, 1, v2
	}
	b.mapPromotedBundleOwners(1)
	requireOK(t, b.apply(b.dir(1, v1)))
	return b, 2, v2
}

func requireNoError(t *testing.T, r *enterprisestatus.Result, code string) {
	t.Helper()
	for _, e := range r.Errors {
		if e.Code == code {
			t.Fatalf("unexpected %s error: %s", code, e.Message)
		}
	}
}

func countErrors(r *enterprisestatus.Result, code string) int {
	n := 0
	for _, e := range r.Errors {
		if e.Code == code {
			n++
		}
	}
	return n
}

func TestBundleFailureAfterConfigWriteRestoresLastGoodPolicy(t *testing.T) {
	for _, c := range afterWriteCases() {
		t.Run(c.name(), func(t *testing.T) {
			b, version, cfg := c.start(t)
			good := b.read(b.env.Layout.ConfigPath)
			goodDigest, _ := installedPolicy(b)
			before := b.state()
			setLifecycleTestFault(t, b.testHost, testFaultAfterServices)
			b.mapPromotedBundleOwners(version)
			path := b.dir(version, cfg)
			r := b.apply(path)
			requireError(t, r, codeLifecycleTestFault)
			requireError(t, r, string(enterprisebundle.CodeApplyFailed))
			rc := b.receipt(bundleID(version))
			if rc.State != enterprisebundle.StateFailed || !rc.RolledBack || rc.EnforcingDigest != goodDigest {
				t.Fatalf("receipt = %+v, want failed, rolled back, enforcing %s", rc, goodDigest)
			}
			if b.read(b.env.Layout.ConfigPath) != good {
				t.Fatal("config.yaml is not the last good config after the failed apply")
			}
			if digest, _ := installedPolicy(b); digest != goodDigest {
				t.Fatalf("gateway policy = %s, want the last good %s", digest, goodDigest)
			}
			st := b.state()
			if (st.Current == nil) != (before.Current == nil) || (st.Current != nil && st.Current.BundleID != before.Current.BundleID) {
				t.Fatalf("bundle state = %+v, want current %+v", st, before.Current)
			}
			gen, err := configwrite.ReadGenerationState(b.env.P(b.env.Layout.ConfigPath))
			if err != nil || gen.ConfigSHA256 != sha256Bytes([]byte(good)) {
				t.Fatalf("generation record = %+v (%v), want the restored config", gen, err)
			}
			wantBundle := ""
			if before.Current != nil {
				wantBundle = before.Current.BundleID
			}
			if gen.BundleID != wantBundle {
				t.Fatalf("generation names bundle %q, want %q", gen.BundleID, wantBundle)
			}
			if r.Bundle == nil || r.Bundle.State != enterprisebundle.StateFailed {
				t.Fatalf("result bundle block = %+v", r.Bundle)
			}
			clearLifecycleTestFault(t, b.testHost)
			b.mapPromotedBundleOwners(version)
			requireOK(t, b.apply(path))
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(version) {
				t.Fatalf("retry: state = %+v", st)
			}
		})
	}
}

func TestBundleFailureAfterCommitConfirmsTheBundleInForce(t *testing.T) {
	for _, c := range afterWriteCases() {
		t.Run(c.name(), func(t *testing.T) {
			b, version, cfg := c.start(t)
			setLifecycleTestFault(t, b.testHost, testFaultAfterCommit)
			b.mapPromotedBundleOwners(version)
			r := b.apply(b.dir(version, cfg))
			requireError(t, r, codeLifecycleTestFault)
			requireNoError(t, r, string(enterprisebundle.CodeApplyFailed))
			requireNoError(t, r, codeBundleNotConfirmed)
			if !hasWarning(r, codeBundleConfirmedWithErrors) {
				t.Fatalf("no %s warning: %+v", codeBundleConfirmedWithErrors, r.Warnings)
			}
			rc := b.receipt(bundleID(version))
			digest, generation := installedPolicy(b)
			if rc.State != enterprisebundle.StateConfirmed || rc.EffectivePolicyDigest != digest || rc.ConfigGeneration != generation {
				t.Fatalf("receipt = %+v, want confirmed at the enforced %s generation %d", rc, digest, generation)
			}
			if sha := sha256Bytes([]byte(b.read(b.env.Layout.ConfigPath))); sha != rc.ConfigSHA256 {
				t.Fatalf("installed config %s is not the confirmed bundle config %s", sha, rc.ConfigSHA256)
			}
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(version) || st.Current.EffectivePolicyDigest != digest {
				t.Fatalf("bundle state = %+v, want current bundle %d enforcing %s", st, version, digest)
			}
			gen, err := configwrite.ReadGenerationState(b.env.P(b.env.Layout.ConfigPath))
			if err != nil || gen.BundleID != bundleID(version) || gen.BundleVersion != version {
				t.Fatalf("generation record = %+v (%v), want bundle %d", gen, err, version)
			}
			if r.Bundle == nil || r.Bundle.State != enterprisebundle.StateConfirmed || r.Bundle.BundleID != bundleID(version) {
				t.Fatalf("result bundle block = %+v", r.Bundle)
			}
			clearLifecycleTestFault(t, b.testHost)
			requireOK(t, b.run(Options{Action: ActionEnsure}))
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(version) {
				t.Fatalf("next ensure: state = %+v", st)
			}
		})
	}
}

// A gateway that stops reporting the bundle policy after the commit (and a
// failed later step) leaves the receipt applied, never failed with "the last
// good policy keeps enforcing" over the installed bundle config; the next
// run confirms it once the gateway reports it.
func TestBundleCommittedButUnreportedAfterFailureStaysApplied(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b, version, cfg := afterWriteCase{goos, true}.start(t)
			good := b.read(b.env.Layout.ConfigPath)
			goodSHA := sha256Bytes([]byte(good))
			goodDigest, _ := installedPolicy(b)
			stale := true
			health := b.env.HealthGet
			b.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
				b.frozen = ""
				if record, err := b.env.loadDeployment(); stale && err == nil && record != nil && record.ConfigSHA256 != goodSHA {
					b.frozen = goodDigest
				}
				return health(ctx)
			}
			setLifecycleTestFault(t, b.testHost, testFaultAfterCommit)
			b.mapPromotedBundleOwners(version)
			r := b.apply(b.dir(version, cfg))
			requireError(t, r, codeLifecycleTestFault)
			// The gateway reports the last good digest, not the bundle's.
			requireError(t, r, string(enterprisebundle.CodeDigestMismatch))
			requireNoError(t, r, string(enterprisebundle.CodeApplyFailed))
			if n := countErrors(r, string(enterprisebundle.CodeDigestMismatch)); n != 1 {
				t.Fatalf("%d digest_mismatch errors, want one: %+v", n, r.Errors)
			}
			rc := b.receipt(bundleID(version))
			if rc.State != enterprisebundle.StateApplied {
				t.Fatalf("receipt = %+v, want applied (not yet confirmed, not failed)", rc)
			}
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(1) {
				t.Fatalf("bundle state = %+v, want bundle 1 still current", st)
			}
			stale = false
			clearLifecycleTestFault(t, b.testHost)
			r = b.run(Options{Action: ActionEnsure})
			requireOK(t, r)
			if !hasWarning(r, codeBundleConfirmedLate) {
				t.Fatalf("no %s warning: %+v", codeBundleConfirmedLate, r.Warnings)
			}
			rc = b.receipt(bundleID(version))
			digest, _ := installedPolicy(b)
			if st := b.state(); rc.State != enterprisebundle.StateConfirmed || st.Current == nil || st.Current.BundleID != bundleID(version) || rc.EffectivePolicyDigest != digest {
				t.Fatalf("next run: receipt = %+v, state = %+v, gateway %s", rc, st, digest)
			}
		})
	}
}

// The after_commit stage of the test fault file fails a plain ensure after
// its deployment committed: nothing is rolled back.
func TestLifecycleTestFaultAfterCommitKeepsTheDeployment(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	setLifecycleTestFault(t, h, testFaultAfterCommit)
	r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
	requireError(t, r, codeLifecycleTestFault)
	if hasWarning(r, codeRolledBack) {
		t.Fatalf("a failure after the commit rolled back: %+v", r.Warnings)
	}
	if got := h.read(filepath.Join(h.env.Layout.BinDir, binGateway)); got != fmt.Sprintf("defenseclaw-gateway %s\n", "2.0.0") {
		t.Fatalf("the committed gateway is not installed: %q", got)
	}
}
