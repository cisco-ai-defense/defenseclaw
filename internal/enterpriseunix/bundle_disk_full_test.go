// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0609: a bundle apply on a full state volume reported
// bundle_state_unreadable ("cannot write the policy bundle receipt ...: no
// space left on device"), a read problem, for a write that failed. Every
// bundle-state write that fails for lack of space is disk_full, with the
// write cause and the next step; the last good policy keeps enforcing.
func TestBundleStateWriteOnAFullVolumeIsDiskFull(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	enospc := &fs.PathError{Op: "mkdir", Path: "/var/lib/defenseclaw-enterprise/receipts", Err: syscall.ENOSPC}
	b.env.bundleFault = func(phase string) error {
		if phase == "private-dir receipts" {
			return enospc
		}
		return nil
	}
	r := b.apply(b.dir(1, v1))
	b.env.bundleFault = nil
	if r.OK || len(r.Errors) == 0 || r.Errors[0].Code != codeDiskFull || hasMessageCode(r.Errors, codeBundleStateUnreadable) {
		t.Fatalf("receipt write on a full volume: ok %v, errors %+v; want disk_full first, no %s", r.OK, r.Errors, codeBundleStateUnreadable)
	}
	for _, want := range []string{"cannot write the policy bundle receipt", "no space left on device", "free space on that filesystem"} {
		if !strings.Contains(r.Errors[0].Message, want) {
			t.Fatalf("disk_full message %q lacks %q", r.Errors[0].Message, want)
		}
	}

	// A step after the receipt that fails for lack of space fails the
	// receipt as disk_full, not apply_failed.
	b.mapPromotedBundleOwners(1)
	requireOK(t, b.apply(b.dir(1, v1)))
	b.env.bundleFault = func(phase string) error {
		if phase == enterprisebundle.StateStaged {
			return fmt.Errorf("promote: %w", enospc)
		}
		return nil
	}
	r = b.apply(b.dir(2, v2))
	b.env.bundleFault = nil
	if r.OK || !hasMessageCode(r.Errors, string(enterprisebundle.CodeDiskFull)) || hasMessageCode(r.Errors, string(enterprisebundle.CodeApplyFailed)) {
		t.Fatalf("staged step on a full volume: ok %v, errors %+v; want disk_full", r.OK, r.Errors)
	}
	if rc := b.receipt(bundleID(2)); rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeDiskFull {
		t.Fatalf("failed receipt = %s %s, want failed disk_full", rc.State, rc.ErrorCode)
	}

	// A state record the run could not write is a disk_full warning too;
	// any other write failure keeps its code.
	if got := stateWriteCode(fmt.Errorf("stage policy-state.json: %w", enospc), codeState); got != codeDiskFull {
		t.Fatalf("stateWriteCode(ENOSPC) = %s", got)
	}
	if got := stateWriteCode(errors.New("permission denied"), codeState); got != codeState {
		t.Fatalf("stateWriteCode(EACCES) = %s", got)
	}

	// The receipt of a lower inbox version a run superseded is a
	// bundle-state write too.
	b.env.bundleFault = func(phase string) error {
		if phase == "private-dir receipts" {
			return enospc
		}
		return nil
	}
	l := &lifecycle{env: b.env, result: &enterprisestatus.Result{}, inboxSuperseded: []supersededInbox{{bundleID: bundleID(3), version: 3}}}
	l.recordSupersededInbox(b.env.bundleStore())
	b.env.bundleFault = nil
	if len(l.result.Warnings) != 1 || l.result.Warnings[0].Code != codeDiskFull ||
		!strings.Contains(l.result.Warnings[0].Message, "free space on that filesystem") {
		t.Fatalf("superseded inbox receipt on a full volume: warnings %+v; want one disk_full", l.result.Warnings)
	}

	// Settling a bundle an earlier run received but did not apply writes
	// its failed receipt.
	if _, err := b.env.bundleStore().Receive(bundleID(4), 4, ""); err != nil {
		t.Fatal(err)
	}
	b.env.bundleFault = func(phase string) error {
		if phase == "private-dir receipts" {
			return enospc
		}
		return nil
	}
	l = &lifecycle{env: b.env, result: &enterprisestatus.Result{}}
	l.settleBundles(context.Background(), nil)
	b.env.bundleFault = nil
	if !hasMessageCode(l.result.Warnings, codeDiskFull) || hasMessageCode(l.result.Warnings, codeBundleStateUnreadable) {
		t.Fatalf("settle on a full volume: warnings %+v; want disk_full, no %s", l.result.Warnings, codeBundleStateUnreadable)
	}
}

// GAP-0609: a trust anchor install whose file write runs out of space is
// disk_full with the next step, and records a failed anchor install with
// that code, not state_invalid.
func TestBundleAnchorsWriteOnAFullVolumeIsDiskFull(t *testing.T) {
	b, dest := newAnchorsHost(t)
	before := readFile(t, dest)
	src, base := agentAnchors(t, anchorsDoc(t, b, "k1:active", "k2:active"))
	b.env.Trust = modeTrust(base, b.env.Root)
	b.env.bundleFault = func(phase string) error {
		if phase == "anchors-write" {
			return &fs.PathError{Op: "write", Path: dest, Err: syscall.ENOSPC}
		}
		return nil
	}
	_, err := b.env.InstallBundleAnchors(context.Background(), src)
	b.env.bundleFault = nil
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeDiskFull || !strings.Contains(err.Error(), "free space on that filesystem") {
		t.Fatalf("anchor write on a full volume: %v; want disk_full with the next step", err)
	}
	if readFile(t, dest) != before {
		t.Fatal("the installed trust anchors changed")
	}
	changes := recordedChanges(t, b.env)
	if len(changes) != 1 || changes[0].Kind != enterprisestatus.ChangeKindTrustAnchors ||
		changes[0].Outcome != enterprisestatus.ChangeFailed || changes[0].ReasonCode != string(enterprisebundle.CodeDiskFull) {
		t.Fatalf("change events = %+v; want one failed anchor install, disk_full", changes)
	}
}
