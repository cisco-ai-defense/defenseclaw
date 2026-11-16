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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// withDeviceGroups returns an anchors document with its device_groups set.
func withDeviceGroups(doc string, groups ...string) string {
	quoted := make([]string, len(groups))
	for i, g := range groups {
		quoted[i] = `"` + g + `"`
	}
	return strings.Replace(doc, `"device_groups":[]`, `"device_groups":[`+strings.Join(quoted, ",")+`]`, 1)
}

// #1316: `anchors install --device-group G` pins the device to one group. The
// file must list G or no group, the installed file lists G alone, and a file
// that does not allow G is refused with nothing written.
func TestInstallBundleAnchorsPinsTheDeviceGroup(t *testing.T) {
	b, dest := newAnchorsHost(t)
	before := readFile(t, dest)
	b.env.AnchorsDeviceGroup = "eng"

	doc := withDeviceGroups(anchorsDoc(t, b, "k1:active", "k2:active"), "eng", "sales")
	src, base := agentAnchors(t, doc)
	b.env.Trust = modeTrust(base, b.env.Root)
	out, err := b.env.InstallBundleAnchors(context.Background(), src)
	if err != nil || out.Result != AnchorsReplaced {
		t.Fatalf("pinned install = %+v, %v", out, err)
	}
	installed, decodeErr := enterprisebundle.DecodeAnchors([]byte(readFile(t, dest)))
	if decodeErr != nil || len(installed.DeviceGroups) != 1 || installed.DeviceGroups[0] != "eng" || len(installed.Keys) != 2 || installed.TenantID != "acme" {
		t.Fatalf("installed anchors = %+v, %v", installed, decodeErr)
	}
	if out.SHA256 != sha256Bytes([]byte(readFile(t, dest))) || len(out.Anchors.DeviceGroups) != 1 {
		t.Fatalf("the result does not describe the pinned file: %+v", out)
	}
	if again, err := b.env.InstallBundleAnchors(context.Background(), src); err != nil || again.Result != AnchorsUnchanged {
		t.Fatalf("the same pin again = %+v, %v", again, err)
	}

	// A file that lists other groups only cannot be pinned to eng: refused, the file stays.
	installedBytes := readFile(t, dest)
	other, otherBase := agentAnchors(t, withDeviceGroups(anchorsDoc(t, b, "k1:active"), "sales"))
	b.env.Trust = modeTrust(otherBase, b.env.Root)
	if _, err := b.env.InstallBundleAnchors(context.Background(), other); enterprisebundle.CodeOf(err) != enterprisebundle.CodeAnchorInvalid {
		t.Fatalf("a file without the group: %v", err)
	}
	if readFile(t, dest) != installedBytes {
		t.Fatal("a refused pin changed the installed file")
	}
	if before == installedBytes {
		t.Fatal("test setup: the pin changed nothing")
	}
}

// applyWithAnchors applies the bundle at dir with the anchor file src.
func (b *bundleHost) applyWithAnchors(dir, src string) *enterprisestatus.Result {
	b.t.Helper()
	return b.run(Options{Action: ActionEnsure, Bundle: dir, TrustAnchors: src})
}

// #1316: anchors and a bundle in one transaction. The bundle is verified
// against the new file, the file stays with a confirmed bundle and is
// recorded once, and the same run reports the install.
func TestBundleApplyWithTrustAnchorsKeepsThemWhenTheBundleIsConfirmed(t *testing.T) {
	b, dest := newAnchorsHost(t)
	v1, _, _ := bundleConfigs(b.testHost)
	b.mapPromotedBundleOwners(1)
	doc := anchorsDoc(t, b, "k1:active", "k2:active")
	src, base := agentAnchors(t, doc)
	b.env.Trust = modeTrust(base, b.env.Root)
	b.env.AnchorsDeviceGroup = "eng"

	r := b.applyWithAnchors(b.dir(1, v1), src)
	requireOK(t, r)
	installed, err := enterprisebundle.DecodeAnchors([]byte(readFile(t, dest)))
	if err != nil || len(installed.Keys) != 2 || len(installed.DeviceGroups) != 1 || installed.DeviceGroups[0] != "eng" {
		t.Fatalf("installed anchors = %+v, %v", installed, err)
	}
	if rc := b.receipt(bundleID(1)); rc.State != enterprisebundle.StateConfirmed {
		t.Fatalf("receipt = %+v", rc)
	}
	if !strings.Contains(strings.Join(r.Changes, "\n"), "replaced the trust anchors in ") || r.Noop {
		t.Fatalf("changes = %v, noop %v", r.Changes, r.Noop)
	}
	changes := recordedChanges(t, b.env)
	if len(changes) != 1 || changes[0].Kind != enterprisestatus.ChangeKindTrustAnchors || changes[0].Outcome != enterprisestatus.ChangeApplied {
		t.Fatalf("change events = %+v", changes)
	}
}

// A bundle that fails puts the anchor file the run found back (the file, or
// none), without the caller's help, and records one failed change.
func TestBundleApplyWithTrustAnchorsPutsThemBackWhenTheBundleFails(t *testing.T) {
	for _, hadFile := range []bool{true, false} {
		name := "previous file"
		if !hadFile {
			name = "no previous file"
		}
		t.Run(name, func(t *testing.T) {
			b, dest := newAnchorsHost(t)
			before := readFile(t, dest)
			if !hadFile {
				if err := os.Remove(dest); err != nil {
					t.Fatal(err)
				}
			}
			v1, _, _ := bundleConfigs(b.testHost)
			// The bundle is signed by k1, which the new file does not hold:
			// the bundle is refused key_unknown.
			src, base := agentAnchors(t, anchorsDoc(t, b, "k2:active"))
			b.env.Trust = modeTrust(base, b.env.Root)

			r := b.applyWithAnchors(b.dir(1, v1), src)
			requireError(t, r, string(enterprisebundle.CodeKeyUnknown))
			raw, readErr := os.ReadFile(dest)
			if hadFile && (readErr != nil || string(raw) != before) {
				t.Fatalf("the previous anchors were not put back: %q, %v", raw, readErr)
			}
			if !hadFile && !os.IsNotExist(readErr) {
				t.Fatalf("the new anchors were left in place: %v", readErr)
			}
			if rc := b.receipt(bundleID(1)); rc.State != enterprisebundle.StateFailed {
				t.Fatalf("receipt = %+v", rc)
			}
			changes := recordedChanges(t, b.env)
			if len(changes) != 1 || changes[0].Outcome != enterprisestatus.ChangeFailed {
				t.Fatalf("change events = %+v", changes)
			}
		})
	}
}

// A device group the anchors do not allow refuses before anything is written;
// a source that is not a trusted anchor file does too.
func TestBundleApplyWithTrustAnchorsRefusesBeforeWriting(t *testing.T) {
	b, dest := newAnchorsHost(t)
	before := readFile(t, dest)
	v1, _, _ := bundleConfigs(b.testHost)
	src, base := agentAnchors(t, withDeviceGroups(anchorsDoc(t, b, "k1:active"), "sales"))
	b.env.Trust = modeTrust(base, b.env.Root)
	b.env.AnchorsDeviceGroup = "eng"
	requireError(t, b.applyWithAnchors(b.dir(1, v1), src), string(enterprisebundle.CodeAnchorInvalid))
	if readFile(t, dest) != before {
		t.Fatal("a refused pin changed the installed anchors")
	}

	b.env.AnchorsDeviceGroup = ""
	requireError(t, b.applyWithAnchors(b.dir(2, v1), src+".missing"), string(enterprisebundle.CodeAnchorMissing))
	if readFile(t, dest) != before {
		t.Fatal("a missing source changed the installed anchors")
	}
}

func TestBundleApplyTrustAnchorsNeedsABundleAndAnAbsolutePath(t *testing.T) {
	b, _ := newAnchorsHost(t)
	v1, _, _ := bundleConfigs(b.testHost)
	requireError(t, b.run(Options{Action: ActionEnsure, TrustAnchors: "/tmp/anchors.json"}), codeInvalidArguments)
	requireError(t, b.run(Options{Action: ActionEnsure, Bundle: b.dir(1, v1), TrustAnchors: "anchors.json"}), codeInvalidArguments)
}
