// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// Every inbox bundle ends in a receipt: the run applies the highest version
// and gives each lower one a failed(superseded) receipt.
func TestBundleInboxGivesLowerVersionsASupersededReceipt(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	for version, cfg := range map[uint64]string{2: v1 + "\n# two\n", 3: v2} {
		var buf bytes.Buffer
		if err := enterprisebundle.WriteArchive(&buf, b.signed(version, cfg)); err != nil {
			t.Fatal(err)
		}
		writeRooted(t, filepath.Join(b.env.bundleInboxDir(), fmt.Sprintf("v%d.dcbundle", version)), buf.String())
	}
	requireOK(t, b.run(Options{Action: ActionEnsure, BundleInbox: true}))
	if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(3) {
		t.Fatalf("state = %+v", st)
	}
	lower := b.receipt(bundleID(2))
	if lower.State != enterprisebundle.StateFailed || lower.ErrorCode != enterprisebundle.CodeSuperseded ||
		!strings.Contains(lower.ErrorMessage, "version 3") {
		t.Fatalf("lower inbox version receipt = %+v", lower)
	}
	if _, err := os.Lstat(filepath.Join(b.env.bundleStore().PublicReceiptEventsDir(), bundleID(2)+".json")); err != nil {
		t.Fatalf("no receipt event for the superseded bundle: %v", err)
	}
	last, _, err := b.env.bundleStore().Latest()
	if err != nil || last == nil || last.BundleID != bundleID(3) {
		t.Fatalf("latest = %+v, %v", last, err)
	}
}

// One run processes at most maxInboxFiles inbox files, in file-name order;
// the rest stay for the next run, which applies them. The apply help states
// the bound, so it must match the constant.
func TestBundleInboxProcessesAtMostMaxInboxFilesARun(t *testing.T) {
	b := newBundleHost(t)
	v1, _, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	// File i holds version i+2, so the file left over holds the top version.
	for i := 0; i <= maxInboxFiles; i++ {
		var buf bytes.Buffer
		if err := enterprisebundle.WriteArchive(&buf, b.signed(uint64(i+2), v1+fmt.Sprintf("\n# %d\n", i))); err != nil {
			t.Fatal(err)
		}
		writeRooted(t, filepath.Join(b.env.bundleInboxDir(), fmt.Sprintf("v%02d.dcbundle", i)), buf.String())
	}
	left := fmt.Sprintf("v%02d.dcbundle", maxInboxFiles)
	top := uint64(maxInboxFiles + 2)
	requireOK(t, b.run(Options{Action: ActionEnsure, BundleInbox: true}))
	if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(top-1) {
		t.Fatalf("first run: state = %+v", st)
	}
	if r := b.receipt(bundleID(2)); r.State != enterprisebundle.StateFailed || r.ErrorCode != enterprisebundle.CodeSuperseded {
		t.Fatalf("first run: lowest version receipt = %+v", r)
	}
	if entries, _ := os.ReadDir(b.env.bundleInboxDir()); len(entries) != 1 || entries[0].Name() != left {
		t.Fatalf("first run: inbox = %v, want only %s", entries, left)
	}
	requireOK(t, b.run(Options{Action: ActionEnsure, BundleInbox: true}))
	if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(top) {
		t.Fatalf("second run: state = %+v", st)
	}
	if entries, _ := os.ReadDir(b.env.bundleInboxDir()); len(entries) != 0 {
		t.Fatalf("second run: inbox not emptied: %v", entries)
	}
	help, err := os.ReadFile(filepath.Join("..", "cli", "enterprise_bundle_apply.go"))
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("at most %d inbox files", maxInboxFiles); !strings.Contains(strings.Join(strings.Fields(string(help)), " "), want) {
		t.Fatalf("the bundle apply help does not say %q", want)
	}
}

// bundle_required says signed-bundle mode is on because a trust anchor file
// exists, without claiming who installed it.
func TestBundleRequiredNamesTheAnchorFileNotWhoInstalledIt(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	other := filepath.Join(t.TempDir(), "config.yaml")
	writeRooted(t, other, v2)
	r := b.run(Options{Action: ActionEnsure, ConfigFile: other})
	requireError(t, r, codeBundleRequired)
	for _, e := range r.Errors {
		if e.Code == codeBundleRequired && (strings.Contains(e.Message, "MDM") || !strings.Contains(e.Message, "a trust anchor file is installed at")) {
			t.Fatalf("bundle_required message = %q", e.Message)
		}
	}
}
