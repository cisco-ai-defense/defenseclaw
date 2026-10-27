// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// rel-1-0-5 GAP-0029: on a managed Mac the hook guardian kept the cleanup
// of a deleted local account forever. The account was deleted with its
// home (sysadminctl -deleteUser), but the long-running guardian's os/user
// lookup still found it (libSystem's per-process cache), so the missing
// home read as "not available yet" and the entry was carried unchanged on
// every pass; status kept guardian_cleanup_pending. A fresh process (status,
// a one-shot reconcile) found no such account and retired it at once. The
// guardian now confirms such a "found" with a fresh directory read before
// it waits for the home.
func TestStandaloneCleanupRetiresADeletedAccountAStaleLookupStillFinds(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	useReportingStandaloneRunner(t)
	deleted := filepath.Join(f.homes, "pod-deleted") // removed with the account
	unmounted := filepath.Join(f.homes, "unmounted-volume", "pod-offline")
	// The stale answer: the account as it was before it was deleted.
	resolver.accounts["pod-deleted"] = unixidentity.Account{Name: "pod-deleted", UID: uid, GID: gid, Home: deleted}
	resolver.accounts["pod-offline"] = unixidentity.Account{Name: "pod-offline", UID: uid + 1, GID: gid, Home: unmounted}
	f.writeManifest(t)

	previous := enterpriseHookCleanupAccountGone
	t.Cleanup(func() { enterpriseHookCleanupAccountGone = previous })
	var asked []string
	gone := map[string]bool{}
	enterpriseHookCleanupAccountGone = func(_ context.Context, name string) bool {
		asked = append(asked, name)
		return gone[name]
	}
	entries := []enterpriseHookUserCleanup{
		{Connector: "hermes", UID: uid, User: "pod-deleted", UserHome: deleted, RecordedAt: "2026-10-27T12:54:40Z"},
		{Connector: "hermes", UID: uid + 1, User: "pod-offline", UserHome: unmounted, RecordedAt: "2026-10-27T12:54:40Z"},
	}

	// Unconfirmed: the fresh read still has the record, so the missing
	// home may come back (a home created at first login): keep waiting.
	var first bytes.Buffer
	outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &first, entries[0], resolver)
	if outcome != enterpriseHookUserCleanupPending || err != nil {
		t.Fatalf("pod-deleted with a directory record = %v, %v; want pending", outcome, err)
	}

	// Confirmed gone. Only an account whose recorded home is definitively
	// gone (its parent answers) is retired; a home below a missing parent
	// (an unmounted volume) still waits, whatever the directory says.
	gone["pod-deleted"], gone["pod-offline"] = true, true
	asked = nil
	if err := saveEnterpriseHookUserCleanups(f.dataDir, entries, time.Now()); err != nil {
		t.Fatal(err)
	}
	manifest, err := enterprisehooks.LoadManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &log, manifest,
		enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, resolver, time.Now()); err != nil {
		t.Fatal(err)
	}
	pending, err := loadEnterpriseHookUserCleanups(f.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].User != "pod-offline" {
		t.Fatalf("only the deleted account's cleanup may be retired: %+v", pending)
	}
	if !strings.Contains(log.String(), "hermes/pod-deleted: no such account (a fresh directory read has no record of pod-deleted") ||
		!strings.Contains(log.String(), "nothing to remove as that user") || strings.Contains(log.String(), "pod-offline: no such account") {
		t.Fatalf("the guardian must say why it retired the deleted account's cleanup, and only that one: %s", log.String())
	}
	if len(asked) != 1 || asked[0] != "pod-deleted" {
		t.Fatalf("the fresh read runs only for an account whose recorded home is gone: asked %v", asked)
	}
	if len(f.workerTargets()) != 0 {
		t.Fatalf("no worker may run for a deleted account: %+v", f.workerTargets())
	}
}
