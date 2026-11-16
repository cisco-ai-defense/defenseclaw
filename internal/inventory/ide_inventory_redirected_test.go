// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/inventory/ideplugins"
)

// A managed profile whose AppData is redirected out of the gateway's reach
// takes its IDE inventory from the enumerator's record, attributed to the
// profile's owner, in place of the gateway's own scan of the profile
// (GAP-1249).
func TestManagedProfileTakesThePublishedIDEInventory(t *testing.T) {
	withoutMachineIDEs(t)
	alice, bob := t.TempDir(), t.TempDir()
	writeVSCodeExtensions(t, alice, "example.local")
	writeVSCodeExtensions(t, bob, "example.bob")
	const sid = "S-1-5-21-1-2-3-1001"
	redirected := filepath.Join(t.TempDir(), "Redirected", "alice", "Code")
	restore := SetOwnerIDELookup(func(gotSID, home string) ([]ideplugins.Install, bool) {
		if gotSID != sid || home != alice {
			return nil, false
		}
		return []ideplugins.Install{{
			Family: ideplugins.FamilyVSCode, Product: "vscode", Root: redirected,
			Plugins: []ideplugins.Plugin{{ID: "augment.vscode-augment", Publisher: "augment", Version: "1.0.0",
				Enabled: ideplugins.EnabledOff, EnabledSource: ideplugins.SourceStateDB, Scope: ideplugins.ScopeUser,
				Path: filepath.Join(redirected, "augment.vscode-augment")}},
		}}, true
	})
	t.Cleanup(restore)
	service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: alice, HomeDirs: []string{alice, bob},
		homeOwners: []discoveryHomeOwner{
			{Home: alice, UserID: sid, UserName: "alice"},
			{Home: bob, UserID: "S-1-5-21-1-2-3-1002", UserName: "bob"},
		}}}
	signals, inv := service.detectEditorExtensions()
	got := map[string]IDEPlugin{}
	for _, p := range inv.Plugins {
		got[p.PluginID] = p
	}
	if p, ok := got["augment.vscode-augment"]; !ok || p.UserID != sid || p.Enabled != ideplugins.EnabledOff {
		t.Fatalf("plugins = %+v, want alice's published plugin, disabled, as hers", inv.Plugins)
	}
	if _, ok := got["example.local"]; ok {
		t.Fatalf("plugins = %+v: the profile was scanned beside its published record", inv.Plugins)
	}
	if p, ok := got["example.bob"]; !ok || p.UserName != "bob" {
		t.Fatalf("plugins = %+v, want bob's profile scanned as before", inv.Plugins)
	}
	var owned bool
	for _, sig := range signals {
		if sig.SignatureID == "ide-augment.vscode-augment" {
			owned = sig.UserID == sid
		}
	}
	if !owned {
		t.Fatalf("signals = %+v, want the published AI extension owned by alice", signals)
	}
}

// A redirected folder the enumerator read for alice can sit inside another
// enrolled profile. Its signals are alice's, as the record is, and never
// the profile's whose path holds it.
func TestPublishedIDEInventoryInsideAnotherProfileIsTheRecordOwners(t *testing.T) {
	withoutMachineIDEs(t)
	alice, bob := t.TempDir(), t.TempDir()
	const sid = "S-1-5-21-1-2-3-1001"
	redirected := filepath.Join(bob, "alice-roaming", "Code")
	restore := SetOwnerIDELookup(func(gotSID, home string) ([]ideplugins.Install, bool) {
		if gotSID != sid || home != alice {
			return nil, false
		}
		return []ideplugins.Install{{
			Family: ideplugins.FamilyVSCode, Product: "vscode", Root: redirected,
			Plugins: []ideplugins.Plugin{{ID: "augment.vscode-augment", Publisher: "augment", Version: "1.0.0",
				Scope: ideplugins.ScopeUser, Path: filepath.Join(redirected, "augment.vscode-augment")}},
		}}, true
	})
	t.Cleanup(restore)
	service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: alice, HomeDirs: []string{alice, bob},
		homeOwners: []discoveryHomeOwner{
			{Home: alice, UserID: sid, UserName: "alice"},
			{Home: bob, UserID: "S-1-5-21-1-2-3-1002", UserName: "bob"},
		}}}
	signals, _ := service.detectEditorExtensions()
	var found bool
	for _, sig := range signals {
		if sig.SignatureID != "ide-augment.vscode-augment" {
			continue
		}
		found = true
		if sig.UserID != sid || sig.UserName != "alice" {
			t.Fatalf("signal owned by %s (%s), want alice's record owner %s", sig.UserName, sig.UserID, sid)
		}
	}
	if !found {
		t.Fatalf("signals = %+v, want the published AI extension", signals)
	}
}
