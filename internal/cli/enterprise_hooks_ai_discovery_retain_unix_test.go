//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func readTestUserScanRecord(path string) (inventory.UserScanRecord, error) {
	var record inventory.UserScanRecord
	data, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	return record, json.Unmarshal(data, &record)
}

// While a home's scans fail and pause, its last record stays current for
// the gateway, marked partial, so its inventory is not reported as removed
// before the pause ends (GAP-1224).
func TestStandaloneAIDiscoveryPauseKeepsTheLastRecordCurrent(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
	if err := os.MkdirAll(filepath.Join(alice, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(alice, ".codex", "config.toml"), []byte("model = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.AIDiscovery.Enabled = true
	dir := inventory.UserScanDirForConfig(cfg)
	previousBreaker, previousReader := enterpriseHookAIDiscoveryBreaker, enterpriseHookAIDiscoveryRecordReader
	t.Cleanup(func() {
		enterpriseHookAIDiscoveryBreaker, enterpriseHookAIDiscoveryRecordReader = previousBreaker, previousReader
	})
	enterpriseHookAIDiscoveryBreaker = newEnterpriseHookScanBreaker(3, time.Hour, 24*time.Hour)
	enterpriseHookAIDiscoveryRecordReader = readTestUserScanRecord
	fail := false
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		if fail {
			return enterpriseHookWorkerResponse{}, errors.New("worker for uid timed out: context deadline exceeded")
		}
		report := inventory.ScanUserHome(ctx, account.Home, account.User, account.UID, request.AIDiscovery.Options, request.AIDiscovery.Catalog)
		return enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion, AIDiscovery: &report}, nil
	}
	rows := []enterpriseHookReconcileRow{{User: "alice", UserHome: alice, Connector: "codex", OK: true, UID: uid}}
	pass := func() { runEnterpriseHookAIDiscoveryPass(context.Background(), io.Discard, dir, rows) }
	pass()
	path := filepath.Join(dir, strconv.Itoa(uid)+".json")
	good, err := readTestUserScanRecord(path)
	if err != nil || len(good.Report.Signals) == 0 {
		t.Fatalf("first scan record = %+v, %v; want alice's signals", good, err)
	}
	fail = true
	for range 3 {
		pass()
	}
	// The pause is longer than a record's life at the gateway: age the
	// record as an hour of the pause would.
	good.UpdatedAt = time.Now().Add(-2 * time.Hour).UTC()
	data, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	pass()
	kept, err := readTestUserScanRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(kept.UpdatedAt) > time.Minute || kept.Report.Summary.Result != "partial" ||
		kept.Report.Summary.DetectorErrors["user_scan"] == "" || len(kept.Report.Signals) != len(good.Report.Signals) {
		t.Fatalf("paused record = updated %s, result %q, errors %v, %d signals; want the last scan kept current and partial",
			kept.UpdatedAt, kept.Report.Summary.Result, kept.Report.Summary.DetectorErrors, len(kept.Report.Signals))
	}
}

// A uid given to a namesake from another domain, whose first scan fails,
// does not keep the previous account's record current: the record names
// another holder and goes (GAP-1074).
func TestStandaloneAIDiscoveryRecordIsNotKeptForANewHolderOfTheUID(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	corp := f.home(t, "alice-corp", 0o700)
	lab := f.home(t, "alice-lab", 0o700)
	resolver.accounts["alice@corp.example"] = unixidentity.Account{Name: "alice@corp.example", UID: uid, GID: gid, Home: corp, Shell: "/bin/bash"}
	if err := os.MkdirAll(filepath.Join(corp, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corp, ".codex", "config.toml"), []byte("model = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.AIDiscovery.Enabled = true
	dir := inventory.UserScanDirForConfig(cfg)
	previousBreaker, previousReader := enterpriseHookAIDiscoveryBreaker, enterpriseHookAIDiscoveryRecordReader
	t.Cleanup(func() {
		enterpriseHookAIDiscoveryBreaker, enterpriseHookAIDiscoveryRecordReader = previousBreaker, previousReader
	})
	enterpriseHookAIDiscoveryBreaker = newEnterpriseHookScanBreaker(3, time.Hour, 24*time.Hour)
	enterpriseHookAIDiscoveryRecordReader = readTestUserScanRecord
	fail := false
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		if fail {
			return enterpriseHookWorkerResponse{}, errors.New("worker for uid timed out: context deadline exceeded")
		}
		report := inventory.ScanUserHome(ctx, account.Home, account.User, account.UID, request.AIDiscovery.Options, request.AIDiscovery.Catalog)
		return enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion, AIDiscovery: &report}, nil
	}
	runEnterpriseHookAIDiscoveryPass(context.Background(), io.Discard, dir, []enterpriseHookReconcileRow{
		{User: "alice@corp.example", UserHome: corp, Connector: "codex", OK: true, UID: uid},
	})
	path := filepath.Join(dir, strconv.Itoa(uid)+".json")
	if good, err := readTestUserScanRecord(path); err != nil || len(good.Report.Signals) == 0 {
		t.Fatalf("first scan record = %+v, %v; want the corp account's signals", good, err)
	}
	delete(resolver.accounts, "alice@corp.example")
	resolver.accounts["alice@lab.example"] = unixidentity.Account{Name: "alice@lab.example", UID: uid, GID: gid, Home: lab, Shell: "/bin/bash"}
	fail = true
	runEnterpriseHookAIDiscoveryPass(context.Background(), io.Discard, dir, []enterpriseHookReconcileRow{
		{User: "alice@lab.example", UserHome: lab, Connector: "codex", OK: true, UID: uid},
	})
	if kept, err := readTestUserScanRecord(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record after the lab account's failed scan = %+v, %v; want the corp account's record gone", kept, err)
	}
}

// An account that is given a removed account's uid does not inherit that
// account's scan pause (GAP-1074).
func TestStandaloneAIDiscoveryPauseIsNotInheritedWithAReusedUID(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	bob := f.home(t, "bob", 0o700)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["bob"] = unixidentity.Account{Name: "bob", UID: uid, GID: gid, Home: bob, Shell: "/bin/bash"}
	cfg.AIDiscovery.Enabled = true
	dir := inventory.UserScanDirForConfig(cfg)
	previous := enterpriseHookAIDiscoveryBreaker
	t.Cleanup(func() { enterpriseHookAIDiscoveryBreaker = previous })
	enterpriseHookAIDiscoveryBreaker = newEnterpriseHookScanBreaker(3, time.Hour, 24*time.Hour)
	workers := map[string]int{}
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		workers[account.User]++
		return enterpriseHookWorkerResponse{}, errors.New("worker for uid timed out: context deadline exceeded")
	}
	for range 4 {
		runEnterpriseHookAIDiscoveryPass(context.Background(), io.Discard, dir, []enterpriseHookReconcileRow{
			{User: "bob", UserHome: bob, Connector: "codex", OK: true, UID: uid},
		})
	}
	if workers["bob"] != 3 {
		t.Fatalf("bob's workers = %d, want 3 before the pause", workers["bob"])
	}
	delete(resolver.accounts, "bob")
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
	runEnterpriseHookAIDiscoveryPass(context.Background(), io.Discard, dir, []enterpriseHookReconcileRow{
		{User: "alice", UserHome: alice, Connector: "codex", OK: true, UID: uid},
	})
	if workers["alice"] != 1 {
		t.Fatalf("alice's workers = %d, want 1: the uid's new account must not inherit bob's pause", workers["alice"])
	}
}
