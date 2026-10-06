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
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// uninstall --purge removed ~/.defenseclaw under a running per-user
// gateway, which kept running as an orphan without its files. The worker
// stops it first.
func TestStopPerUserGatewayForPurgeStopsTheRunningGateway(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	marker := filepath.Join(t.TempDir(), "purge-probe-running")
	t.Setenv(cliRestartProbeEnv, marker)

	gateway := daemon.New(config.DefaultDataPath())
	if _, err := gateway.Start([]string{"-test.run=^TestCLIRestartProcessProbe$"}); err != nil {
		t.Fatalf("start the probe gateway: %v", err)
	}
	t.Cleanup(func() { _ = gateway.Stop(3 * time.Second) })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("probe marker was not created: %v", err)
	}
	if running, _ := gateway.IsRunning(); !running {
		t.Fatal("the probe gateway is not running")
	}

	if stopped, err := stopPerUserGatewayForPurge(enterprisehooks.InstallOptions{UserHome: home}); err != nil || !stopped {
		t.Fatalf("stopPerUserGatewayForPurge: stopped=%v, %v", stopped, err)
	}
	if running, pid := daemon.New(dataDir).IsRunning(); running {
		t.Fatalf("the per-user gateway (PID %d) still runs after the purge stop", pid)
	}
	// Nothing left to stop, or no data directory at all, is not an error.
	if stopped, err := stopPerUserGatewayForPurge(enterprisehooks.InstallOptions{UserHome: home, DataDir: dataDir}); err != nil || stopped {
		t.Fatalf("second stop: stopped=%v, %v", stopped, err)
	}
	if stopped, err := stopPerUserGatewayForPurge(enterprisehooks.InstallOptions{UserHome: t.TempDir()}); err != nil || stopped {
		t.Fatalf("stop without a data directory: stopped=%v, %v", stopped, err)
	}
}

// The purge runs only after the stop, and a gateway that could not be
// stopped keeps the account's state.
func TestEnterpriseHookWorkerPurgeStopsThePerUserGatewayFirst(t *testing.T) {
	previousStop, previousPurger := enterpriseHookWorkerStopPerUser, enterpriseHookWorkerPurger
	t.Cleanup(func() { enterpriseHookWorkerStopPerUser, enterpriseHookWorkerPurger = previousStop, previousPurger })
	var calls []string
	stopErr := error(nil)
	enterpriseHookWorkerStopPerUser = func(opts enterprisehooks.InstallOptions) (bool, error) {
		calls = append(calls, "stop "+opts.DataDir)
		return false, stopErr
	}
	enterpriseHookWorkerPurger = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.PurgeSummary, error) {
		calls = append(calls, "purge "+opts.DataDir)
		return enterprisehooks.PurgeSummary{Data: true}, nil
	}
	home := t.TempDir()
	request := enterpriseHookWorkerRequest{
		Home: home, UID: os.Getuid(), GID: os.Getgid(),
		Targets: []enterpriseHookWorkerTarget{{Index: 0, Mode: enterpriseHookWorkerModePurge, Options: enterpriseHookWorkerOptions{
			UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), DataDir: filepath.Join(home, ".defenseclaw"),
		}}},
	}
	response := runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || !response.Targets[0].OK {
		t.Fatalf("purge response %+v", response)
	}
	// The worker reports only what it found: here the data folder, but no
	// running gateway and no per-user binaries (GAP-1444).
	if got := response.Targets[0].Purged; got == nil || *got != (enterpriseHookPurgeDetail{Data: true}) {
		t.Fatalf("purge detail %+v", got)
	}
	want := "stop " + filepath.Join(home, ".defenseclaw") + ",purge " + filepath.Join(home, ".defenseclaw")
	if got := strings.Join(calls, ","); got != want {
		t.Fatalf("calls %s, want %s", got, want)
	}

	calls = nil
	stopErr = errors.New("its per-user gateway (PID 42) could not be stopped: permission denied")
	response = runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || response.Targets[0].OK || !strings.Contains(response.Targets[0].Error, "could not be stopped") {
		t.Fatalf("purge response after a failed stop %+v", response)
	}
	if got := strings.Join(calls, ","); got != "stop "+filepath.Join(home, ".defenseclaw") {
		t.Fatalf("the purge ran after a failed stop: %s", got)
	}
}

// Every enrolled account the purge leaves alone is named, with the reason,
// so the administrator knows whose data stays.
func TestAddEnterpriseHookStatePurgesListsAccountsItCannotPurge(t *testing.T) {
	previousCheck := enterpriseHookCheckHome
	t.Cleanup(func() { enterpriseHookCheckHome = previousCheck })
	enterpriseHookCheckHome = func(home string, _ int) enterprisehooks.HomeCheck {
		switch home {
		case "/home/carol", "/home/gina":
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending}
		case "/home/frank":
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeUntrusted}
	}
	uid := func(v int) *int { return &v }
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{
		{User: "alice", UserHome: "/home/alice", UID: uid(1001), Connector: "codex"},
		{User: "alice", UserHome: "/home/alice", UID: uid(1001), Connector: "cursor"},
		{User: "bob", UserHome: "/home/bob", UID: uid(1002), Connector: "codex"},
		{User: "carol", UserHome: "/home/carol", UID: uid(1003), Connector: "codex"},
		{User: "dave", UserHome: "/home/dave", UID: uid(1004), Connector: "codex"},
		{User: "erin", UserHome: "/home/erin", Connector: "codex"},
	}}
	jobs := map[int]*enterpriseHookWorkerJob{
		1001: {Account: enterpriseHookWorkerAccount{UID: 1001, GID: 1001, User: "alice", Home: "/home/alice"}},
		1004: {Account: enterpriseHookWorkerAccount{UID: 1004, GID: 1004, User: "dave", Home: "/home/dave"}},
	}
	// A host that protects only machine-policy connectors has no manifest
	// rows: its eligible accounts (frank, gina) are enrolled too. alice is
	// in both and is purged once.
	accounts := []enterprisehooks.UnixEligibleAccount{
		{User: "alice", UID: 1001, GID: 1001, Home: "/home/alice"},
		{User: "frank", UID: 1006, GID: 1006, Home: "/home/frank"},
		{User: "gina", UID: 1007, GID: 1007, Home: "/home/gina"},
	}
	notPurged := addEnterpriseHookStatePurges(jobs, manifest, accounts, map[int]bool{1004: true})
	want := []string{
		"bob: its home is not trusted",
		"carol: its home is not available; rerun the purge when it is",
		"dave: its pending hook cleanup failed; the state stays for a retry",
		"erin: its manifest row has no usable uid",
		"gina: its home is not available; rerun the purge when it is",
	}
	if strings.Join(notPurged, "\n") != strings.Join(want, "\n") {
		t.Fatalf("not purged:\n%s\nwant:\n%s", strings.Join(notPurged, "\n"), strings.Join(want, "\n"))
	}
	// alice gets one purge of her data directory, dave none.
	purges := 0
	for _, target := range jobs[1001].Request.Targets {
		if target.Mode == enterpriseHookWorkerModePurge && target.Options.DataDir == "/home/alice/.defenseclaw" {
			purges++
		}
	}
	if purges != 1 || len(jobs[1004].Request.Targets) != 0 {
		t.Fatalf("alice purges %d, dave targets %+v", purges, jobs[1004].Request.Targets)
	}
	frank := jobs[1006]
	if frank == nil || len(frank.Request.Targets) != 1 || frank.Request.Targets[0].Mode != enterpriseHookWorkerModePurge ||
		frank.Request.Targets[0].Options.DataDir != "/home/frank/.defenseclaw" {
		t.Fatalf("frank, enrolled by the eligible accounts, has no purge of his data directory: %+v", frank)
	}
}

// GAP-1502: the purge removes the account's per-user install, so its gateway
// port claims go too; other accounts' init would keep skipping that port.
func TestStopPerUserGatewayForPurgeDropsTheAccountsPortClaims(t *testing.T) {
	claims := t.TempDir()
	previous := gatewayPortClaimDir
	gatewayPortClaimDir = claims
	t.Cleanup(func() { gatewayPortClaimDir = previous })
	claim := filepath.Join(claims, gatewayPortClaimPrefix+"19126")
	other := filepath.Join(claims, "unrelated-file")
	for _, path := range []string{claim, other} {
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if stopped, err := stopPerUserGatewayForPurge(enterprisehooks.InstallOptions{DataDir: dataDir}); err != nil || stopped {
		t.Fatalf("stopPerUserGatewayForPurge = %v, %v; want false, nil", stopped, err)
	}
	if _, err := os.Lstat(claim); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the account's port claim is still there: %v", err)
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatalf("an unrelated file went: %v", err)
	}
}
