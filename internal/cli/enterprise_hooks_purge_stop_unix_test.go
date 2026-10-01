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

	if err := stopPerUserGatewayForPurge(enterprisehooks.InstallOptions{UserHome: home}); err != nil {
		t.Fatalf("stopPerUserGatewayForPurge: %v", err)
	}
	if running, pid := daemon.New(dataDir).IsRunning(); running {
		t.Fatalf("the per-user gateway (PID %d) still runs after the purge stop", pid)
	}
	// Nothing left to stop, or no data directory at all, is not an error.
	if err := stopPerUserGatewayForPurge(enterprisehooks.InstallOptions{UserHome: home, DataDir: dataDir}); err != nil {
		t.Fatalf("second stop: %v", err)
	}
	if err := stopPerUserGatewayForPurge(enterprisehooks.InstallOptions{UserHome: t.TempDir()}); err != nil {
		t.Fatalf("stop without a data directory: %v", err)
	}
}

// The purge runs only after the stop, and a gateway that could not be
// stopped keeps the account's state.
func TestEnterpriseHookWorkerPurgeStopsThePerUserGatewayFirst(t *testing.T) {
	previousStop, previousPurger := enterpriseHookWorkerStopPerUser, enterpriseHookWorkerPurger
	t.Cleanup(func() { enterpriseHookWorkerStopPerUser, enterpriseHookWorkerPurger = previousStop, previousPurger })
	var calls []string
	stopErr := error(nil)
	enterpriseHookWorkerStopPerUser = func(opts enterprisehooks.InstallOptions) error {
		calls = append(calls, "stop "+opts.DataDir)
		return stopErr
	}
	enterpriseHookWorkerPurger = func(_ context.Context, opts enterprisehooks.InstallOptions) error {
		calls = append(calls, "purge "+opts.DataDir)
		return nil
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
		if home == "/home/carol" {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending}
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
	notPurged := addEnterpriseHookStatePurges(jobs, manifest, map[int]bool{1004: true})
	want := []string{
		"bob: its home is not trusted",
		"carol: its home is not available; rerun the purge when it is",
		"dave: its pending hook cleanup failed; the state stays for a retry",
		"erin: its manifest row has no usable uid",
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
}
