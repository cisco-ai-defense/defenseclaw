// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// `enterprise hooks remove-all --check` reads the guardian's pending
// cleanups. A cleanup of an account the manifest no longer names, whose home
// is not available, passed the uninstall precheck; the real remove-all then
// left it pending, and the uninstall stopped on it after it had stopped the
// services, removed the machine policy and the other users' Claude Code
// blockers (GAP-2377). The check reports it as the real run does (a bare
// pending entry, which the precheck refuses on), and an untrusted home as
// failed, without running a worker; a cleanup the worker can run, one a
// manifest row covers and one of a removed account are left alone.
func TestRemoveAllCheckReportsThePendingCleanupsTheRealRunWouldStopOn(t *testing.T) {
	previousCheck, previousGone, previousRunner := enterpriseHookCheckHome, enterpriseHookRecordedHomeGone, enterpriseHookWorkerRunner
	previousCfg := cfg
	t.Cleanup(func() {
		enterpriseHookCheckHome, enterpriseHookRecordedHomeGone, enterpriseHookWorkerRunner = previousCheck, previousGone, previousRunner
		cfg = previousCfg
	})
	cfg = &config.Config{DataDir: useUserCleanupStateDir(t)}
	enterpriseHookRecordedHomeGone = func(string) bool { return false }
	enterpriseHookCheckHome = func(home string, _ int) enterprisehooks.HomeCheck {
		switch home {
		case "/home/pm58m":
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending}
		case "/home/mallory":
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomeUntrusted, Reason: "user home is group/other writable"}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	workers := 0
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		workers++
		return enterpriseHookWorkerResponse{}, nil
	}
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"pm58m":   {Name: "pm58m", UID: 3101, GID: 3101, Home: "/home/pm58m"},
		"mallory": {Name: "mallory", UID: 3102, GID: 3102, Home: "/home/mallory"},
		"frank":   {Name: "frank", UID: 3103, GID: 3103, Home: "/home/frank"},
		"alice":   {Name: "alice", UID: 3104, GID: 3104, Home: "/home/alice"},
	}}
	cleanups := []enterpriseHookUserCleanup{
		{Connector: "hermes", UID: 3101, User: "pm58m", UserHome: "/home/pm58m"},
		{Connector: "codex", UID: 3102, User: "mallory", UserHome: "/home/mallory"},
		{Connector: "codex", UID: 3103, User: "frank", UserHome: "/home/frank"},
		{Connector: "codex", UID: 3104, User: "alice", UserHome: "/home/alice"},
		{Connector: "codex", UID: 3199, User: "gone", UserHome: "/home/gone"},
	}
	if err := saveEnterpriseHookUserCleanups(cfg.DataDir, cleanups, time.Now()); err != nil {
		t.Fatal(err)
	}
	// alice's codex row is still in the manifest, so its job covers her cleanup.
	jobs := map[int]*enterpriseHookWorkerJob{3104: {
		Account: enterpriseHookWorkerAccount{UID: 3104, GID: 3104, User: "alice", Home: "/home/alice"},
		Request: enterpriseHookWorkerRequest{Targets: []enterpriseHookWorkerTarget{{
			Mode: enterpriseHookWorkerModeRemove, Options: enterpriseHookWorkerOptions{ConnectorName: "codex"},
		}}},
	}}
	report := enterpriseHooksRemoveAllReport{}
	checkEnterpriseHookPendingCleanups(&report, jobs, resolver)
	if !slices.Equal(report.Pending, []string{"pm58m/hermes"}) {
		t.Fatalf("pending = %q, want the cleanup whose home is not available, as a bare entry", report.Pending)
	}
	if len(report.Failed) != 1 || report.Failed[0] != "mallory/codex: enterprise hooks: user home is group/other writable" {
		t.Fatalf("failed = %q, want the cleanup whose home is not trusted", report.Failed)
	}
	if report.Removed != 0 || workers != 0 {
		t.Fatalf("the check changed something: removed %d, %d workers ran", report.Removed, workers)
	}
	if remaining, err := loadEnterpriseHookUserCleanups(cfg.DataDir); err != nil || len(remaining) != len(cleanups) {
		t.Fatalf("the check changed the ledger: %d rows, %v", len(remaining), err)
	}
}
