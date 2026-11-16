//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// The shared fixture predates Remove reports. DELTA-33's re-home tests use
// this reporting wrapper while retaining the fixture's request recording.
func useReportingStandaloneRunner(t *testing.T) {
	t.Helper()
	previous := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = previous })
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response, err := previous(ctx, account, request)
		if err != nil {
			return response, err
		}
		for i := range response.Targets {
			for _, target := range request.Targets {
				if response.Targets[i].Index == target.Index && target.Mode == enterpriseHookWorkerModeRemove {
					response.Targets[i].PathsReported = true
					response.Targets[i].CleanedPaths = []string{filepath.Join(account.Home, ".config", target.Options.ConnectorName, "config")}
				}
			}
		}
		return response, nil
	}
}

func TestStandaloneCleanupRequiresTrustedRemoveReportOnlyAfterRehome(t *testing.T) {
	for _, test := range []struct {
		name, path, remaining string
		report                bool
		wantRuns              int
	}{
		{name: "missing report", wantRuns: 1},
		{name: "outside path", path: "/tmp/sample-other/config", report: true, wantRuns: 2},
		{name: "relative path", path: "relative/config", report: true, wantRuns: 1},
		{name: "oversized path", path: "/" + strings.Repeat("a", enterpriseHookWorkerRemovePathMax), report: true, wantRuns: 1},
		{name: "remaining entry", remaining: "DefenseClaw hook remains", report: true, wantRuns: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			home := f.home(t, "sample-current", 0o700)
			uid, gid := rehomedTestUID(t, home)
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: home}
			oldHome := filepath.Join(f.homes, "sample-old")
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: oldHome}
			previous := enterpriseHookWorkerRunner
			enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				response, err := previous(ctx, account, request)
				if err == nil {
					response.Targets[0].PathsReported = test.report
					if test.path != "" {
						response.Targets[0].CleanedPaths = []string{test.path}
					} else if test.report {
						response.Targets[0].CleanedPaths = []string{filepath.Join(home, ".hermes", "config.yaml")}
					}
					response.Targets[0].Remaining = test.remaining
				}
				return response, err
			}
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
			var unverified *enterpriseHookCleanupUnverifiedError
			if outcome != enterpriseHookUserCleanupFailed || !errors.As(err, &unverified) ||
				!strings.Contains(err.Error(), "rerun") || len(f.requests) != test.wantRuns {
				t.Fatalf("unverified report = %v, %v, runs %d", outcome, err, len(f.requests))
			}
			if test.path != "" && !strings.Contains(err.Error(), test.path[:min(len(test.path), 96)]) {
				t.Fatalf("warning omitted path %q: %v", test.path, err)
			}
		})
	}

	// A normal removal keeps the previous semantics even with the old fake.
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	home := f.home(t, "sample-current", 0o700)
	uid, gid := rehomedTestUID(t, home)
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: home}
	entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: home}
	if outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver); outcome != enterpriseHookUserCleanupDone || err != nil || len(f.requests) != 1 {
		t.Fatalf("ordinary removal changed: %v, %v, runs %d", outcome, err, len(f.requests))
	}
}

func TestStandaloneCleanupRejectsRecordedWorkerOffHomePath(t *testing.T) {
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	useReportingStandaloneRunner(t)
	currentHome := f.home(t, "sample-current", 0o700)
	oldHome := f.home(t, "sample-old", 0o700)
	uid, gid := rehomedTestUID(t, currentHome)
	rehomedTestUID(t, oldHome)
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: currentHome}
	entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: oldHome}
	outside := filepath.Join(f.homes, "other", "config.yaml")
	previous := enterpriseHookWorkerRunner
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response, err := previous(ctx, account, request)
		if err == nil && account.Home == oldHome {
			response.Targets[0].CleanedPaths = []string{outside}
		}
		return response, err
	}
	outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
	if outcome != enterpriseHookUserCleanupFailed || err == nil ||
		!strings.Contains(err.Error(), outside) || len(f.requests) != 3 {
		t.Fatalf("recorded worker off-home report = %v, %v, requests %d", outcome, err, len(f.requests))
	}
}
