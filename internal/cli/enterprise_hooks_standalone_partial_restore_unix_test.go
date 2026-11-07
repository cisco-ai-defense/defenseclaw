// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-0754: a worker that put hook files back and left the target failed is
// a restore (counted, audited, recorded) and a failure (the row is not OK, so
// the pass retries and the owned-files record does not call it verified). A
// worker that restored nothing and failed is only a failure.
func TestStandalonePassAccountsARestoreOnATargetThatStaysFailed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		restored bool
	}{{"restored", true}, {"nothing restored", false}} {
		t.Run(tc.name, func(t *testing.T) {
			uid, gid := os.Getuid(), os.Getgid()
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{}}
			f := newStandaloneFixture(t, resolver)
			alice := f.home(t, "alice", 0o700)
			resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
			f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"})
			f.writeLedger(t, protectedRow("alice", alice, "hermes"))
			key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "hermes"})
			f.writeBindings(t, map[string]enterpriseHookUnixBinding{key: {UID: uid, Home: alice, LockUpdatedAt: "L", EntryUpdatedAt: "E"}})

			var mu sync.Mutex
			var reports []string
			previousFactory := guardianAuditClientFactory
			guardianAuditClientFactory = func(time.Duration, string, int) (*http.Client, error) {
				return &http.Client{Transport: gap0754RoundTripper(func(r *http.Request) (*http.Response, error) {
					body, _ := io.ReadAll(r.Body)
					mu.Lock()
					reports = append(reports, string(body))
					mu.Unlock()
					return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				})}, nil
			}
			t.Cleanup(func() { guardianAuditClientFactory = previousFactory })

			previousRunner := enterpriseHookWorkerRunner
			t.Cleanup(func() { enterpriseHookWorkerRunner = previousRunner })
			enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				response, err := previousRunner(ctx, account, request)
				for i := range response.Targets {
					response.Targets[i].OK, response.Targets[i].Result, response.Targets[i].AgentConfig = false, nil, ""
					response.Targets[i].Error = "install failed after it wrote the script"
					response.Targets[i].Repaired = tc.restored
				}
				return response, err
			}

			run, err := runEnterpriseHookReconcileOnce(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if run.Failures != 1 || len(run.Rows) != 1 || run.Rows[0].OK {
				t.Fatalf("failures = %d, rows = %+v, want the target failed so the pass retries it", run.Failures, run.Rows)
			}
			want := map[bool]int{true: 1, false: 0}[tc.restored]
			mu.Lock()
			got := append([]string(nil), reports...)
			mu.Unlock()
			if run.Repairs != want || len(run.RepairedTargets) != want || len(got) != want {
				t.Fatalf("repairs = %d (%v), audit reports = %v, want %d", run.Repairs, run.RepairedTargets, got, want)
			}
			data, readErr := os.ReadFile(filepath.Join(f.dataDir, hookGuardianRepairsFile))
			if tc.restored != (readErr == nil && strings.Contains(string(data), "hermes")) {
				t.Fatalf("repairs record = %q, %v, want hermes recorded = %v", data, readErr, tc.restored)
			}
			if record, err := enterprisehooks.ReadGuardianOwnedFilesRecord(filepath.Join(f.dataDir, enterprisehooks.GuardianOwnedFilesFile)); err == nil && len(record.Targets) != 0 {
				t.Fatalf("owned-files record = %+v, want the failed target not recorded as verified", record.Targets)
			}
		})
	}
}
