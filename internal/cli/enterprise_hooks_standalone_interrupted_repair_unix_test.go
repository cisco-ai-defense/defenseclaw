// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
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

type gap0754RoundTripper func(*http.Request) (*http.Response, error)

func (f gap0754RoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// GAP-0754: a pass the watch loop interrupts after its worker put a target
// back still accounts the repair like a pass that ran to its end: the repairs
// record, the audit report to the gateway, the pass repair count the watch
// loop logs, the agent config notice of the worker and the durable restore
// entry. The notice of a target the pass did not answer survives. A pass that
// is interrupted with nothing repaired reports nothing.
func TestStandaloneInterruptedPassStillReportsTheRepairItMade(t *testing.T) {
	for _, tc := range []struct {
		name   string
		repair bool
	}{{"repaired", true}, {"nothing repaired", false}} {
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

			// A notice of another target, written by an earlier pass.
			writeEnterpriseHookGuardianNotices(io.Discard, f.dataDir, []enterpriseHookGuardianNotice{{User: "bob", Connector: "codex", AgentConfig: "restored_last_good"}})

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

			interrupt, cancel := context.WithCancel(context.Background())
			defer cancel()
			previousRunner := enterpriseHookWorkerRunner
			enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				response, err := previousRunner(ctx, account, request)
				for i := range response.Targets {
					response.Targets[i].Repaired = tc.repair
					if tc.repair {
						response.Targets[i].AgentConfig = "settings_lost"
					}
				}
				cancel() // the watch loop interrupts the pass as its worker answers
				return response, err
			}

			run, err := runEnterpriseHookReconcileOnce(interrupt)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("interrupted pass error = %v, want context canceled", err)
			}
			if want := map[bool]int{true: 1, false: 0}[tc.repair]; run.Repairs != want || len(run.RepairedTargets) != want {
				t.Fatalf("interrupted pass repairs = %d (%v), want %d: the watch loop logs repairs>0 from it (GAP-0754)", run.Repairs, run.RepairedTargets, want)
			}
			mu.Lock()
			got := append([]string(nil), reports...)
			mu.Unlock()
			repairsPath := filepath.Join(f.dataDir, hookGuardianRepairsFile)
			if !tc.repair {
				if len(got) != 0 {
					t.Fatalf("a pass that repaired nothing reported %v", got)
				}
				if _, err := os.Stat(repairsPath); err == nil {
					t.Fatal("a pass that repaired nothing wrote a repairs record")
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("audit reports = %v, want one for the repaired hermes target (GAP-0754)", got)
			}
			var report struct {
				User      string `json:"user"`
				UID       *int   `json:"uid"`
				Connector string `json:"connector"`
			}
			if err := json.Unmarshal([]byte(got[0]), &report); err != nil || report.User != "alice" || report.UID == nil || *report.UID != uid || report.Connector != "hermes" {
				t.Fatalf("audit report = %s (%v)", got[0], err)
			}
			if data, err := os.ReadFile(repairsPath); err != nil || !strings.Contains(string(data), "hermes") {
				t.Fatalf("repairs record = %q, %v", data, err)
			}

			notices := map[string]string{}
			for _, notice := range readEnterpriseHookGuardianNotices(f.dataDir) {
				notices[notice.User+"/"+notice.Connector] = notice.AgentConfig
			}
			if len(notices) != 2 || notices["alice/hermes"] != "settings_lost" || notices["bob/codex"] != "restored_last_good" {
				t.Fatalf("notices after the interrupted pass = %v, want the worker notice of alice/hermes next to the earlier bob/codex one", notices)
			}
			// The restore is on disk now, not when a later pass records.
			if restores := guardianRestoresForTest(t, f.dataDir); len(restores) != 1 {
				t.Fatalf("restores right after the interrupted pass = %v, want the hermes restore of uid %d", restores, uid)
			}

			// The next pass finds the target in order and repairs nothing.
			enterpriseHookWorkerRunner = previousRunner
			if _, err := runEnterpriseHookReconcileOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			restores := guardianRestoresForTest(t, f.dataDir)
			if _, ok := restores[enterpriseHookGuardianRestoreUIDKey(uid, "hermes")]; !ok || len(restores) != 1 {
				t.Fatalf("restores after the next pass = %v, want the hermes restore of uid %d", restores, uid)
			}
		})
	}
}
