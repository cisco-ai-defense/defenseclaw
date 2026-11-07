// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-0754: the production worker runner drops its response when the pass
// context is canceled, so an independent owned-file or manifest event can
// cancel a worker after it restored a hook file and before its answer is
// accepted. The guardian then proves the restore from the file itself.

// The watch loop's manifest event cancels a subprocess after its file write.
// A subsequent clean pass cannot recover the missing accounting.
func TestStandaloneWatchCountsRestoreWhenEventKillsWorkerBeforeItAnswers(t *testing.T) {
	const script = "#!/bin/sh\nexec defenseclaw-hook\n"
	path, log, _ := startGAP0754RealGuardian(t, filepath.Join(".defenseclaw", "hooks", "hermes-hook.sh"), script, "")
	logStart := len(log.String())
	wrote := make(chan struct{})
	var first atomic.Bool
	enterpriseHookWorkerRunner = func(ctx context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		if body, err := os.ReadFile(path); err == nil && string(body) != script && !first.Swap(true) {
			if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
				return enterpriseHookWorkerResponse{}, err
			}
			close(wrote)
			<-ctx.Done()
			return enterpriseHookWorkerResponse{}, ctx.Err()
		}
		response := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{
				Index: target.Index, OK: true,
				Result: &enterprisehooks.InstallResult{Connector: target.Options.ConnectorName, UserHome: target.Options.UserHome},
			})
		}
		return response, nil
	}
	if err := os.WriteFile(path, []byte(script+"#\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wrote:
	case <-time.After(6 * time.Second):
		t.Fatalf("worker did not start repair: %s", log.String())
	}
	manifest, err := os.ReadFile(enterpriseHookManifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(enterpriseHookManifest, append(manifest, []byte("\n# preempt subprocess\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(6 * time.Second)
	for !strings.Contains(log.String()[logStart:], "reconcile reason=fsnotify status=ok") {
		select {
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			t.Fatalf("watch loop did not replay: %s", log.String())
		}
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != script {
		t.Fatalf("file was not restored: %q, %v", body, err)
	}
	if !strings.Contains(log.String()[logStart:], "repairs=1") {
		t.Fatalf("restored file was never counted by interrupted or replay pass: %s", log.String())
	}
}

// A second event can cancel a real subprocess after it restores a file but
// before its answer is accepted. runEnterpriseHookWorker returns no response
// on ctx.Err() in that interval. This seam models that documented behavior.
func TestStandaloneInterruptedPassCountsRestoreWhenWorkerAnswerIsLost(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{}}
	f := newStandaloneFixture(t, resolver)
	home := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"})
	f.writeLedger(t, protectedRow("alice", home, "hermes"))
	key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "hermes"})
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{key: {UID: uid, Home: home, LockUpdatedAt: "L", EntryUpdatedAt: "E"}})
	script := filepath.Join(home, ".defenseclaw", "hooks", "hermes-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("tampered\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	interrupt, cancel := context.WithCancel(context.Background())
	defer cancel()
	previousRunner := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = previousRunner })
	enterpriseHookWorkerRunner = func(ctx context.Context, _ enterpriseHookWorkerAccount, _ enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		if err := os.WriteFile(script, []byte("#!/bin/sh\nexec defenseclaw-hook\n"), 0o700); err != nil {
			return enterpriseHookWorkerResponse{}, err
		}
		cancel() // an independent owned-file or manifest event preempts now
		<-ctx.Done()
		return enterpriseHookWorkerResponse{}, ctx.Err() // real subprocess runner also discards its response
	}
	run, err := runEnterpriseHookReconcileOnce(interrupt)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted pass error = %v", err)
	}
	if body, err := os.ReadFile(script); err != nil || string(body) != "#!/bin/sh\nexec defenseclaw-hook\n" {
		t.Fatalf("worker did not restore the script: %q, %v", body, err)
	}
	if run.Repairs != 1 {
		t.Fatalf("repaired file with discarded worker response: repairs=%d, want 1", run.Repairs)
	}
}

// The guardian proves a lost restore only from the file: a target whose file
// is restored to the content the guardian last recorded counts; a file an event
// just tampered with, a file left as it was and a worker that wrote nothing
// do not.
func TestStandaloneInterruptedPassLostAnswerCountsOnlyProvenRestores(t *testing.T) {
	const good = "#!/bin/sh\nexec defenseclaw-hook\n"
	for _, tc := range []struct {
		name    string
		record  bool   // the guardian recorded the good file at its last pass
		before  string // file when the pass begins; empty removes it
		during  string // what the killed worker or an event left; empty writes nothing
		repairs int
	}{
		{"restored tampered file with record", true, "tampered\n", good, 1},
		{"restored deleted file with record", true, "", good, 1},
		{"restored tampered file without record", false, "tampered\n", good, 1},
		{"tamper event during the pass with record", true, good + "#\n", "evil\n", 0},
		{"tamper event replaces a good file", true, good, "evil\n", 0},
		{"worker wrote nothing", true, "tampered\n", "", 0},
		{"file already in order", true, good, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid, gid := os.Getuid(), os.Getgid()
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{}}
			f := newStandaloneFixture(t, resolver)
			home := f.home(t, "alice", 0o700)
			resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}
			f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"})
			f.writeLedger(t, protectedRow("alice", home, "hermes"))
			key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "hermes"})
			f.writeBindings(t, map[string]enterpriseHookUnixBinding{key: {UID: uid, Home: home, LockUpdatedAt: "L", EntryUpdatedAt: "E"}})
			script := filepath.Join(home, ".defenseclaw", "hooks", "hermes-hook.sh")
			if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.record {
				if err := os.WriteFile(script, []byte(good), 0o700); err != nil {
					t.Fatal(err)
				}
				rows := []enterpriseHookReconcileRow{{User: "alice", Connector: "hermes", OK: true}}
				if err := writeEnterpriseHookGuardianOwnedFiles(io.Discard, f.dataDir, rows, map[int]int{0: uid}, map[int][]string{0: {script}}); err != nil {
					t.Fatal(err)
				}
			}
			_ = os.Remove(script)
			if tc.before != "" {
				if err := os.WriteFile(script, []byte(tc.before), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			interrupt, cancel := context.WithCancel(context.Background())
			defer cancel()
			previousRunner := enterpriseHookWorkerRunner
			t.Cleanup(func() { enterpriseHookWorkerRunner = previousRunner })
			enterpriseHookWorkerRunner = func(ctx context.Context, _ enterpriseHookWorkerAccount, _ enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				if tc.during != "" {
					if err := os.WriteFile(script, []byte(tc.during), 0o700); err != nil {
						return enterpriseHookWorkerResponse{}, err
					}
				}
				cancel()
				<-ctx.Done()
				return enterpriseHookWorkerResponse{}, ctx.Err()
			}
			run, err := runEnterpriseHookReconcileOnce(interrupt)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("interrupted pass error = %v", err)
			}
			if run.Repairs != tc.repairs || len(run.RepairedTargets) != tc.repairs {
				t.Fatalf("repairs = %d (%v), want %d", run.Repairs, run.RepairedTargets, tc.repairs)
			}
			restores := guardianRestoresForTest(t, f.dataDir)
			if len(restores) != tc.repairs {
				t.Fatalf("restore entries = %v, want %d", restores, tc.repairs)
			}
		})
	}
}
