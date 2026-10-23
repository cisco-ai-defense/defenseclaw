// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/google/uuid"
)

// setPendingHookFileOps replaces the pending spool's file operations for one
// test. A nil operation keeps the real one.
func setPendingHookFileOps(t *testing.T, ops pendingHookFileOps) {
	t.Helper()
	if ops.syncDir == nil {
		ops.syncDir = syncDaemonDir
	}
	if ops.validate == nil {
		ops.validate = safefile.ValidatePrivateFile
	}
	if ops.read == nil {
		ops.read = safefile.ReadRegularFileBounded
	}
	pendingHookFileOpsOverride.Store(&ops)
	t.Cleanup(func() { pendingHookFileOpsOverride.Store(nil) })
}

var pendingAllow = agentHookResponse{Action: "allow", Mode: "action", Severity: "NONE"}

func beginPendingAllow(t *testing.T, api *APIServer, session string) (*pendingHookOccurrence, error) {
	t.Helper()
	req := agentHookRequest{
		ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: session,
		ToolName: "Bash", ToolInvocationID: session + "-tool",
	}
	return api.beginPendingHookOccurrence(t.Context(), req, pendingAllow, nil, 64, time.Millisecond, false, nil)
}

// pendingFile returns the path and bytes of the one occurrence in dir.
func pendingFile(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Error(err)
		return "", nil
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				t.Error(err)
			}
			return path, data
		}
	}
	t.Error("no pending occurrence on disk")
	return "", nil
}

// An occurrence is the only record of an offered answer until its terminal
// audit lands, so the directory that holds it must survive a power loss
// before the answer is offered: the parent of every directory the write
// creates is synced, again when the directory is created anew while the
// gateway runs, and a parent that cannot be synced means no answer is
// offered. Before, only the new directory itself was synced.
func TestPendingHookNewDirectoryIsDurableBeforeTheAnswer(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	var mu sync.Mutex
	var synced []string
	var failing atomic.Value
	setPendingHookFileOps(t, pendingHookFileOps{syncDir: func(dir string) error {
		mu.Lock()
		synced = append(synced, dir)
		mu.Unlock()
		if failed, _ := failing.Load().(string); failed == dir {
			return errors.New("directory sync failed by the test")
		}
		return syncDaemonDir(dir)
	}})
	take := func() []string {
		mu.Lock()
		defer mu.Unlock()
		got := synced
		synced = nil
		return got
	}
	begin := func(session string) {
		t.Helper()
		p, err := beginPendingAllow(t, f.api, session)
		if err != nil {
			t.Fatal(err)
		}
		p.release()
	}
	dataDir := f.api.scannerCfg.DataDir
	dir := filepath.Join(dataDir, pendingHookDirName)

	begin("dir-first")
	if got := take(); !slices.Contains(got, dir) || !slices.Contains(got, dataDir) {
		t.Fatalf("first occurrence synced %v, want its new directory and that directory's parent %s", got, dataDir)
	}
	begin("dir-existing")
	if got := take(); !slices.Contains(got, dir) || slices.Contains(got, dataDir) {
		t.Fatalf("occurrence in a durable directory synced %v, want only its directory", got)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	begin("dir-recreated")
	if got := take(); !slices.Contains(got, dataDir) {
		t.Fatalf("occurrence in a directory created again synced %v, want its parent %s too", got, dataDir)
	}

	root := t.TempDir()
	nested := filepath.Join(root, "state", "data")
	f.api.scannerCfg.DataDir = nested
	begin("dir-nested")
	if got := take(); !slices.Contains(got, nested) || !slices.Contains(got, filepath.Join(root, "state")) || !slices.Contains(got, root) {
		t.Fatalf("occurrence that created three directories synced %v, want the parent of each", got)
	}

	f.api.scannerCfg.DataDir = dataDir
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	failing.Store(dataDir)
	p, err := beginPendingAllow(t, f.api, "dir-parent-fails")
	if err == nil || p != nil {
		t.Fatalf("begin with an unsyncable parent = %v, %v; want an error and no answer offered", p, err)
	}
	if left := pendingEntries(t, f); len(left) != 0 {
		t.Fatalf("pending occurrences after the refused begin = %v, want none", left)
	}
}

// Recovery quarantines only an occurrence proven invalid or untrusted. One
// it cannot read for an operating-system reason is kept and recovered by a
// later pass. Before, it was renamed .invalid and its audit was lost.
func TestPendingHookRecoveryKeepsAnOccurrenceItCannotReadYet(t *testing.T) {
	for _, tc := range []struct {
		name string
		ops  func(path string) pendingHookFileOps
	}{
		{"too many open files", func(path string) pendingHookFileOps {
			return pendingHookFileOps{read: func(name string, limit int64) ([]byte, error) {
				if name == path {
					return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.EMFILE}
				}
				return safefile.ReadRegularFileBounded(name, limit)
			}}
		}},
		{"i/o error checking its protection", func(path string) pendingHookFileOps {
			return pendingHookFileOps{validate: func(name string) error {
				if name == path {
					return &fs.PathError{Op: "lstat", Path: name, Err: syscall.EIO}
				}
				return safefile.ValidatePrivateFile(name)
			}}
		}},
		{"replaced while it was read", func(path string) pendingHookFileOps {
			return pendingHookFileOps{read: func(name string, limit int64) ([]byte, error) {
				if name == path {
					return nil, fmt.Errorf("safefile: file changed while reading: %s", name)
				}
				return safefile.ReadRegularFileBounded(name, limit)
			}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newManagedHookAuditFixture(t, nil)
			session := "unreadable-" + strings.ReplaceAll(tc.name, " ", "-")
			path := orphanPendingHook(t, f, session)
			setPendingHookFileOps(t, tc.ops(path))
			api := f.restartedAPI(t, true)
			api.recoverPendingHookOccurrences(t.Context(), nil)
			if !pendingPathExists(path) || pendingPathExists(path+pendingHookQuarantineSuffix) {
				t.Fatalf("occurrence kept = %t, quarantined = %t; want it kept for the next pass",
					pendingPathExists(path), pendingPathExists(path+pendingHookQuarantineSuffix))
			}
			if got := f.audited(t, session)[session]; got != "" {
				t.Fatalf("audit written from an unreadable occurrence: %q", got)
			}
			pendingHookFileOpsOverride.Store(nil)
			api.recoverPendingHookOccurrences(t.Context(), nil)
			if got := f.audited(t, session)[session]; got != "unconfirmed/no_answer" {
				t.Fatalf("audit after the read recovered = %q, want unconfirmed/no_answer", got)
			}
			if rows := f.hookRows(t, session); rows != 1 || pendingPathExists(path) {
				t.Fatalf("connector rows = %d, occurrence left = %t; want one row and none", rows, pendingPathExists(path))
			}
		})
	}
	t.Run("too large is still quarantined", func(t *testing.T) {
		f := newManagedHookAuditFixture(t, nil)
		orphanPendingHook(t, f, "oversize-neighbour")
		path := filepath.Join(f.api.scannerCfg.DataDir, pendingHookDirName, uuid.NewString()+".json")
		if err := os.WriteFile(path, make([]byte, maxPendingHookBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		f.restartedAPI(t, true).recoverPendingHookOccurrences(t.Context(), nil)
		if !pendingPathExists(path + pendingHookQuarantineSuffix) {
			t.Fatalf("oversize occurrence not quarantined: %v", pendingEntries(t, f))
		}
	})
}

// A terminal record the live handler already stored is the authority for
// its missing companion, whatever the occurrence file says: the file can be
// older than the record (a final rewrite a crash undid) or newer (a final
// rewrite that was on disk but not synced). Before, recovery wrote the file's
// answer beside a stored record that said something else.
func TestPendingHookRecoveryTakesAStoredRecordAsTheAuthority(t *testing.T) {
	for _, tc := range []struct {
		name         string
		finalAllow   bool
		stored       agentHookResponse
		decisionOnly bool
		want         string
		wantDecision string
	}{
		{"connector row allow, file without the final answer", false, pendingAllow, false, "allow", "allow/ok"},
		{"hook_decision allow, file without the final answer", false, pendingAllow, true, "allow", "allow/ok"},
		{"connector row closed fallback", false, pendingFailureHookDecision(pendingAllow), false, "block/no_answer", "block/ok"},
		{"hook_decision closed fallback", false, pendingFailureHookDecision(pendingAllow), true, "block/no_answer", "block/ok"},
		{"connector row unconfirmed, file with a final allow", true, unconfirmedHookDelivery(pendingAllow), false, "unconfirmed/no_answer", "unconfirmed/ok"},
		{"hook_decision unconfirmed, file with a final allow", true, unconfirmedHookDelivery(pendingAllow), true, "unconfirmed/no_answer", "unconfirmed/ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newManagedHookAuditFixture(t, nil)
			session := "authority-" + strings.NewReplacer(" ", "-", ",", "").Replace(tc.name)
			p, err := beginPendingAllow(t, f.api, session)
			if err != nil {
				t.Fatal(err)
			}
			p.release()
			if tc.finalAllow {
				if published, err := p.setFinal(pendingAllow, time.Millisecond); !published || err != nil {
					t.Fatalf("setFinal = %t, %v", published, err)
				}
			}
			// The live handler's records under the occurrence IDs, one of
			// them refused.
			writer := f.restartedAPI(t, tc.decisionOnly)
			lift := func() {}
			if tc.decisionOnly {
				lift = refuseConnectorHookAuditRows(t, f)
			}
			req := p.Request.request(p.ID, p.BodyBytes)
			req.pendingRecovery = false
			writer.finalizeAgentHook(enrichAgentHookContext(t.Context(), req), req.ConnectorName, req, tc.stored,
				nil, nil, time.Millisecond, false, nil)
			lift()
			stored := len(f.decisions(t)) + f.hookRows(t, session)
			if stored != 1 {
				t.Fatalf("stored records before recovery = %d, want one", stored)
			}

			f.restartedAPI(t, true).recoverPendingHookOccurrences(t.Context(), nil)
			got, decisions := f.audited(t, session)[session], strings.Join(f.decisions(t), ",")
			if got != tc.want || decisions != tc.wantDecision {
				t.Fatalf("records after recovery: connector %q, hook_decision %q; want %q, %q",
					got, decisions, tc.want, tc.wantDecision)
			}
			if rows := f.hookRows(t, session); rows != 1 {
				t.Fatalf("connector rows = %d, want one", rows)
			}
			if left := pendingEntries(t, f); len(left) != 0 {
				t.Fatalf("pending occurrences after recovery = %v, want none", left)
			}
		})
	}
}

// A final answer is durable only once its directory is synced. Before, a
// rewrite that replaced the file but whose sync failed counted as published.
func TestPendingHookFinalAnswerIsDurableOnlyOnceSynced(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	dir := filepath.Join(f.api.scannerCfg.DataDir, pendingHookDirName)
	var failing atomic.Bool
	setPendingHookFileOps(t, pendingHookFileOps{syncDir: func(d string) error {
		if failing.Load() && d == dir {
			return errors.New("directory sync failed by the test")
		}
		return syncDaemonDir(d)
	}})
	p, err := beginPendingAllow(t, f.api, "final-unsynced")
	if err != nil {
		t.Fatal(err)
	}
	defer p.release()
	failing.Store(true)
	published, err := p.setFinal(pendingAllow, time.Millisecond)
	if published || err == nil || p.Final != nil {
		t.Fatalf("setFinal with its directory sync failing = published %t, err %v, final %v; want not published",
			published, err, p.Final)
	}
	failing.Store(false)
	if published, err := p.setFinal(pendingAllow, time.Millisecond); !published || err != nil || p.Final == nil {
		t.Fatalf("setFinal = published %t, err %v, final %v; want published", published, err, p.Final)
	}
}

// When the final rewrite of an acknowledged call is on disk but not synced,
// and the connector row fails, the two records still agree after recovery:
// with the rewrite kept, and with the earlier file a crash brought back.
// Before, the handler counted the rewrite as published and stored an allow
// hook_decision, and recovery from the earlier file wrote an unconfirmed
// connector row beside it.
func TestPendingHookRecordsAgreeWhenAFinalRewriteIsNotDurable(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(map[bool]string{false: "rewrite kept", true: "crash restores the earlier file"}[crash], func(t *testing.T) {
			f := newManagedHookAuditFixture(t, nil)
			session := fmt.Sprintf("final-not-durable-%t", crash)
			dir := filepath.Join(f.api.scannerCfg.DataDir, pendingHookDirName)
			var failing atomic.Bool
			setPendingHookFileOps(t, pendingHookFileOps{syncDir: func(d string) error {
				if failing.Load() && d == dir {
					return errors.New("directory sync failed by the test")
				}
				return syncDaemonDir(d)
			}})
			var earlierPath string
			var earlier []byte
			lift := refuseConnectorHookAuditRows(t, f)
			reply := &onHookConfirmationWriter{ResponseRecorder: httptest.NewRecorder(), confirmed: func() {
				earlierPath, earlier = pendingFile(t, dir)
				failing.Store(true)
			}}
			ackedHookCall(t, f.api, session, reply)
			failing.Store(false)
			lift()
			if !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
				t.Fatalf("gateway response = %q, want the receipt confirmation", reply.Body.String())
			}
			if crash {
				if err := os.WriteFile(earlierPath, earlier, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			f.restartedAPI(t, true).recoverPendingHookOccurrences(t.Context(), nil)
			got, decisions := f.audited(t, session)[session], strings.Join(f.decisions(t), ",")
			if got != "unconfirmed/no_answer" || decisions != "unconfirmed/ok" {
				t.Fatalf("records: connector %q, hook_decision %q; want unconfirmed/no_answer, unconfirmed/ok", got, decisions)
			}
			if left := pendingEntries(t, f); len(left) != 0 {
				t.Fatalf("pending occurrences after recovery = %v, want none", left)
			}
		})
	}
}

// A first write that fails after its rename is answered 503, and the hook
// blocks. When nothing can sync the removal of that file, a crash can bring
// it back; recovery then completes the records of the block, never a second,
// unconfirmed decision. Before, the 503 records had fresh IDs and recovery
// audited the restored file as an unconfirmed call beside them.
func TestPendingHookFailedFirstWriteNeverGetsASecondDecision(t *testing.T) {
	for _, refuseConnector := range []bool{false, true} {
		t.Run(map[bool]string{false: "both records stored", true: "connector row refused"}[refuseConnector], func(t *testing.T) {
			f := newManagedHookAuditFixture(t, nil)
			session := fmt.Sprintf("first-write-fails-%t", refuseConnector)
			dir := filepath.Join(f.api.scannerCfg.DataDir, pendingHookDirName)
			var capturedPath string
			var captured []byte
			var once sync.Once
			setPendingHookFileOps(t, pendingHookFileOps{syncDir: func(d string) error {
				if d != dir {
					return syncDaemonDir(d)
				}
				once.Do(func() { capturedPath, captured = pendingFile(t, dir) })
				return errors.New("directory sync failed by the test")
			}})
			lift := func() {}
			if refuseConnector {
				lift = refuseConnectorHookAuditRows(t, f)
			}
			reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
			ackedHookCall(t, f.api, session, reply)
			lift()
			pendingHookFileOpsOverride.Store(nil)
			if reply.finalStatus != http.StatusServiceUnavailable {
				t.Fatalf("gateway answered %d, want 503", reply.finalStatus)
			}
			if captured == nil {
				t.Fatal("the failed first write left no file to restore")
			}
			// A crash undid every change nothing could sync.
			if err := os.WriteFile(capturedPath, captured, 0o600); err != nil {
				t.Fatal(err)
			}
			f.restartedAPI(t, true).recoverPendingHookOccurrences(t.Context(), nil)
			got, decisions := f.audited(t, session)[session], strings.Join(f.decisions(t), ",")
			if got != "block/no_answer" || decisions != "block/ok" {
				t.Fatalf("records: connector %q, hook_decision %q; want block/no_answer, block/ok", got, decisions)
			}
			if rows := f.hookRows(t, session); rows != 1 {
				t.Fatalf("connector rows = %d, want one", rows)
			}
			if left := pendingEntries(t, f); len(left) != 0 {
				t.Fatalf("pending occurrences after recovery = %v, want none", left)
			}
		})
	}
}
