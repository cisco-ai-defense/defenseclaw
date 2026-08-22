// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func requireProtectedSetupSelectionHost(t *testing.T) {
	t.Helper()
	if !RequiresProtectedSetupAgentSelection("codex") {
		t.Skip("host does not require protected Codex setup selection")
	}
}

func writeSetupSelectionExecutable(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatalf("write setup-selected executable: %v", err)
	}
	return path
}

func TestSetupSelectedAgentExecutableEvidenceEnforcesSizeBounds(t *testing.T) {
	for _, test := range []struct {
		name string
		size int64
	}{
		{name: "empty", size: 0},
		{name: "oversize", size: setupAgentExecutableMaxBytes + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o700)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(test.size); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, _, ok := setupSelectedAgentExecutableEvidence(path); ok {
				t.Fatalf("setupSelectedAgentExecutableEvidence accepted %d-byte file", test.size)
			}
		})
	}
}

func TestProtectedStateLeafValidationIsDarwinScoped(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Darwin validates the real leaf")
	}
	if err := validateProtectedStateFileLeaf(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("non-Darwin leaf validation changed existing owner semantics: %v", err)
	}
}

func publishCodexSetupSelection(t *testing.T, dataDir, executable string) *SetupAgentSelectionPublication {
	t.Helper()
	publication, err := PublishSetupAgentSelection(dataDir, "codex", executable, "codex-cli 0.142.0")
	if err != nil {
		t.Fatalf("PublishSetupAgentSelection: %v", err)
	}
	return publication
}

func writeProtectedSelectionLock(
	t *testing.T,
	dataDir string,
	selection agentSelectionEvidence,
	executable, digest string,
) {
	t.Helper()
	resolution := ResolveHookContract(selection.Connector, selection.RawVersion)
	entry := HookContractLockEntry{
		Connector:              selection.Connector,
		RawAgentVersion:        selection.RawVersion,
		NormalizedAgentVersion: selection.NormalizedVersion,
		CompatibilityStatus:    resolution.Status,
		ContractID:             resolution.Contract.ContractID,
		AgentExecutable:        executable,
		AgentExecutableSource:  "setup-selected",
		AgentExecutableSHA256:  digest,
		UpdatedAt:              time.Now().UTC().Format(time.RFC3339Nano),
	}
	lock := hookContractLock{
		Version:    hookContractLockVersion,
		UpdatedAt:  entry.UpdatedAt,
		Connectors: map[string]HookContractLockEntry{selection.Connector: entry},
	}
	body, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(filepath.Join(dataDir, hookContractLockFile), append(body, '\n')); err != nil {
		t.Fatalf("write protected hook lock: %v", err)
	}
}

func TestPublishSetupAgentSelectionRollbackRestoresTrueAbsenceAndFinalizesOnce(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	dataDir := testenv.PrivateTempDir(t)
	executable := writeSetupSelectionExecutable(t, t.TempDir(), "codex", "first executable")
	publication := publishCodexSetupSelection(t, dataDir, executable)
	receiptPath := filepath.Join(dataDir, agentSelectionFile)
	if _, err := os.Lstat(receiptPath); err != nil {
		t.Fatalf("published receipt missing: %v", err)
	}

	if err := publication.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, err := os.Lstat(receiptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt exists after absent-state rollback: %v", err)
	}
	if err := publication.Rollback(); err != nil {
		t.Fatalf("second Rollback: %v", err)
	}
	if err := publication.Consume(); err == nil || !strings.Contains(err.Error(), "already finalized by rollback") {
		t.Fatalf("Consume after Rollback error = %v, want opposite-finalization refusal", err)
	}
}

func TestPublishSetupAgentSelectionRollbackRestoresExactPriorBytes(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	dataDir := testenv.PrivateTempDir(t)
	executableDir := t.TempDir()
	first := publishCodexSetupSelection(t, dataDir, writeSetupSelectionExecutable(t, executableDir, "codex-first", "first"))
	receiptPath := filepath.Join(dataDir, agentSelectionFile)
	prior, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	second := publishCodexSetupSelection(t, dataDir, writeSetupSelectionExecutable(t, executableDir, "codex-second", "second"))
	if err := second.Rollback(); err != nil {
		t.Fatalf("second Rollback: %v", err)
	}
	restored, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(prior) {
		t.Fatalf("rollback did not restore exact prior bytes\n got: %s\nwant: %s", restored, prior)
	}
	if err := first.Rollback(); err != nil {
		t.Fatalf("first Rollback: %v", err)
	}
}

func TestPublishSetupAgentSelectionRejectsWhitespaceConnectorKeyWithoutMutation(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	dataDir := testenv.PrivateTempDir(t)
	if err := safefile.ProtectDirectory(dataDir); err != nil {
		t.Fatal(err)
	}
	before := []byte(`{"schema_version":1,"updated_at":"2026-08-22T00:00:00Z","selections":{" codex ":{}}}` + "\n")
	receiptPath := filepath.Join(dataDir, agentSelectionFile)
	if err := safefile.WritePrivate(receiptPath, before); err != nil {
		t.Fatal(err)
	}
	executable := writeSetupSelectionExecutable(t, t.TempDir(), "codex", "codex")
	if _, err := PublishSetupAgentSelection(dataDir, "codex", executable, "codex-cli 0.142.0"); err == nil ||
		!strings.Contains(err.Error(), "non-canonical connector key") {
		t.Fatalf("PublishSetupAgentSelection error = %v, want whitespace-key refusal", err)
	}
	after, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("rejected receipt was mutated: got %q want %q", after, before)
	}
}

func TestLoadProtectedHookContractLockEntriesRejectsNonCanonicalIdentity(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	if err := safefile.ProtectDirectory(dataDir); err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{
		[]byte(`{"version":2,"updated_at":"2026-08-22T00:00:00Z","connectors":{" codex ":{"connector":"codex"}}}` + "\n"),
		[]byte(`{"version":2,"updated_at":"2026-08-22T00:00:00Z","connectors":{"codex":{"connector":" CODEX "}}}` + "\n"),
	} {
		if err := safefile.WritePrivate(filepath.Join(dataDir, hookContractLockFile), body); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadProtectedHookContractLockEntries(dataDir); err == nil {
			t.Fatalf("LoadProtectedHookContractLockEntries accepted non-canonical lock: %s", body)
		}
	}
}

func TestSetupAgentSelectionFinalizationPreservesPeerAndRejectsChangedSelection(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	dataDir := testenv.PrivateTempDir(t)
	executableDir := t.TempDir()
	first := publishCodexSetupSelection(t, dataDir, writeSetupSelectionExecutable(t, executableDir, "codex-first", "first"))
	second := publishCodexSetupSelection(t, dataDir, writeSetupSelectionExecutable(t, executableDir, "codex-second", "second"))
	if err := first.Rollback(); err == nil || !strings.Contains(err.Error(), "changed before finalization") {
		t.Fatalf("stale Rollback error = %v, want changed-selection refusal", err)
	}
	selected, ok := loadSetupAgentSelection(dataDir, "codex")
	if !ok || selected != second.publishedSelection {
		t.Fatalf("stale rollback changed newer selection: got %+v valid=%t", selected, ok)
	}
	if err := second.Rollback(); err != nil {
		t.Fatalf("newer Rollback: %v", err)
	}
	if err := first.Rollback(); err != nil {
		t.Fatalf("older Rollback after restoration: %v", err)
	}
}

func publishPeerSetupSelection(t *testing.T, dataDir, executable string) *SetupAgentSelectionPublication {
	t.Helper()
	name, version := protectedPeerSetupSelectionIdentity()
	publication, err := PublishSetupAgentSelection(dataDir, name, executable, version)
	if err != nil {
		t.Fatalf("PublishSetupAgentSelection(%s): %v", name, err)
	}
	return publication
}

func protectedPeerSetupSelectionIdentity() (string, string) {
	if runtime.GOOS == "darwin" {
		return "claudecode", "2.1.219 (Claude Code)"
	}
	return "amp", "0.0.1785334225"
}

func TestSetupAgentSelectionRollbackAndConsumePreservePeerConnector(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	for _, consume := range []bool{false, true} {
		name := "rollback"
		if consume {
			name = "consume"
		}
		t.Run(name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			executableDir := t.TempDir()
			primary := publishCodexSetupSelection(t, dataDir, writeSetupSelectionExecutable(t, executableDir, "codex", "codex"))
			peer := publishPeerSetupSelection(t, dataDir, writeSetupSelectionExecutable(t, executableDir, "peer", "peer"))
			if consume {
				writeProtectedSelectionLock(
					t,
					dataDir,
					primary.publishedSelection,
					primary.publishedSelection.Executable,
					primary.publishedSelection.SHA256,
				)
				if err := primary.Consume(); err != nil {
					t.Fatalf("Consume: %v", err)
				}
			} else if err := primary.Rollback(); err != nil {
				t.Fatalf("Rollback: %v", err)
			}
			selected, ok := loadSetupAgentSelection(dataDir, peer.connectorName)
			if !ok || selected != peer.publishedSelection {
				t.Fatalf("peer selection changed: got %+v valid=%t want %+v", selected, ok, peer.publishedSelection)
			}
			if err := peer.Rollback(); err != nil {
				t.Fatalf("peer Rollback: %v", err)
			}
		})
	}
}

func TestSetupAgentSelectionRollbackDropsThenRestoresExpiredPeer(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	dataDir := testenv.PrivateTempDir(t)
	if err := safefile.ProtectDirectory(dataDir); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	peerName, peerVersion := protectedPeerSetupSelectionIdentity()
	peerResolution := ResolveHookContract(peerName, peerVersion)
	if peerResolution.Status != HookCompatibilityKnown {
		t.Fatalf("peer contract resolution = %s (%s), want known", peerResolution.Status, peerResolution.Reason)
	}
	expired := agentSelectionEvidence{
		Connector:         peerName,
		Source:            "setup-selected",
		Executable:        filepath.Join(t.TempDir(), peerName),
		RawVersion:        peerResolution.RawVersion,
		NormalizedVersion: peerResolution.NormalizedVersion,
		SHA256:            strings.Repeat("a", 64),
		SelectedAt:        now.Add(-2 * agentSelectionMaxLifetime).Format(time.RFC3339),
		ExpiresAt:         now.Add(-agentSelectionMaxLifetime).Format(time.RFC3339),
	}
	priorReceipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     now.Add(-agentSelectionMaxLifetime).Format(time.RFC3339),
		Selections:    map[string]agentSelectionEvidence{peerName: expired},
	}
	prior, err := marshalSetupAgentSelectionReceipt(priorReceipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(dataDir, agentSelectionFile)
	if err := safefile.WritePrivate(receiptPath, prior); err != nil {
		t.Fatal(err)
	}
	publication := publishCodexSetupSelection(t, dataDir, writeSetupSelectionExecutable(t, t.TempDir(), "codex", "codex"))
	published, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(published), `"`+peerName+`"`) {
		t.Fatalf("published receipt retained expired peer: %s", published)
	}
	if err := publication.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	restored, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(prior) {
		t.Fatalf("rollback did not restore expired prior bytes exactly\n got: %s\nwant: %s", restored, prior)
	}
}

func rejectProtectedStateLeafForTest(t *testing.T, path string) func() {
	t.Helper()
	previous := validateProtectedStateFileLeaf
	restored := false
	validateProtectedStateFileLeaf = func(candidate string) error {
		if filepath.Clean(candidate) == filepath.Clean(path) {
			return errors.New("synthetic unsafe leaf ACL")
		}
		return previous(candidate)
	}
	restore := func() {
		if restored {
			return
		}
		validateProtectedStateFileLeaf = previous
		restored = true
	}
	t.Cleanup(restore)
	return restore
}

func TestSetupAgentSelectionRejectsUnsafeExistingReceiptLeafWithoutMutation(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	for _, operation := range []string{"publish", "finalize"} {
		t.Run(operation, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			executableDir := t.TempDir()
			publication := publishCodexSetupSelection(
				t,
				dataDir,
				writeSetupSelectionExecutable(t, executableDir, "codex-first", "first"),
			)
			receiptPath := filepath.Join(dataDir, agentSelectionFile)
			before, err := os.ReadFile(receiptPath)
			if err != nil {
				t.Fatal(err)
			}
			restore := rejectProtectedStateLeafForTest(t, receiptPath)

			switch operation {
			case "publish":
				_, err = PublishSetupAgentSelection(
					dataDir,
					"codex",
					writeSetupSelectionExecutable(t, executableDir, "codex-second", "second"),
					"codex-cli 0.142.0",
				)
			case "finalize":
				err = publication.Rollback()
			}
			if err == nil || !strings.Contains(err.Error(), "synthetic unsafe leaf ACL") {
				t.Fatalf("%s error = %v, want unsafe-leaf refusal", operation, err)
			}
			after, readErr := os.ReadFile(receiptPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(after) != string(before) {
				t.Fatalf("%s mutated rejected receipt: got %q want %q", operation, after, before)
			}

			restore()
			if err := publication.Rollback(); err != nil {
				t.Fatalf("Rollback after restoring leaf validator: %v", err)
			}
		})
	}
}

func TestProtectedLockReadersRejectUnsafeLeafAndConsumePreservesReceipt(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	dataDir := testenv.PrivateTempDir(t)
	executable := writeSetupSelectionExecutable(t, t.TempDir(), "codex", "codex")
	publication := publishCodexSetupSelection(t, dataDir, executable)
	writeProtectedSelectionLock(
		t,
		dataDir,
		publication.publishedSelection,
		publication.publishedSelection.Executable,
		publication.publishedSelection.SHA256,
	)
	lockPath := filepath.Join(dataDir, hookContractLockFile)
	restore := rejectProtectedStateLeafForTest(t, lockPath)

	if _, err := LoadProtectedHookContractLockEntries(dataDir); err == nil ||
		!strings.Contains(err.Error(), "synthetic unsafe leaf ACL") {
		t.Fatalf("LoadProtectedHookContractLockEntries error = %v, want unsafe-leaf refusal", err)
	}
	if err := publication.Consume(); err == nil || !strings.Contains(err.Error(), "synthetic unsafe leaf ACL") {
		t.Fatalf("Consume error = %v, want unsafe-lock-leaf refusal", err)
	}
	if _, ok := loadSetupAgentSelection(dataDir, "codex"); !ok {
		t.Fatal("failed Consume removed the setup selection receipt")
	}

	restore()
	if err := publication.Consume(); err != nil {
		t.Fatalf("Consume after restoring leaf validator: %v", err)
	}
}

func TestDarwinProtectedCacheReadersRejectUnsafeAuthorityLeaves(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin protected-state leaf ACL authority")
	}
	dataDir := testenv.PrivateTempDir(t)
	executable := writeSetupSelectionExecutable(t, t.TempDir(), "codex", "codex")
	publication := publishCodexSetupSelection(t, dataDir, executable)
	receiptPath := filepath.Join(dataDir, agentSelectionFile)
	restoreReceipt := rejectProtectedStateLeafForTest(t, receiptPath)
	if _, ok := loadSetupAgentSelection(dataDir, "codex"); ok {
		t.Fatal("loadSetupAgentSelection accepted an unsafe receipt leaf")
	}
	restoreReceipt()

	writeProtectedSelectionLock(
		t,
		dataDir,
		publication.publishedSelection,
		publication.publishedSelection.Executable,
		publication.publishedSelection.SHA256,
	)
	if err := os.Remove(receiptPath); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dataDir, hookContractLockFile)
	restoreLock := rejectProtectedStateLeafForTest(t, lockPath)
	if got := LoadCachedAgentVersion(dataDir, "codex"); got != "" {
		t.Fatalf("unsafe-lock cached version = %q, want empty", got)
	}
	if got := LoadCachedAgentExecutable(dataDir, "codex"); got != "" {
		t.Fatalf("unsafe-lock cached executable = %q, want empty", got)
	}
	restoreLock()
}

func TestConsumeSetupAgentSelectionRequiresExactDurableLock(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	dataDir := testenv.PrivateTempDir(t)
	executable := writeSetupSelectionExecutable(t, t.TempDir(), "codex", "codex")
	publication := publishCodexSetupSelection(t, dataDir, executable)

	if err := publication.Consume(); err == nil || !strings.Contains(err.Error(), "exact executable identity") {
		t.Fatalf("Consume without lock error = %v, want exact-lock refusal", err)
	}
	writeProtectedSelectionLock(t, dataDir, publication.publishedSelection, executable, strings.Repeat("f", 64))
	if err := publication.Consume(); err == nil || !strings.Contains(err.Error(), "exact executable identity") {
		t.Fatalf("Consume with mismatched lock error = %v, want exact-lock refusal", err)
	}
	writeProtectedSelectionLock(
		t,
		dataDir,
		publication.publishedSelection,
		publication.publishedSelection.Executable,
		publication.publishedSelection.SHA256,
	)
	if err := publication.Consume(); err != nil {
		t.Fatalf("Consume with exact lock: %v", err)
	}
	if err := publication.Consume(); err != nil {
		t.Fatalf("second Consume: %v", err)
	}
	if err := publication.Rollback(); err == nil || !strings.Contains(err.Error(), "already finalized by consume") {
		t.Fatalf("Rollback after Consume error = %v, want opposite-finalization refusal", err)
	}
}

func TestConsumeSetupAgentSelectionRejectsExecutableSwapOrDisappearance(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	for _, test := range []struct {
		name       string
		mutate     func(t *testing.T, executable string)
		lockDigest func(t *testing.T, executable string) (string, string)
	}{
		{
			name: "swapped",
			mutate: func(t *testing.T, executable string) {
				t.Helper()
				if err := os.Remove(executable); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(executable, []byte("replacement"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			lockDigest: func(t *testing.T, executable string) (string, string) {
				t.Helper()
				path, digest, ok := setupSelectedAgentExecutableEvidence(executable)
				if !ok {
					t.Fatal("replacement executable has no stable evidence")
				}
				return path, digest
			},
		},
		{
			name: "disappeared",
			mutate: func(t *testing.T, executable string) {
				t.Helper()
				if err := os.Remove(executable); err != nil {
					t.Fatal(err)
				}
			},
			lockDigest: func(*testing.T, string) (string, string) { return "", "" },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			executable := writeSetupSelectionExecutable(t, t.TempDir(), "codex", "original")
			publication := publishCodexSetupSelection(t, dataDir, executable)
			test.mutate(t, executable)
			lockPath, lockDigest := test.lockDigest(t, executable)
			writeProtectedSelectionLock(t, dataDir, publication.publishedSelection, lockPath, lockDigest)
			if err := publication.Consume(); err == nil || !strings.Contains(err.Error(), "exact executable identity") {
				t.Fatalf("Consume error = %v, want changed-executable refusal", err)
			}
			if _, ok := loadSetupAgentSelection(dataDir, "codex"); !ok {
				t.Fatal("failed Consume removed the setup selection receipt")
			}
		})
	}
}

func TestSetupAgentSelectionPersistentLockSerializesInProcess(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	dataDir := testenv.PrivateTempDir(t)
	if err := safefile.ProtectDirectory(dataDir); err != nil {
		t.Fatal(err)
	}
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- withSetupAgentSelectionLock(dataDir, func() error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()
	select {
	case <-firstEntered:
	case err := <-firstDone:
		t.Fatalf("first lock failed before entering callback: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first setup selection transaction did not enter")
	}
	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- withSetupAgentSelectionLock(dataDir, func() error {
			close(secondEntered)
			return nil
		})
	}()
	select {
	case <-secondEntered:
		t.Fatal("second setup selection transaction entered while first held the persistent lock")
	case err := <-secondDone:
		t.Fatalf("second lock failed while waiting: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first lock: %v", err)
	}
	select {
	case <-secondEntered:
	case err := <-secondDone:
		t.Fatalf("second lock failed before entering callback: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("second setup selection transaction did not enter after release")
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second lock: %v", err)
	}
	lockInfo, err := os.Lstat(filepath.Join(dataDir, agentSelectionFile+".lock"))
	if err != nil || !lockInfo.Mode().IsRegular() {
		t.Fatalf("persistent lock was removed or replaced: info=%v err=%v", lockInfo, err)
	}
	if runtime.GOOS != "windows" && lockInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("persistent lock mode = %#o, want private", lockInfo.Mode().Perm())
	}
}

func TestPrepareProtectedSetupTransactionDoesNotWaitForHeldLease(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("protected enterprise transaction is a Darwin contract")
	}
	requireProtectedSetupSelectionHost(t)
	dataDir := testenv.PrivateTempDir(t)
	if err := safefile.ProtectDirectory(dataDir); err != nil {
		t.Fatal(err)
	}
	first, err := PrepareProtectedSetupAgentSelectionTransaction(dataDir, "codex")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Acquire(); err != nil {
		t.Fatal(err)
	}
	defer first.Release() //nolint:errcheck // failure-path cleanup

	prepared := make(chan *ProtectedSetupAgentSelectionTransaction, 1)
	prepareErr := make(chan error, 1)
	go func() {
		second, err := PrepareProtectedSetupAgentSelectionTransaction(dataDir, "codex")
		if err != nil {
			prepareErr <- err
			return
		}
		prepared <- second
	}()
	var second *ProtectedSetupAgentSelectionTransaction
	select {
	case second = <-prepared:
	case err := <-prepareErr:
		t.Fatalf("prepare second lease: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("nonblocking Prepare waited on the held transaction")
	}
	defer second.Release() //nolint:errcheck // failure-path cleanup
	acquired := make(chan error, 1)
	go func() { acquired <- second.Acquire() }()
	select {
	case err := <-acquired:
		t.Fatalf("second Acquire completed while first held lease: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second Acquire did not complete after first Release")
	}
}

func TestPublishSetupAgentSelectionAmbiguousCommitRestoresExactPredecessor(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	for _, priorExists := range []bool{false, true} {
		name := "prior absent"
		if priorExists {
			name = "prior exact bytes"
		}
		t.Run(name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			priorExecutable := writeSetupSelectionExecutable(t, t.TempDir(), "codex", "prior")
			var priorPublication *SetupAgentSelectionPublication
			var priorBody []byte
			if priorExists {
				priorPublication = publishCodexSetupSelection(t, dataDir, priorExecutable)
				var err error
				priorBody, err = os.ReadFile(filepath.Join(dataDir, agentSelectionFile))
				if err != nil {
					t.Fatal(err)
				}
			}
			executable := writeSetupSelectionExecutable(t, t.TempDir(), "codex", "replacement")
			original := transformSetupAgentSelectionFile
			calls := 0
			injected := errors.New("injected post-rename directory sync failure")
			transformSetupAgentSelectionFile = func(
				path, stateDir string,
				perm os.FileMode,
				transform func([]byte, bool) (atomicTransformResult, error),
			) error {
				calls++
				err := original(path, stateDir, perm, transform)
				if calls == 1 && err == nil {
					return injected
				}
				return err
			}
			t.Cleanup(func() { transformSetupAgentSelectionFile = original })

			publication, err := PublishSetupAgentSelection(dataDir, "codex", executable, "codex-cli 0.142.0")
			if publication != nil || !errors.Is(err, injected) {
				t.Fatalf("ambiguous publication = (%v, %v), want nil/sentinel", publication, err)
			}
			path := filepath.Join(dataDir, agentSelectionFile)
			if priorExists {
				body, readErr := os.ReadFile(path)
				if readErr != nil || !bytes.Equal(body, priorBody) {
					t.Fatalf("prior bytes not restored: err=%v got=%q want=%q", readErr, body, priorBody)
				}
				if err := priorPublication.Rollback(); err != nil {
					t.Fatal(err)
				}
			} else if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("prior absence not restored: %v", statErr)
			}
		})
	}
}

func TestConsumeSetupAgentSelectionAmbiguousCommitRestoresExactPredecessor(t *testing.T) {
	requireProtectedSetupSelectionHost(t)
	dataDir := testenv.PrivateTempDir(t)
	priorExecutable := writeSetupSelectionExecutable(t, t.TempDir(), "codex", "prior")
	priorPublication := publishCodexSetupSelection(t, dataDir, priorExecutable)
	priorBody, err := os.ReadFile(filepath.Join(dataDir, agentSelectionFile))
	if err != nil {
		t.Fatal(err)
	}
	executable := writeSetupSelectionExecutable(t, t.TempDir(), "codex", "replacement")
	publication := publishCodexSetupSelection(t, dataDir, executable)
	writeProtectedSelectionLock(
		t,
		dataDir,
		publication.publishedSelection,
		publication.publishedSelection.Executable,
		publication.publishedSelection.SHA256,
	)

	original := transformSetupAgentSelectionFile
	calls := 0
	injected := errors.New("injected post-remove directory sync failure")
	transformSetupAgentSelectionFile = func(
		path, stateDir string,
		perm os.FileMode,
		transform func([]byte, bool) (atomicTransformResult, error),
	) error {
		calls++
		err := original(path, stateDir, perm, transform)
		if calls == 1 && err == nil {
			return injected
		}
		return err
	}
	t.Cleanup(func() { transformSetupAgentSelectionFile = original })

	if err := publication.Consume(); !errors.Is(err, injected) {
		t.Fatalf("ambiguous Consume error = %v", err)
	}
	if publication.Consumed() {
		t.Fatal("ambiguous Consume was marked committed")
	}
	body, err := os.ReadFile(filepath.Join(dataDir, agentSelectionFile))
	if err != nil || !bytes.Equal(body, priorBody) {
		t.Fatalf("prior receipt not restored: err=%v got=%q want=%q", err, body, priorBody)
	}
	if err := publication.Rollback(); err != nil {
		t.Fatalf("idempotent rollback after ambiguous Consume: %v", err)
	}
	if err := priorPublication.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedSetupAgentSelectionTransactionSerializesAcrossProcesses(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("protected enterprise transaction is a Darwin contract")
	}
	if os.Getenv("DEFENSECLAW_SETUP_TRANSACTION_CHILD") == "1" {
		dataDir := os.Getenv("DEFENSECLAW_SETUP_TRANSACTION_DATA_DIR")
		entered := filepath.Join(dataDir, "child-entered")
		release := filepath.Join(dataDir, "release-child")
		err := WithProtectedSetupAgentSelectionTransaction(dataDir, "codex", func() error {
			if err := os.WriteFile(entered, []byte("entered"), 0o600); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for {
				if _, err := os.Lstat(release); err == nil {
					return nil
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(10 * time.Millisecond):
				}
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		return
	}

	dataDir := testenv.PrivateTempDir(t)
	if err := safefile.ProtectDirectory(dataDir); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestProtectedSetupAgentSelectionTransactionSerializesAcrossProcesses$")
	command.Env = append(os.Environ(),
		"DEFENSECLAW_SETUP_TRANSACTION_CHILD=1",
		"DEFENSECLAW_SETUP_TRANSACTION_DATA_DIR="+dataDir,
	)
	var childOutput bytes.Buffer
	command.Stdout = &childOutput
	command.Stderr = &childOutput
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Process.Kill() //nolint:errcheck // best-effort cleanup after test failures
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Lstat(filepath.Join(dataDir, "child-entered")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child did not acquire transaction lock: %s", childOutput.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- WithProtectedSetupAgentSelectionTransaction(dataDir, "codex", func() error {
			close(secondEntered)
			return nil
		})
	}()
	select {
	case <-secondEntered:
		t.Fatal("second process transaction entered while child held the persistent lock")
	case err := <-secondDone:
		t.Fatalf("second transaction failed while waiting: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := os.WriteFile(filepath.Join(dataDir, "release-child"), []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("child transaction: %v\n%s", err, childOutput.String())
	}
	select {
	case <-secondEntered:
	case err := <-secondDone:
		t.Fatalf("second transaction failed after release: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("second transaction did not enter after child release")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}
