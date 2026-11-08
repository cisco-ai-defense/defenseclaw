// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// replaceRecord publishes content at path through a new file renamed over it,
// the way the guardian replaces its records.
func replaceRecord(t *testing.T, path string, content []byte) {
	t.Helper()
	staged := path + ".next"
	if err := os.WriteFile(staged, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
}

// swapAfterStat replaces the record each time its name is checked, up to
// swaps times, and counts the checks.
func swapAfterStat(t *testing.T, path string, swaps int, content []byte) *int {
	t.Helper()
	checks := 0
	restore := pathidentity.SetPinnedStatHookForTest(func(checked string) {
		if checked != path {
			return
		}
		checks++
		if checks <= swaps {
			replaceRecord(t, path, content)
		}
	})
	t.Cleanup(restore)
	return &checks
}

func TestPublishedRecordReadSurvivesAReplacementBetweenCheckAndOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	checks := swapAfterStat(t, path, 2, []byte(`{"v":1}`))
	data, exists, err := readEnterpriseHookPublishedRecord(path, "hook guardian activation", 1024, nil)
	if err != nil || !exists || string(data) != `{"v":1}` {
		t.Fatalf("read after replacements = %q, exists=%t, %v; want the record", data, exists, err)
	}
	if *checks != 3 {
		t.Fatalf("name checked %d times, want 3 (two replaced, one stable)", *checks)
	}
}

func TestPublishedRecordReadFailsClosedNamingTheFileWhenItStaysSwapped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	swapAfterStat(t, path, 1<<20, []byte(`{"v":1}`))
	data, exists, err := readEnterpriseHookPublishedRecord(path, "hook guardian activation", 1024, nil)
	if err == nil || data != nil || !exists {
		t.Fatalf("persistent swap = %q, exists=%t, %v; want a refusal", data, exists, err)
	}
	if !errors.Is(err, safefile.ErrReadIdentityChanged) ||
		!strings.Contains(err.Error(), "hook guardian activation") || !strings.Contains(err.Error(), path) {
		t.Fatalf("persistent swap error = %v; want it to name the record and its path", err)
	}
}

func TestPublishedRecordReadRefusesALinkOrAnotherTypeAtOnce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	directory := filepath.Join(dir, "directory.json")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, directory} {
		checks := 0
		restore := pathidentity.SetPinnedStatHookForTest(func(string) { checks++ })
		_, exists, err := readEnterpriseHookPublishedRecord(path, "hook guardian activation", 1024, nil)
		restore()
		if err == nil || !exists || !strings.Contains(err.Error(), "is not a regular file") {
			t.Fatalf("%s: exists=%t, %v; want a not-a-regular-file refusal", path, exists, err)
		}
		if checks > 1 {
			t.Fatalf("%s: name checked %d times, want one (no retry for a link or another type)", path, checks)
		}
	}
}

func TestPublishedRecordReadRefusesAnUntrustedRecordAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	trustCalls := 0
	_, exists, err := readEnterpriseHookPublishedRecord(path, "hook guardian activation", 1024, func(string) error {
		trustCalls++
		return errors.New("owner is not trusted")
	})
	if err == nil || !exists || trustCalls != 1 || !strings.Contains(err.Error(), "owner is not trusted") {
		t.Fatalf("untrusted record: exists=%t, %v after %d trust checks; want one refusal", exists, err, trustCalls)
	}
}

func TestPublishedRecordReadReportsAMissingRecordAsAbsent(t *testing.T) {
	data, exists, err := readEnterpriseHookPublishedRecord(filepath.Join(t.TempDir(), "none.json"), "hook guardian activation", 1024, nil)
	if err != nil || exists || data != nil {
		t.Fatalf("missing record = %q, exists=%t, %v; want absent with no error", data, exists, err)
	}
}

func TestPublishedRecordReadKeepsTheSizeBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readEnterpriseHookPublishedRecord(path, "hook guardian activation", 16, nil); err == nil || !strings.Contains(err.Error(), "exceeds 16-byte limit") {
		t.Fatalf("oversized record error = %v; want the byte limit", err)
	}
}

func TestGuardianActivationStatusReadSurvivesTheGuardianRewrite(t *testing.T) {
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	dataDir := t.TempDir()
	authorizationDir := t.TempDir()
	t.Setenv(hookGuardianAuthorizationDirEnv, authorizationDir)
	activation := enterpriseHookGuardianActivation{
		Version:        enterpriseHookGuardianActivationVersion,
		ReconcileID:    strings.Repeat("b", 32),
		Manifest:       "targets.yaml",
		ManifestSHA256: strings.Repeat("a", sha256.Size*2),
		OK:             true,
	}
	body, err := json.Marshal(activation)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(authorizationDir, hookGuardianActivationFile)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	swapAfterStat(t, path, 2, body)
	got, exists, err := loadEnterpriseHookGuardianActivation(dataDir)
	if err != nil || !exists || got.ReconcileID != activation.ReconcileID {
		t.Fatalf("activation read during rewrites = %+v, exists=%t, %v; want the record", got, exists, err)
	}
}

func TestPublishedRecordReadNeverTurnsAnObservedRecordIntoAbsence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	checks := 0
	restore := pathidentity.SetPinnedStatHookForTest(func(checked string) {
		if checked != path {
			return
		}
		checks++
		if checks == 1 {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		}
	})
	defer restore()
	data, exists, err := readEnterpriseHookPublishedRecord(path, "hook guardian activation", 1024, nil)
	if err == nil || data != nil || !exists {
		t.Fatalf("record seen then gone = %q, exists=%t, %v; want a refusal, not absence", data, exists, err)
	}
	if !errors.Is(err, safefile.ErrReadIdentityChanged) ||
		!strings.Contains(err.Error(), "hook guardian activation") || !strings.Contains(err.Error(), path) {
		t.Fatalf("seen-then-gone error = %v; want it to name the record and its path", err)
	}
}

func publishTestGuardianGeneration(t *testing.T, dataDir string, rows []enterpriseHookReconcileRow, failures int) {
	t.Helper()
	if err := writeEnterpriseHookGuardianState(dataDir, "targets.yaml", strings.Repeat("a", sha256.Size*2), rows, failures, true); err != nil {
		t.Fatalf("write guardian records: %v", err)
	}
}

func TestGuardianGenerationIsRepublishedOnlyWhenItChangesOrAges(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("enterprise hook guardian persistence is unsupported on native Windows; lifecycle gate coverage remains active")
	}
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	originalOwnership := enterpriseHookAuthorizationOwnershipSetter
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	t.Cleanup(func() { enterpriseHookAuthorizationOwnershipSetter = originalOwnership })
	dataDir := t.TempDir()
	t.Setenv(hookGuardianAuthorizationDirEnv, t.TempDir())
	rows := []enterpriseHookReconcileRow{{User: "alice", Connector: "codex", OK: true}}
	publishTestGuardianGeneration(t, dataDir, rows, 0)
	first, _, err := loadEnterpriseHookGuardianActivation(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	candidate := func() (enterpriseHookGuardianAuthorization, enterpriseHookGuardianState, enterpriseHookGuardianActivation) {
		state, _, _ := loadEnterpriseHookGuardianState(dataDir)
		authorization, _, _ := loadEnterpriseHookGuardianAuthorization(dataDir)
		activation := first
		activation.UpdatedAt, activation.ReconcileID = "other", strings.Repeat("c", 32)
		authorization.UpdatedAt, state.UpdatedAt = "other", "other"
		return authorization, state, activation
	}
	published, _ := time.Parse(time.RFC3339Nano, first.UpdatedAt)

	authorization, state, activation := candidate()
	if !enterpriseHookGuardianGenerationCurrent(dataDir, published.Add(time.Second), authorization, state, activation) {
		t.Fatal("an identical, young generation was not kept")
	}
	if enterpriseHookGuardianGenerationCurrent(dataDir, published.Add(enterpriseHookGuardianRepublishAfter), authorization, state, activation) {
		t.Fatal("a generation at the republish age was kept; the freshness limit would be near")
	}
	state.Results = []enterpriseHookReconcileRow{{User: "alice", Connector: "codex", OK: true, Error: "x"}}
	if enterpriseHookGuardianGenerationCurrent(dataDir, published.Add(time.Second), authorization, state, activation) {
		t.Fatal("a changed state row was kept")
	}
	authorization, state, activation = candidate()
	activation.ManifestSHA256 = strings.Repeat("d", sha256.Size*2)
	if enterpriseHookGuardianGenerationCurrent(dataDir, published.Add(time.Second), authorization, state, activation) {
		t.Fatal("a changed manifest was kept")
	}
	authorization, state, activation = candidate()
	if err := os.Remove(filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), hookGuardianActivationFile)); err != nil {
		t.Fatal(err)
	}
	if enterpriseHookGuardianGenerationCurrent(dataDir, published.Add(time.Second), authorization, state, activation) {
		t.Fatal("a missing activation record was kept; it must be repaired")
	}
	publishTestGuardianGeneration(t, dataDir, rows, 0)
	if again, exists, err := loadEnterpriseHookGuardianActivation(dataDir); err != nil || !exists || again.ReconcileID == first.ReconcileID {
		t.Fatalf("the repaired generation = %+v, exists=%t, %v; want a new published activation", again, exists, err)
	}
}

func TestRestartedGuardianPublishesFreshGenerationForUnchangedOutcome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("enterprise hook guardian persistence is unsupported on native Windows; lifecycle gate coverage remains active")
	}
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	originalOwnership := enterpriseHookAuthorizationOwnershipSetter
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	t.Cleanup(func() { enterpriseHookAuthorizationOwnershipSetter = originalOwnership })
	wasPublished := enterpriseHookGuardianPublishedByProcess.Load()
	t.Cleanup(func() { enterpriseHookGuardianPublishedByProcess.Store(wasPublished) })
	dataDir := t.TempDir()
	t.Setenv(hookGuardianAuthorizationDirEnv, t.TempDir())
	rows := []enterpriseHookReconcileRow{{User: "alice", Connector: "codex", OK: true}}

	// A previous process published this outcome a moment ago.
	enterpriseHookGuardianPublishedByProcess.Store(false)
	publishTestGuardianGeneration(t, dataDir, rows, 0)
	previous, _, err := loadEnterpriseHookGuardianActivation(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	// The same process finds the same outcome and keeps the generation.
	publishTestGuardianGeneration(t, dataDir, rows, 0)
	if same, _, err := loadEnterpriseHookGuardianActivation(dataDir); err != nil || same.ReconcileID != previous.ReconcileID {
		t.Fatalf("unchanged pass of the same process = %+v, %v; want the generation kept", same, err)
	}
	// A restarted guardian is a new process: its first pass publishes a new
	// reconcile ID and generation although nothing changed, which is what
	// Setup waits for after it restarts the guardian (GAP-0931).
	enterpriseHookGuardianPublishedByProcess.Store(false)
	publishTestGuardianGeneration(t, dataDir, rows, 0)
	fresh, _, err := loadEnterpriseHookGuardianActivation(dataDir)
	if err != nil || fresh.ReconcileID == previous.ReconcileID || fresh.UpdatedAt == previous.UpdatedAt {
		t.Fatalf("first pass after a restart = %+v, %v; want a new reconcile ID and generation than %+v", fresh, err, previous)
	}
	state, _, err := loadEnterpriseHookGuardianState(dataDir)
	if err != nil || state.UpdatedAt != fresh.UpdatedAt {
		t.Fatalf("state generation = %q, %v; want %q", state.UpdatedAt, err, fresh.UpdatedAt)
	}
	// Its later passes keep it again.
	publishTestGuardianGeneration(t, dataDir, rows, 0)
	if again, _, err := loadEnterpriseHookGuardianActivation(dataDir); err != nil || again.ReconcileID != fresh.ReconcileID {
		t.Fatalf("second pass after the restart = %+v, %v; want the generation kept", again, err)
	}
}
