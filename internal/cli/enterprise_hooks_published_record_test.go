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

// guardianFreshCoverage is the question Setup asks after it restarts the
// guardian (Test-DefenseClawGuardianCoverageReport with the manifest digest,
// the standalone activation and rollback wait): the generation is not older
// than the moment Setup started the restart, the activation names that very
// generation with a reconcile ID Setup has not seen and the manifest digest it
// expects, and the state and authorization name the same generation too.
func guardianFreshCoverage(t *testing.T, dataDir string, startedAfter time.Time, priorReconcileID, manifestSHA256 string) error {
	t.Helper()
	activation, exists, err := loadEnterpriseHookGuardianActivation(dataDir)
	if err != nil || !exists {
		return errors.New("guardian status is missing protected activation coverage")
	}
	state, _, _ := loadEnterpriseHookGuardianState(dataDir)
	authorization, _, _ := loadEnterpriseHookGuardianAuthorization(dataDir)
	generation, err := time.Parse(time.RFC3339Nano, activation.UpdatedAt)
	if err != nil {
		return errors.New("guardian generation " + activation.UpdatedAt + " is invalid")
	}
	if generation.Before(startedAfter) {
		return errors.New("guardian generation " + activation.UpdatedAt + " predates activation")
	}
	if activation.ReconcileID == priorReconcileID {
		return errors.New("guardian reconcile ID " + activation.ReconcileID + " is not fresh")
	}
	if state.UpdatedAt != activation.UpdatedAt || authorization.UpdatedAt != activation.UpdatedAt {
		return errors.New("guardian activation does not identify the reported generation")
	}
	if activation.ManifestSHA256 != manifestSHA256 {
		return errors.New("guardian manifest SHA-256 does not match")
	}
	return nil
}

func useGuardianPublishFixture(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("enterprise hook guardian persistence is unsupported on native Windows; lifecycle gate coverage remains active")
	}
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	originalOwnership := enterpriseHookAuthorizationOwnershipSetter
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	t.Cleanup(func() { enterpriseHookAuthorizationOwnershipSetter = originalOwnership })
	wasPublished := enterpriseHookGuardianPublishedByProcess.Load()
	t.Cleanup(func() { enterpriseHookGuardianPublishedByProcess.Store(wasPublished) })
	t.Setenv(hookGuardianAuthorizationDirEnv, t.TempDir())
	return t.TempDir()
}

// GAP-0936: a Setup lifecycle rollback restarts the guardian, and the
// restarted guardian decides the same failed row (a link on a vendor machine
// folder) as the process before it. Its first pass must still publish a new
// generation, because the wait that proves the restart rejects the one the
// earlier process left ("generation predates activation"). The row is failed
// on purpose: the failed-row pass is the one GAP-0912 made quiet.
func TestRestartedGuardianAfterARollbackPublishesAFreshGenerationForTheSameFailedRow(t *testing.T) {
	dataDir := useGuardianPublishFixture(t)
	manifestSHA256 := strings.Repeat("a", sha256.Size*2)
	failedRow := []enterpriseHookReconcileRow{
		{User: "alice", Connector: "cursor", OK: false, Error: "reparse point in path: C:\\ProgramData\\Cursor"},
		{User: "alice", Connector: "codex", OK: true},
	}
	publish := func() {
		t.Helper()
		if err := writeEnterpriseHookGuardianState(dataDir, "targets.yaml", manifestSHA256, failedRow, 1, true); err != nil {
			t.Fatalf("write guardian records: %v", err)
		}
	}
	// The guardian before the rollback published this outcome.
	enterpriseHookGuardianPublishedByProcess.Store(false)
	publish()
	before, _, err := loadEnterpriseHookGuardianActivation(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	// The rollback: Setup notes the moment, stops the guardian and starts it.
	time.Sleep(5 * time.Millisecond)
	startedAfter := time.Now().UTC()
	if err := guardianFreshCoverage(t, dataDir, startedAfter, before.ReconcileID, manifestSHA256); err == nil ||
		!strings.Contains(err.Error(), "predates activation") {
		t.Fatalf("the generation the earlier process left passed the wait for a restart: %v", err)
	}
	enterpriseHookGuardianPublishedByProcess.Store(false) // the new process
	publish()
	if err := guardianFreshCoverage(t, dataDir, startedAfter, before.ReconcileID, manifestSHA256); err != nil {
		t.Fatalf("the restarted guardian first pass did not satisfy the fresh-coverage wait: %v", err)
	}
	after, _, _ := loadEnterpriseHookGuardianActivation(dataDir)
	if after.OK || after.FailureCount != 1 || after.ReconcileID == before.ReconcileID {
		t.Fatalf("restarted guardian activation = %+v; want the same failed outcome under a new reconcile ID", after)
	}
}

// GAP-0912 must keep its benefit: after its first pass a guardian process
// does not rewrite the three records for a pass that decided nothing new,
// whether the outcome is healthy or carries a failed row.
func TestGuardianPassesAfterTheFirstDoNotRewriteAnUnchangedOutcome(t *testing.T) {
	for name, rows := range map[string][]enterpriseHookReconcileRow{
		"healthy":    {{User: "alice", Connector: "codex", OK: true}},
		"failed row": {{User: "alice", Connector: "cursor", OK: false, Error: "reparse point in path"}},
	} {
		t.Run(name, func(t *testing.T) {
			dataDir := useGuardianPublishFixture(t)
			failures := 0
			for _, row := range rows {
				if !row.OK {
					failures++
				}
			}
			manifestSHA256 := strings.Repeat("a", sha256.Size*2)
			enterpriseHookGuardianPublishedByProcess.Store(false)
			if err := writeEnterpriseHookGuardianState(dataDir, "targets.yaml", manifestSHA256, rows, failures, true); err != nil {
				t.Fatal(err)
			}
			records := func() map[string]string {
				read := map[string]string{}
				for _, path := range []string{
					filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), hookGuardianAuthorizationFile),
					filepath.Join(dataDir, hookGuardianStateFile),
					filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), hookGuardianActivationFile),
				} {
					body, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					info, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					read[path] = string(body) + "@" + info.ModTime().String()
				}
				return read
			}
			first := records()
			time.Sleep(10 * time.Millisecond)
			for pass := 2; pass <= 4; pass++ {
				if err := writeEnterpriseHookGuardianState(dataDir, "targets.yaml", manifestSHA256, rows, failures, true); err != nil {
					t.Fatal(err)
				}
				now := records()
				for path, want := range first {
					if now[path] != want {
						t.Fatalf("pass %d rewrote %s for an unchanged outcome", pass, path)
					}
				}
			}
		})
	}
}

// GAP-0936: an activation the guardian has not acknowledged is published
// even from a process that already published. The activation Setup waits for
// is the manifest digest the guardian runs and the one generation all three
// records name; a pass that runs a different manifest, or finds the
// activation record newer or different than the generation it published,
// publishes again.
func TestGuardianPublishesAnActivationItHasNotAcknowledged(t *testing.T) {
	manifestSHA256 := strings.Repeat("a", sha256.Size*2)
	rows := []enterpriseHookReconcileRow{{User: "alice", Connector: "cursor", OK: false, Error: "reparse point in path"}}
	rewriteActivation := func(t *testing.T, dataDir string, change func(*enterpriseHookGuardianActivation)) {
		t.Helper()
		activation, _, err := loadEnterpriseHookGuardianActivation(dataDir)
		if err != nil {
			t.Fatal(err)
		}
		change(&activation)
		body, err := json.MarshalIndent(activation, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		replaceRecord(t, filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), hookGuardianActivationFile), append(body, 10))
	}
	for name, unacknowledge := range map[string]func(t *testing.T, dataDir string) string{
		"a new manifest digest": func(*testing.T, string) string { return strings.Repeat("b", sha256.Size*2) },
		"an activation newer than the published generation": func(t *testing.T, dataDir string) string {
			rewriteActivation(t, dataDir, func(activation *enterpriseHookGuardianActivation) {
				stamped, _ := time.Parse(time.RFC3339Nano, activation.UpdatedAt)
				activation.UpdatedAt = stamped.Add(time.Millisecond).Format(time.RFC3339Nano)
			})
			return manifestSHA256
		},
		"an activation that names another outcome": func(t *testing.T, dataDir string) string {
			rewriteActivation(t, dataDir, func(activation *enterpriseHookGuardianActivation) {
				activation.OK, activation.FailureCount = true, 0
			})
			return manifestSHA256
		},
	} {
		t.Run(name, func(t *testing.T) {
			dataDir := useGuardianPublishFixture(t)
			enterpriseHookGuardianPublishedByProcess.Store(false)
			if err := writeEnterpriseHookGuardianState(dataDir, "targets.yaml", manifestSHA256, rows, 1, true); err != nil {
				t.Fatal(err)
			}
			published, _, _ := loadEnterpriseHookGuardianActivation(dataDir)
			// The same process, unchanged: kept.
			if err := writeEnterpriseHookGuardianState(dataDir, "targets.yaml", manifestSHA256, rows, 1, true); err != nil {
				t.Fatal(err)
			}
			if kept, _, _ := loadEnterpriseHookGuardianActivation(dataDir); kept.ReconcileID != published.ReconcileID {
				t.Fatalf("an unchanged pass republished (control): %+v", kept)
			}
			digest := unacknowledge(t, dataDir)
			time.Sleep(5 * time.Millisecond)
			startedAfter := time.Now().UTC()
			if err := writeEnterpriseHookGuardianState(dataDir, "targets.yaml", digest, rows, 1, true); err != nil {
				t.Fatal(err)
			}
			if err := guardianFreshCoverage(t, dataDir, startedAfter, published.ReconcileID, digest); err != nil {
				t.Fatalf("the unacknowledged activation was not published: %v", err)
			}
		})
	}
}
