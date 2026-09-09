// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestEnterpriseHookRotationPrepareCommitRollback(t *testing.T) {
	env := newEnterpriseHookRotationTestEnv(t, "alice", "bob")
	req := env.request()

	prepared, err := executeEnterpriseHookRotationPrepare(req)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if prepared.Phase != enterpriseHookRotationPhasePrepared {
		t.Fatalf("prepare phase = %q", prepared.Phase)
	}
	if got := env.publishedToken(t, "alice"); got != env.tokenB {
		t.Fatal("alice did not receive generation B")
	}
	if got := env.publishedToken(t, "bob"); got != env.tokenB {
		t.Fatal("bob did not receive generation B")
	}
	authorization, exists, err := loadEnterpriseHookGuardianAuthorization(env.serviceDir)
	if err != nil || !exists || authorization.Current == nil || !authorization.Current.OK {
		t.Fatalf("current readiness after prepare: exists=%v err=%v current=%v", exists, err, authorization.Current)
	}
	if authorization.Current.Generation != env.generation {
		t.Fatalf("current generation = %q, want rotation generation", authorization.Current.Generation)
	}
	if journalHasSecret(t, env.serviceDir, env.tokenA, env.tokenB) {
		t.Fatal("public journal contained raw token material")
	}

	again, err := executeEnterpriseHookRotationPrepare(req)
	if err != nil {
		t.Fatalf("idempotent prepare: %v", err)
	}
	if again.Phase != enterpriseHookRotationPhasePrepared {
		t.Fatalf("idempotent prepare phase = %q", again.Phase)
	}

	committed, err := executeEnterpriseHookRotationCommit(req)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if committed.Phase != enterpriseHookRotationPhaseCommitted {
		t.Fatalf("commit phase = %q", committed.Phase)
	}
	if _, err := os.Lstat(enterpriseHookRotationRollbackPath(env.serviceDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback material survived commit: %v", err)
	}
	if _, err := executeEnterpriseHookRotationCommit(req); err != nil {
		t.Fatalf("idempotent commit: %v", err)
	}
}

func TestEnterpriseHookRotationPartialPrepareRestoresA(t *testing.T) {
	env := newEnterpriseHookRotationTestEnv(t, "alice", "bob")
	writes := 0
	originalAfter := enterpriseHookRotationAfterTargetWrite
	t.Cleanup(func() { enterpriseHookRotationAfterTargetWrite = originalAfter })
	enterpriseHookRotationAfterTargetWrite = func(target enterpriseHookRotationTarget) error {
		writes++
		if writes == 2 {
			return errors.New("injected target-write failure")
		}
		return nil
	}

	if _, err := executeEnterpriseHookRotationPrepare(env.request()); err == nil {
		t.Fatal("prepare succeeded despite injected failure")
	}
	if got := env.publishedToken(t, "alice"); got != env.tokenA {
		t.Fatal("alice was not restored to generation A")
	}
	if got := env.publishedToken(t, "bob"); got != env.tokenA {
		t.Fatal("bob was not restored to generation A")
	}
}

func TestEnterpriseHookRotationRollbackRestoresAAfterPrepare(t *testing.T) {
	env := newEnterpriseHookRotationTestEnv(t, "alice")
	req := env.request()
	if _, err := executeEnterpriseHookRotationPrepare(req); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	rolled, err := executeEnterpriseHookRotationRollback(req)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolled.Phase != enterpriseHookRotationPhaseRolledBack {
		t.Fatalf("rollback phase = %q", rolled.Phase)
	}
	if got := env.publishedToken(t, "alice"); got != env.tokenA {
		t.Fatal("rollback did not restore generation A")
	}
	authorization, exists, err := loadEnterpriseHookGuardianAuthorization(env.serviceDir)
	if err != nil || !exists || authorization.Current == nil || !authorization.Current.OK {
		t.Fatalf("readiness after rollback should republish generation A: exists=%v err=%v current=%v", exists, err, authorization.Current)
	}
	wantFingerprint := managed.ScopedTokenFingerprint(env.tokenA)
	if authorization.Current.ManifestSHA256 != rolled.ManifestSHA256 {
		t.Fatalf("rollback manifest digest = %q, want %q", authorization.Current.ManifestSHA256, rolled.ManifestSHA256)
	}
	if len(authorization.Current.Attestations) != 1 ||
		authorization.Current.Attestations[0].TokenFingerprint != wantFingerprint {
		t.Fatalf("rollback attestations = %+v, want generation A fingerprint", authorization.Current.Attestations)
	}
	if _, err := executeEnterpriseHookRotationRollback(req); err != nil {
		t.Fatalf("idempotent rollback: %v", err)
	}
}

func TestEnterpriseHookRotationRejectsConflictingOperation(t *testing.T) {
	env := newEnterpriseHookRotationTestEnv(t, "alice")
	if _, err := executeEnterpriseHookRotationPrepare(env.request()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	conflict := env.request()
	conflict.OperationID = strings.Repeat("c", 32)
	if _, err := executeEnterpriseHookRotationPrepare(conflict); err == nil || !strings.Contains(err.Error(), "conflicting operation") {
		t.Fatalf("conflicting prepare error = %v", err)
	}
}

func TestEnterpriseHookRotationBusyBlocksReconcile(t *testing.T) {
	env := newEnterpriseHookRotationTestEnv(t, "alice")
	if _, err := executeEnterpriseHookRotationPrepare(env.request()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := enterpriseHookRotationBusy(env.serviceDir); err == nil {
		t.Fatal("prepared rotation did not serialize reconcile")
	}
}

func TestEnterpriseHookRotationRefusesSymlinkHome(t *testing.T) {
	env := newEnterpriseHookRotationTestEnv(t, "alice")
	linked := filepath.Join(t.TempDir(), "linked-home")
	if err := os.Symlink(env.homes["alice"], linked); err != nil {
		t.Fatalf("symlink home: %v", err)
	}
	manifest := filepath.Join(env.scope, "symlink-manifest.yaml")
	if err := os.WriteFile(manifest, []byte("version: 1\ntargets:\n  - user: alice\n    user_home: "+linked+"\n    connector: codex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prints, err := json.Marshal(enterpriseHookRotationFingerprintFile{Targets: []enterpriseHookRotationTarget{{
		User:             "alice",
		UserHome:         linked,
		Connector:        "codex",
		TokenFingerprint: managed.ScopedTokenFingerprint(env.tokenB),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	printsPath := filepath.Join(env.scope, "symlink-fingerprints.json")
	if err := os.WriteFile(printsPath, prints, 0o600); err != nil {
		t.Fatal(err)
	}
	req := env.request()
	req.Manifest = manifest
	req.Fingerprints = printsPath
	if _, err := executeEnterpriseHookRotationPrepare(req); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink home error = %v", err)
	}
}

type enterpriseHookRotationTestEnv struct {
	scope      string
	serviceDir string
	homes      map[string]string
	tokenA     string
	tokenB     string
	operation  string
	generation string
	manifest   string
	prints     string
}

func newEnterpriseHookRotationTestEnv(t *testing.T, users ...string) *enterpriseHookRotationTestEnv {
	t.Helper()
	scope := t.TempDir()
	serviceDir := filepath.Join(scope, "service")
	if err := os.MkdirAll(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	env := &enterpriseHookRotationTestEnv{
		scope:      scope,
		serviceDir: serviceDir,
		homes:      map[string]string{},
		tokenA:     strings.Repeat("a", 64),
		tokenB:     strings.Repeat("b", 64),
		operation:  strings.Repeat("1", 32),
		generation: strings.Repeat("2", 32),
	}

	originalCfg := cfg
	originalTrust := enterpriseHookManifestFileTrustCheck
	originalDirTrust := enterpriseHookAuthorizationDirTrustCheck
	originalFileTrust := enterpriseHookAuthorizationFileTrustCheck
	originalOwner := enterpriseHookAuthorizationOwnershipSetter
	originalStateTrust := enterpriseHookGuardianStateFileTrustCheck
	originalMutation := enterpriseHooksMutationIdentityPreflight
	originalLoadB := enterpriseHookRotationLoadB
	originalSpace := enterpriseHookRotationSpaceCheck
	t.Cleanup(func() {
		cfg = originalCfg
		enterpriseHookManifestFileTrustCheck = originalTrust
		enterpriseHookAuthorizationDirTrustCheck = originalDirTrust
		enterpriseHookAuthorizationFileTrustCheck = originalFileTrust
		enterpriseHookAuthorizationOwnershipSetter = originalOwner
		enterpriseHookGuardianStateFileTrustCheck = originalStateTrust
		enterpriseHooksMutationIdentityPreflight = originalMutation
		enterpriseHookRotationLoadB = originalLoadB
		enterpriseHookRotationSpaceCheck = originalSpace
	})
	enterpriseHookManifestFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHooksMutationIdentityPreflight = func() error { return nil }
	enterpriseHookRotationSpaceCheck = func(string) error { return nil }
	enterpriseHookRotationLoadB = func(string, string) (string, error) { return env.tokenB, nil }

	var manifest strings.Builder
	manifest.WriteString("version: 1\ntargets:\n")
	rows := make([]enterpriseHookReconcileRow, 0, len(users))
	expected := enterpriseHookRotationFingerprintFile{Targets: make([]enterpriseHookRotationTarget, 0, len(users))}
	for _, user := range users {
		home := filepath.Join(scope, "home", user)
		dataDir := filepath.Join(home, ".defenseclaw")
		if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := connector.PublishHookAPIToken(dataDir, "codex", env.tokenA); err != nil {
			t.Fatalf("publish A for %s: %v", user, err)
		}
		env.homes[user] = home
		manifest.WriteString("  - user: " + user + "\n    user_home: " + home + "\n    connector: codex\n")
		rows = append(rows, enterpriseHookReconcileRow{
			User:             user,
			UserHome:         home,
			Connector:        "codex",
			OK:               true,
			TokenFingerprint: managed.ScopedTokenFingerprint(env.tokenA),
		})
		expected.Targets = append(expected.Targets, enterpriseHookRotationTarget{
			User:             user,
			UserHome:         home,
			Connector:        "codex",
			TokenFingerprint: managed.ScopedTokenFingerprint(env.tokenB),
		})
	}
	env.manifest = filepath.Join(scope, "targets.yaml")
	if err := os.WriteFile(env.manifest, []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	prints, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	env.prints = filepath.Join(scope, "expected-fingerprints.json")
	if err := os.WriteFile(env.prints, prints, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	cfg = &config.Config{DataDir: serviceDir}
	if err := writeEnterpriseHookGuardianState(serviceDir, env.manifest, testEnterpriseHookManifestSHA256, rows, 0, true); err != nil {
		t.Fatalf("seed current attestations: %v", err)
	}
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	return env
}

func (env *enterpriseHookRotationTestEnv) request() enterpriseHookRotationRequest {
	return enterpriseHookRotationRequest{
		OperationID:  env.operation,
		Generation:   env.generation,
		Manifest:     env.manifest,
		Fingerprints: env.prints,
	}
}

func (env *enterpriseHookRotationTestEnv) publishedToken(t *testing.T, user string) string {
	t.Helper()
	token, err := connector.LoadHookAPIToken(filepath.Join(env.homes[user], ".defenseclaw"), "codex")
	if err != nil {
		t.Fatalf("load published token for %s: %v", user, err)
	}
	return token
}

func journalHasSecret(t *testing.T, dataDir string, secrets ...string) bool {
	t.Helper()
	path := enterpriseHookRotationJournalPath(dataDir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	text := string(data)
	for _, secret := range secrets {
		if strings.Contains(text, secret) {
			return true
		}
	}
	return false
}

// The preflight symlink refusal runs before the rotation lock, so a target
// user can swap their data directory for a symlink before the privileged
// write. mkdirEnterpriseHookRotationBound must refuse to traverse it rather
// than creating directories outside the user's own home.
func TestEnterpriseHookRotationBoundMkdirRefusesSwappedSymlink(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.Symlink(outside, dataDir); err != nil {
		t.Fatalf("symlink data dir: %v", err)
	}
	if err := mkdirEnterpriseHookRotationBound(dataDir, "hooks"); err == nil {
		t.Fatal("bound mkdir traversed a swapped symlink")
	}
	if _, err := os.Lstat(filepath.Join(outside, "hooks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("privileged mkdir escaped the home directory: %v", err)
	}
}

// The ordinary case must still work: a real data directory and its hooks
// subdirectory are created with the expected permissions.
func TestEnterpriseHookRotationBoundMkdirCreatesRealDirs(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := mkdirEnterpriseHookRotationBound(dataDir, "hooks"); err != nil {
		t.Fatalf("bound mkdir: %v", err)
	}
	info, err := os.Lstat(filepath.Join(dataDir, "hooks"))
	if err != nil {
		t.Fatalf("hooks dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("hooks is not a directory")
	}
	// Idempotent: a second call over existing directories must succeed.
	if err := mkdirEnterpriseHookRotationBound(dataDir, "hooks"); err != nil {
		t.Fatalf("bound mkdir second call: %v", err)
	}
}

// A prepare that was interrupted leaves the journal at `preparing`. Resuming it
// re-entered the snapshot loop, and snapshotEnterpriseHookRotationTarget
// overwrites the sidecar unconditionally -- so a target already published as
// generation B had its generation-A snapshot replaced with B, and a later
// rollback restored B while reporting success. Prepare must refuse instead.
func TestEnterpriseHookRotationPreparingJournalRefusesResume(t *testing.T) {
	env := newEnterpriseHookRotationTestEnv(t, "alice")
	req := env.request()
	prepared, err := executeEnterpriseHookRotationPrepare(req)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if prepared.Phase != enterpriseHookRotationPhasePrepared {
		t.Fatalf("prepare phase = %q", prepared.Phase)
	}
	// Simulate an interruption: rewind the persisted phase to preparing.
	journal, exists, err := loadEnterpriseHookRotationJournal(env.serviceDir)
	if err != nil || !exists {
		t.Fatalf("load journal: %v exists=%v", err, exists)
	}
	journal.Phase = enterpriseHookRotationPhasePreparing
	if err := writeEnterpriseHookRotationJournal(env.serviceDir, journal); err != nil {
		t.Fatalf("seed preparing journal: %v", err)
	}
	snapshotBefore := mustReadRotationSnapshot(t, env, "alice")
	if _, err := executeEnterpriseHookRotationPrepare(req); err == nil ||
		!strings.Contains(err.Error(), "already preparing") {
		t.Fatalf("resume error = %v, want refusal", err)
	}
	if after := mustReadRotationSnapshot(t, env, "alice"); after != snapshotBefore {
		t.Fatal("refused prepare still overwrote the generation-A snapshot")
	}
}

// An interrupted commit can persist `committed` and still fail before retiring
// the rollback directory. Re-running commit must finish that cleanup.
func TestEnterpriseHookRotationCommitRetiresRollbackMaterialIdempotently(t *testing.T) {
	env := newEnterpriseHookRotationTestEnv(t, "alice")
	req := env.request()
	if _, err := executeEnterpriseHookRotationPrepare(req); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	journal, exists, err := loadEnterpriseHookRotationJournal(env.serviceDir)
	if err != nil || !exists {
		t.Fatalf("load journal: %v exists=%v", err, exists)
	}
	journal.Phase = enterpriseHookRotationPhaseCommitted
	if err := writeEnterpriseHookRotationJournal(env.serviceDir, journal); err != nil {
		t.Fatalf("write committed journal: %v", err)
	}
	if _, err := os.Lstat(enterpriseHookRotationRollbackPath(env.serviceDir)); err != nil {
		t.Fatalf("expected leftover rollback material: %v", err)
	}
	committed, err := executeEnterpriseHookRotationCommit(req)
	if err != nil {
		t.Fatalf("idempotent commit: %v", err)
	}
	if committed.Phase != enterpriseHookRotationPhaseCommitted {
		t.Fatalf("phase = %q", committed.Phase)
	}
	if _, err := os.Lstat(enterpriseHookRotationRollbackPath(env.serviceDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback material was not retired: %v", err)
	}
}

func mustReadRotationSnapshot(t *testing.T, env *enterpriseHookRotationTestEnv, user string) string {
	t.Helper()
	target := enterpriseHookRotationTarget{
		User: user, UserHome: env.homes[user], Connector: "codex",
	}
	data, err := os.ReadFile(enterpriseHookRotationTargetSnapshotPath(env.serviceDir, target))
	if err != nil {
		t.Fatalf("read snapshot for %s: %v", user, err)
	}
	return string(data)
}
