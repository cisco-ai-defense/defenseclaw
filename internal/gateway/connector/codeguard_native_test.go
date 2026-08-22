// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestConnectorEnvHomeDirResolvesRelativeOverride(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("CODEX_HOME", "relative-codex-home")

	want := filepath.Join(root, "relative-codex-home")
	if got := codexHomeDir(); got != want {
		t.Fatalf("codexHomeDir() = %q, want %q", got, want)
	}
}

func TestCodexCodeGuardSkillInstallCopiesSoftwareSecurity(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "project-codeguard")
	sourceDir := filepath.Join(repoDir, "skills", nativeCodeGuardRepoSkillName)
	writeTestFile(t, filepath.Join(sourceDir, "SKILL.md"), `---
name: codeguard
---

# Software Security Skill (Project CodeGuard)
`)
	writeTestFile(t, filepath.Join(sourceDir, "rules", "codeguard-1-hardcoded-credentials.md"), "# Rule\n")

	oldOverride := nativeCodeGuardRepoDirOverride
	nativeCodeGuardRepoDirOverride = repoDir
	t.Cleanup(func() { nativeCodeGuardRepoDirOverride = oldOverride })

	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	codexHome := filepath.Join(dir, "codex-home")
	t.Setenv("CODEX_HOME", codexHome)

	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	if err := ensureCodexCodeGuardSkill(context.Background(), opts); err != nil {
		t.Fatalf("ensureCodexCodeGuardSkill: %v", err)
	}

	targetDir := filepath.Join(userHome, ".agents", "skills", nativeCodeGuardCodexSkillName)
	if data, err := os.ReadFile(filepath.Join(targetDir, "SKILL.md")); err != nil {
		t.Fatalf("read installed SKILL.md: %v", err)
	} else if !strings.Contains(string(data), "Project CodeGuard") {
		t.Fatalf("installed SKILL.md does not contain Project CodeGuard marker:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "rules", "codeguard-1-hardcoded-credentials.md")); err != nil {
		t.Fatalf("rule file was not copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(codexHome, "skills", nativeCodeGuardCodexSkillName)); !os.IsNotExist(err) {
		t.Fatalf("CODEX_HOME unexpectedly redirected the personal skill install: %v", err)
	}
	if _, err := os.Stat(codexCodeGuardReceiptPath(opts)); err != nil {
		t.Fatalf("ownership receipt was not published: %v", err)
	}
	receipt, exists, err := loadCodexCodeGuardReceipt(opts, targetDir)
	if err != nil || !exists {
		t.Fatalf("load pinned ownership receipt: exists=%v err=%v", exists, err)
	}
	if receipt.SourceCommit != nativeCodeGuardRepoCommit ||
		receipt.SourceTreeSHA256 == "" ||
		receipt.SourceTreeSHA256 != receipt.SHA256 {
		t.Fatalf("pinned source identity = %#v", receipt)
	}

	if err := teardownCodexCodeGuardSkill(opts); err != nil {
		t.Fatalf("teardownCodexCodeGuardSkill: %v", err)
	}
	for _, removed := range []string{
		targetDir,
		filepath.Join(userHome, ".agents", "skills"),
		filepath.Join(userHome, ".agents"),
		codexCodeGuardReceiptPath(opts),
	} {
		if _, err := os.Lstat(removed); !os.IsNotExist(err) {
			t.Fatalf("owned path survived exact teardown %s: %v", removed, err)
		}
	}
}

func TestCodexCodeGuardSkillMigratesLegacyOwnedReceiptToPinnedSourceAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "project-codeguard")
	sourceDir := filepath.Join(repoDir, "skills", nativeCodeGuardRepoSkillName)
	writeTestFile(t, filepath.Join(sourceDir, "SKILL.md"), `---
name: codeguard
---

# Software Security Skill (Project CodeGuard)

# pinned source
`)
	writeTestFile(t, filepath.Join(sourceDir, "rules", "pinned.md"), "# Pinned rule\n")

	oldOverride := nativeCodeGuardRepoDirOverride
	nativeCodeGuardRepoDirOverride = repoDir
	t.Cleanup(func() { nativeCodeGuardRepoDirOverride = oldOverride })

	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	targetDir := filepath.Join(userHome, ".agents", "skills", nativeCodeGuardCodexSkillName)
	legacySkill := filepath.Join(targetDir, "SKILL.md")
	writeTestFile(t, legacySkill, `---
name: codeguard
---

# Software Security Skill (Project CodeGuard)

# legacy mutable-main source
`)
	writeTestFile(t, filepath.Join(targetDir, "rules", "legacy.md"), "# Legacy rule\n")
	legacyDigest, exists, err := digestCodexCodeGuardSkill(targetDir)
	if err != nil || !exists {
		t.Fatalf("digest legacy owned skill: exists=%v err=%v", exists, err)
	}
	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	legacyReceipt := codexCodeGuardReceipt{
		Version: nativeCodeGuardCodexReceiptVersion,
		Target:  targetDir,
		SHA256:  legacyDigest,
	}
	if err := writeCodexCodeGuardReceipt(codexCodeGuardReceiptPath(opts), legacyReceipt); err != nil {
		t.Fatalf("write legacy ownership receipt: %v", err)
	}

	oldWriter := nativeCodeGuardCodexReceiptWriter
	receiptWrites := 0
	nativeCodeGuardCodexReceiptWriter = func(path string, receipt codexCodeGuardReceipt) error {
		receiptWrites++
		return writeCodexCodeGuardReceipt(path, receipt)
	}
	t.Cleanup(func() { nativeCodeGuardCodexReceiptWriter = oldWriter })

	if err := ensureCodexCodeGuardSkill(context.Background(), opts); err != nil {
		t.Fatalf("migrate legacy owned CodeGuard skill: %v", err)
	}
	if receiptWrites != 1 {
		t.Fatalf("migration receipt writes = %d, want 1", receiptWrites)
	}
	if data, err := os.ReadFile(legacySkill); err != nil {
		t.Fatalf("read migrated SKILL.md: %v", err)
	} else if !strings.Contains(string(data), "# pinned source") || strings.Contains(string(data), "legacy mutable-main") {
		t.Fatalf("legacy skill was not replaced by pinned source:\n%s", data)
	}
	if _, err := os.Lstat(filepath.Join(targetDir, "rules", "legacy.md")); !os.IsNotExist(err) {
		t.Fatalf("legacy-only file survived pinned migration: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "rules", "pinned.md")); err != nil {
		t.Fatalf("pinned rule was not installed: %v", err)
	}
	receipt, exists, err := loadCodexCodeGuardReceipt(opts, targetDir)
	if err != nil || !exists {
		t.Fatalf("load migrated receipt: exists=%v err=%v", exists, err)
	}
	if receipt.SourceCommit != nativeCodeGuardRepoCommit ||
		receipt.SourceTreeSHA256 == "" ||
		receipt.SourceTreeSHA256 != receipt.SHA256 ||
		receipt.SHA256 == legacyDigest {
		t.Fatalf("migrated receipt did not bind pinned source: %#v", receipt)
	}
	for _, retired := range []string{
		codexCodeGuardMigrationQuarantineDir(targetDir),
		codexCodeGuardMigrationJournalPath(opts),
	} {
		if _, err := os.Lstat(retired); !os.IsNotExist(err) {
			t.Fatalf("migration recovery artifact survived successful receipt publication %s: %v", retired, err)
		}
	}

	// A current pinned receipt must short-circuit without consulting the source
	// checkout or rewriting its authority record.
	nativeCodeGuardRepoDirOverride = filepath.Join(dir, "missing-source")
	if err := ensureCodexCodeGuardSkill(context.Background(), opts); err != nil {
		t.Fatalf("idempotent pinned ensure consulted source or rewrote target: %v", err)
	}
	if receiptWrites != 1 {
		t.Fatalf("idempotent pinned ensure receipt writes = %d, want 1", receiptWrites)
	}
}

func TestCodexCodeGuardLegacyMigrationReceiptFailureRestoresPriorOwnedTree(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "project-codeguard")
	sourceDir := filepath.Join(repoDir, "skills", nativeCodeGuardRepoSkillName)
	writeTestFile(t, filepath.Join(sourceDir, "SKILL.md"), `---
name: codeguard
---

# Software Security Skill (Project CodeGuard)

# pinned source
`)
	oldOverride := nativeCodeGuardRepoDirOverride
	nativeCodeGuardRepoDirOverride = repoDir
	t.Cleanup(func() { nativeCodeGuardRepoDirOverride = oldOverride })

	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	targetDir := filepath.Join(userHome, ".agents", "skills", nativeCodeGuardCodexSkillName)
	const legacyBody = `---
name: codeguard
---

# Software Security Skill (Project CodeGuard)

# legacy source must be restored
`
	writeTestFile(t, filepath.Join(targetDir, "SKILL.md"), legacyBody)
	legacyDigest, exists, err := digestCodexCodeGuardSkill(targetDir)
	if err != nil || !exists {
		t.Fatalf("digest legacy owned skill: exists=%v err=%v", exists, err)
	}
	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	legacyReceipt := codexCodeGuardReceipt{
		Version: nativeCodeGuardCodexReceiptVersion,
		Target:  targetDir,
		SHA256:  legacyDigest,
	}
	if err := writeCodexCodeGuardReceipt(codexCodeGuardReceiptPath(opts), legacyReceipt); err != nil {
		t.Fatalf("write legacy ownership receipt: %v", err)
	}

	oldWriter := nativeCodeGuardCodexReceiptWriter
	nativeCodeGuardCodexReceiptWriter = func(string, codexCodeGuardReceipt) error {
		return errors.New("fixture migration receipt failure")
	}
	t.Cleanup(func() { nativeCodeGuardCodexReceiptWriter = oldWriter })
	err = ensureCodexCodeGuardSkill(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "fixture migration receipt failure") {
		t.Fatalf("migration receipt failure error = %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(targetDir, "SKILL.md")); err != nil {
		t.Fatalf("prior owned tree was not restored: %v", err)
	} else if string(data) != legacyBody {
		t.Fatalf("prior owned tree changed after migration rollback:\n%s", data)
	}
	digest, exists, err := digestCodexCodeGuardSkill(targetDir)
	if err != nil || !exists || digest != legacyDigest {
		t.Fatalf("restored legacy digest = %q exists=%v err=%v, want %q", digest, exists, err, legacyDigest)
	}
	receipt, exists, err := loadCodexCodeGuardReceipt(opts, targetDir)
	if err != nil || !exists {
		t.Fatalf("legacy receipt was not preserved: exists=%v err=%v", exists, err)
	}
	if receipt.SourceCommit != "" || receipt.SourceTreeSHA256 != "" || receipt.SHA256 != legacyDigest {
		t.Fatalf("legacy receipt changed after failed migration: %#v", receipt)
	}
	for _, retired := range []string{
		codexCodeGuardMigrationQuarantineDir(targetDir),
		codexCodeGuardMigrationJournalPath(opts),
	} {
		if _, err := os.Lstat(retired); !os.IsNotExist(err) {
			t.Fatalf("migration rollback left recovery artifact %s: %v", retired, err)
		}
	}
}

func TestCodexCodeGuardMigrationRecoversEveryDurableCrashBoundary(t *testing.T) {
	tests := []struct {
		name  string
		stage int
	}{
		{name: "journal-published", stage: 0},
		{name: "prior-tree-quarantined", stage: 1},
		{name: "pinned-tree-installed", stage: 2},
		{name: "pinned-receipt-published", stage: 3},
		{name: "prior-tree-retired", stage: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCodexCodeGuardMigrationFixture(t)
			fixture.publishJournal(t)

			if test.stage >= 1 {
				if err := os.Rename(fixture.targetDir, fixture.quarantineDir); err != nil {
					t.Fatalf("simulate crash after prior-tree quarantine: %v", err)
				}
			}
			if test.stage >= 2 {
				if err := copyDirectoryAtomic(fixture.sourceDir, fixture.targetDir); err != nil {
					t.Fatalf("simulate crash after pinned-tree install: %v", err)
				}
			}
			if test.stage >= 3 {
				if err := writeCodexCodeGuardReceipt(
					codexCodeGuardReceiptPath(fixture.opts),
					fixture.pinnedReceipt,
				); err != nil {
					t.Fatalf("simulate crash after pinned-receipt publication: %v", err)
				}
				// Recovery of a committed receipt must happen before the normal
				// pinned-receipt early return and without consulting the source.
				nativeCodeGuardRepoDirOverride = filepath.Join(fixture.root, "missing-source")
			}
			if test.stage >= 4 {
				if err := os.RemoveAll(fixture.quarantineDir); err != nil {
					t.Fatalf("simulate crash after prior-tree retirement: %v", err)
				}
			}

			if err := ensureCodexCodeGuardSkill(context.Background(), fixture.opts); err != nil {
				t.Fatalf("recover interrupted migration: %v", err)
			}
			fixture.requireCommitted(t)
		})
	}
}

func TestCodexCodeGuardCrashStagingAndLegacyTempsStayOutOfDiscovery(t *testing.T) {
	fixture := newCodexCodeGuardMigrationFixture(t)
	fixture.publishJournal(t)
	if err := os.Rename(fixture.targetDir, fixture.quarantineDir); err != nil {
		t.Fatalf("quarantine prior tree: %v", err)
	}

	discoveryRoot := filepath.Dir(fixture.targetDir)
	stageDir := codexCodeGuardStagingDir(fixture.targetDir)
	if rel, err := filepath.Rel(discoveryRoot, stageDir); err != nil ||
		(rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		t.Fatalf("CodeGuard staging path %q is inside discovery root %q", stageDir, discoveryRoot)
	}
	if err := copyDirectory(fixture.sourceDir, stageDir); err != nil {
		t.Fatalf("simulate crash with complete out-of-root stage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stageDir, "SKILL.md")); err != nil {
		t.Fatalf("crash fixture stage is not SKILL.md-bearing: %v", err)
	}

	legacyStage := fixture.targetDir + ".tmp-123456789"
	legacyRemoval := fixture.targetDir + ".defenseclaw-remove-123456790"
	for _, path := range []string{legacyStage, legacyRemoval} {
		if err := copyDirectory(fixture.sourceDir, path); err != nil {
			t.Fatalf("create authenticated legacy discovery temp %s: %v", path, err)
		}
		if _, err := os.Stat(filepath.Join(path, "SKILL.md")); err != nil {
			t.Fatalf("legacy crash fixture is not SKILL.md-bearing: %v", err)
		}
	}

	if err := ensureCodexCodeGuardSkill(context.Background(), fixture.opts); err != nil {
		t.Fatalf("recover crash staging and legacy temps: %v", err)
	}
	fixture.requireCommitted(t)
	for _, retired := range []string{stageDir, legacyStage, legacyRemoval} {
		if _, err := os.Lstat(retired); !os.IsNotExist(err) {
			t.Fatalf("authenticated crash artifact remained discoverable at %s: %v", retired, err)
		}
	}
	assertNoTransientCodeGuardSkillInDiscoveryRoot(t, discoveryRoot, fixture.targetDir)
}

func TestCodexCodeGuardMigrationRecoversRollbackCrashBoundaries(t *testing.T) {
	for _, test := range []struct {
		name          string
		priorRestored bool
	}{
		{name: "pinned-tree-hidden"},
		{name: "prior-tree-restored", priorRestored: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCodexCodeGuardMigrationFixture(t)
			fixture.publishJournal(t)
			if err := os.Rename(fixture.targetDir, fixture.quarantineDir); err != nil {
				t.Fatalf("quarantine prior tree: %v", err)
			}
			if err := copyDirectoryAtomic(fixture.sourceDir, fixture.targetDir); err != nil {
				t.Fatalf("install pinned tree: %v", err)
			}
			rollback := codexCodeGuardRollbackQuarantineDir(fixture.targetDir)
			if rel, err := filepath.Rel(filepath.Dir(fixture.targetDir), rollback); err != nil ||
				(rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				t.Fatalf("CodeGuard rollback quarantine %q is inside the discovery root", rollback)
			}
			if err := os.Rename(fixture.targetDir, rollback); err != nil {
				t.Fatalf("simulate crash after hiding pinned rollback tree: %v", err)
			}
			if test.priorRestored {
				if err := os.Rename(fixture.quarantineDir, fixture.targetDir); err != nil {
					t.Fatalf("simulate crash after restoring prior tree: %v", err)
				}
			}

			if err := ensureCodexCodeGuardSkill(context.Background(), fixture.opts); err != nil {
				t.Fatalf("recover rollback crash boundary: %v", err)
			}
			fixture.requireCommitted(t)
			if _, err := os.Lstat(rollback); !os.IsNotExist(err) {
				t.Fatalf("rollback quarantine survived recovery: %v", err)
			}
		})
	}
}

func TestCodexCodeGuardMigrationPreservesUnexpectedRollbackQuarantine(t *testing.T) {
	fixture := newCodexCodeGuardMigrationFixture(t)
	fixture.publishJournal(t)
	rollback := codexCodeGuardRollbackQuarantineDir(fixture.targetDir)
	writeTestFile(t, filepath.Join(rollback, "SKILL.md"), `---
name: codeguard
---

# operator replacement
`)

	err := ensureCodexCodeGuardSkill(context.Background(), fixture.opts)
	if err == nil || !strings.Contains(err.Error(), "rollback quarantine changed") ||
		!strings.Contains(err.Error(), "preserving") {
		t.Fatalf("unexpected rollback quarantine error = %v, want preservation refusal", err)
	}
	if data, readErr := os.ReadFile(filepath.Join(rollback, "SKILL.md")); readErr != nil ||
		!strings.Contains(string(data), "operator replacement") {
		t.Fatalf("unexpected rollback quarantine was not preserved: data=%q err=%v", data, readErr)
	}
}

func TestCodexCodeGuardLegacyTempRecoveryPreservesUnexpectedReplacement(t *testing.T) {
	fixture := newCodexCodeGuardMigrationFixture(t)
	unexpected := fixture.targetDir + ".tmp-123456789"
	writeTestFile(t, filepath.Join(unexpected, "SKILL.md"), `---
name: codeguard
---

# operator replacement
`)

	err := ensureCodexCodeGuardSkill(context.Background(), fixture.opts)
	if err == nil || !strings.Contains(err.Error(), "unauthenticated digest") {
		t.Fatalf("unexpected legacy staging error = %v, want authenticated refusal", err)
	}
	if data, readErr := os.ReadFile(filepath.Join(unexpected, "SKILL.md")); readErr != nil ||
		!strings.Contains(string(data), "operator replacement") {
		t.Fatalf("unexpected legacy staging replacement was not preserved: data=%q err=%v", data, readErr)
	}
}

func TestCodexCodeGuardStagingRecoveryPreservesUnexpectedReplacement(t *testing.T) {
	fixture := newCodexCodeGuardMigrationFixture(t)
	stageDir := codexCodeGuardStagingDir(fixture.targetDir)
	writeTestFile(t, filepath.Join(stageDir, "SKILL.md"), `---
name: codeguard
---

# operator replacement
`)

	err := ensureCodexCodeGuardSkill(context.Background(), fixture.opts)
	if err == nil || !strings.Contains(err.Error(), "staging path") ||
		!strings.Contains(err.Error(), "preserving it") {
		t.Fatalf("unexpected out-of-root staging error = %v, want preservation refusal", err)
	}
	if data, readErr := os.ReadFile(filepath.Join(stageDir, "SKILL.md")); readErr != nil ||
		!strings.Contains(string(data), "operator replacement") {
		t.Fatalf("unexpected staging replacement was not preserved: data=%q err=%v", data, readErr)
	}
}

func TestCodexCodeGuardTeardownRecoversOutOfRootRemovalQuarantine(t *testing.T) {
	fixture := newCodexCodeGuardMigrationFixture(t)
	quarantine := codexCodeGuardRemovalQuarantineDir(fixture.targetDir)
	discoveryRoot := filepath.Dir(fixture.targetDir)
	if rel, err := filepath.Rel(discoveryRoot, quarantine); err != nil ||
		(rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		t.Fatalf("CodeGuard removal quarantine %q is inside discovery root %q", quarantine, discoveryRoot)
	}
	if err := os.Rename(fixture.targetDir, quarantine); err != nil {
		t.Fatalf("simulate crash after removal quarantine rename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(quarantine, "SKILL.md")); err != nil {
		t.Fatalf("removal crash fixture is not SKILL.md-bearing: %v", err)
	}

	if err := teardownCodexCodeGuardSkill(fixture.opts); err != nil {
		t.Fatalf("recover interrupted out-of-root removal: %v", err)
	}
	for _, removed := range []string{
		fixture.targetDir,
		quarantine,
		codexCodeGuardReceiptPath(fixture.opts),
	} {
		if _, err := os.Lstat(removed); !os.IsNotExist(err) {
			t.Fatalf("interrupted removal artifact survived at %s: %v", removed, err)
		}
	}
}

func TestCodexCodeGuardRemovalRecoveryPreservesUnexpectedReplacement(t *testing.T) {
	fixture := newCodexCodeGuardMigrationFixture(t)
	quarantine := codexCodeGuardRemovalQuarantineDir(fixture.targetDir)
	writeTestFile(t, filepath.Join(quarantine, "SKILL.md"), `---
name: codeguard
---

# operator replacement
`)

	err := teardownCodexCodeGuardSkill(fixture.opts)
	if err == nil || !strings.Contains(err.Error(), "not authenticated") ||
		!strings.Contains(err.Error(), "preserving") {
		t.Fatalf("unexpected removal replacement error = %v, want preservation refusal", err)
	}
	for _, preserved := range []string{fixture.targetDir, quarantine} {
		if _, statErr := os.Stat(filepath.Join(preserved, "SKILL.md")); statErr != nil {
			t.Fatalf("unexpected removal state was not preserved at %s: %v", preserved, statErr)
		}
	}
}

func assertNoTransientCodeGuardSkillInDiscoveryRoot(t *testing.T, discoveryRoot, targetDir string) {
	t.Helper()
	entries, err := os.ReadDir(discoveryRoot)
	if err != nil {
		t.Fatalf("read CodeGuard discovery root: %v", err)
	}
	for _, entry := range entries {
		path := filepath.Join(discoveryRoot, entry.Name())
		if path == targetDir {
			continue
		}
		if _, err := os.Stat(filepath.Join(path, "SKILL.md")); err == nil {
			t.Fatalf("transient SKILL.md remained discoverable at %s", path)
		}
	}
}

func TestCodexCodeGuardMigrationRecoveryPreservesUnexpectedReplacement(t *testing.T) {
	fixture := newCodexCodeGuardMigrationFixture(t)
	fixture.publishJournal(t)
	if err := os.Rename(fixture.targetDir, fixture.quarantineDir); err != nil {
		t.Fatalf("quarantine prior tree: %v", err)
	}
	if err := copyDirectoryAtomic(fixture.sourceDir, fixture.targetDir); err != nil {
		t.Fatalf("install pinned tree: %v", err)
	}
	foreign := filepath.Join(fixture.targetDir, "foreign.md")
	writeTestFile(t, foreign, "operator replacement during interrupted migration\n")

	nativeCodeGuardRepoDirOverride = filepath.Join(fixture.root, "missing-source")
	err := ensureCodexCodeGuardSkill(context.Background(), fixture.opts)
	if err == nil || !strings.Contains(err.Error(), "unexpected prior state") {
		t.Fatalf("unexpected replacement recovery error = %v, want fail-closed state refusal", err)
	}
	if data, readErr := os.ReadFile(foreign); readErr != nil || !strings.Contains(string(data), "operator replacement") {
		t.Fatalf("unexpected replacement was not preserved: data=%q err=%v", data, readErr)
	}
	if digest, exists, digestErr := digestCodexCodeGuardSkill(fixture.quarantineDir); digestErr != nil || !exists || digest != fixture.legacyReceipt.SHA256 {
		t.Fatalf(
			"prior quarantine after refusal = %q exists=%v err=%v, want %q",
			digest,
			exists,
			digestErr,
			fixture.legacyReceipt.SHA256,
		)
	}
	if _, statErr := os.Lstat(codexCodeGuardMigrationJournalPath(fixture.opts)); statErr != nil {
		t.Fatalf("fail-closed recovery did not preserve its journal: %v", statErr)
	}
}

func TestCodexCodeGuardMigrationRecoversAmbiguousReceiptPublication(t *testing.T) {
	fixture := newCodexCodeGuardMigrationFixture(t)
	oldWriter := nativeCodeGuardCodexReceiptWriter
	nativeCodeGuardCodexReceiptWriter = func(path string, receipt codexCodeGuardReceipt) error {
		if err := writeCodexCodeGuardReceipt(path, receipt); err != nil {
			return err
		}
		return errors.New("fixture failure after receipt publication")
	}
	t.Cleanup(func() { nativeCodeGuardCodexReceiptWriter = oldWriter })

	err := ensureCodexCodeGuardSkill(context.Background(), fixture.opts)
	if err == nil || !strings.Contains(err.Error(), "fixture failure after receipt publication") {
		t.Fatalf("ambiguous receipt publication error = %v", err)
	}
	if digest, exists, digestErr := digestCodexCodeGuardSkill(fixture.targetDir); digestErr != nil || !exists || digest != fixture.pinnedDigest {
		t.Fatalf("pinned target after ambiguous publication = %q exists=%v err=%v", digest, exists, digestErr)
	}
	for _, recoverable := range []string{
		fixture.quarantineDir,
		codexCodeGuardMigrationJournalPath(fixture.opts),
	} {
		if _, statErr := os.Lstat(recoverable); statErr != nil {
			t.Fatalf("ambiguous publication did not preserve recovery artifact %s: %v", recoverable, statErr)
		}
	}

	nativeCodeGuardCodexReceiptWriter = oldWriter
	nativeCodeGuardRepoDirOverride = filepath.Join(fixture.root, "missing-source")
	if err := ensureCodexCodeGuardSkill(context.Background(), fixture.opts); err != nil {
		t.Fatalf("recover visible pinned receipt after ambiguous publication: %v", err)
	}
	fixture.requireCommitted(t)
}

func TestCodexCodeGuardMigrationRecoveryHonorsJournaledImmutableCommit(t *testing.T) {
	fixture := newCodexCodeGuardMigrationFixture(t)
	priorDefenseClawCommit := strings.Repeat("b", 40)
	journal := codexCodeGuardMigrationJournal{
		Version:      nativeCodeGuardMigrationVersion,
		Target:       fixture.targetDir,
		Quarantine:   fixture.quarantineDir,
		PriorReceipt: fixture.legacyReceipt,
		PinnedSHA256: fixture.pinnedDigest,
		SourceCommit: priorDefenseClawCommit,
	}
	if err := writeCodexCodeGuardMigrationJournal(codexCodeGuardMigrationJournalPath(fixture.opts), journal); err != nil {
		t.Fatalf("publish prior-version migration journal: %v", err)
	}
	if err := os.Rename(fixture.targetDir, fixture.quarantineDir); err != nil {
		t.Fatalf("quarantine prior tree: %v", err)
	}
	if err := copyDirectoryAtomic(fixture.sourceDir, fixture.targetDir); err != nil {
		t.Fatalf("install prior-version pinned tree: %v", err)
	}
	priorPinnedReceipt := codexCodeGuardPinnedReceiptAtCommit(
		fixture.legacyReceipt,
		fixture.pinnedDigest,
		priorDefenseClawCommit,
	)
	if err := writeCodexCodeGuardReceipt(codexCodeGuardReceiptPath(fixture.opts), priorPinnedReceipt); err != nil {
		t.Fatalf("publish prior-version pinned receipt: %v", err)
	}

	if err := ensureCodexCodeGuardSkill(context.Background(), fixture.opts); err != nil {
		t.Fatalf("recover prior-version immutable migration and refresh receipt: %v", err)
	}
	fixture.requireCommitted(t)
}

func TestCodexCodeGuardTeardownRecoversInterruptedMigrationFirst(t *testing.T) {
	fixture := newCodexCodeGuardMigrationFixture(t)
	fixture.publishJournal(t)
	if err := os.Rename(fixture.targetDir, fixture.quarantineDir); err != nil {
		t.Fatalf("quarantine prior tree: %v", err)
	}
	if err := copyDirectoryAtomic(fixture.sourceDir, fixture.targetDir); err != nil {
		t.Fatalf("install pinned tree: %v", err)
	}

	if err := teardownCodexCodeGuardSkill(fixture.opts); err != nil {
		t.Fatalf("teardown interrupted migration: %v", err)
	}
	for _, removed := range []string{
		fixture.targetDir,
		fixture.quarantineDir,
		codexCodeGuardReceiptPath(fixture.opts),
		codexCodeGuardMigrationJournalPath(fixture.opts),
	} {
		if _, err := os.Lstat(removed); !os.IsNotExist(err) {
			t.Fatalf("teardown retained interrupted migration path %s: %v", removed, err)
		}
	}
}

type codexCodeGuardMigrationFixture struct {
	root          string
	opts          SetupOpts
	sourceDir     string
	targetDir     string
	quarantineDir string
	legacyReceipt codexCodeGuardReceipt
	pinnedReceipt codexCodeGuardReceipt
	pinnedDigest  string
}

func newCodexCodeGuardMigrationFixture(t *testing.T) codexCodeGuardMigrationFixture {
	t.Helper()
	root := t.TempDir()
	repoDir := filepath.Join(root, "project-codeguard")
	sourceDir := filepath.Join(repoDir, "skills", nativeCodeGuardRepoSkillName)
	writeTestFile(t, filepath.Join(sourceDir, "SKILL.md"), `---
name: codeguard
---

# Software Security Skill (Project CodeGuard)

# pinned crash-recovery source
`)
	writeTestFile(t, filepath.Join(sourceDir, "rules", "pinned.md"), "# Pinned rule\n")
	pinnedDigest, exists, err := digestCodexCodeGuardSkill(sourceDir)
	if err != nil || !exists {
		t.Fatalf("digest pinned fixture source: exists=%v err=%v", exists, err)
	}

	oldOverride := nativeCodeGuardRepoDirOverride
	nativeCodeGuardRepoDirOverride = repoDir
	t.Cleanup(func() { nativeCodeGuardRepoDirOverride = oldOverride })

	userHome := filepath.Join(root, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	targetDir := filepath.Join(userHome, ".agents", "skills", nativeCodeGuardCodexSkillName)
	writeTestFile(t, filepath.Join(targetDir, "SKILL.md"), `---
name: codeguard
---

# Software Security Skill (Project CodeGuard)

# legacy crash-recovery source
`)
	writeTestFile(t, filepath.Join(targetDir, "rules", "legacy.md"), "# Legacy rule\n")
	legacyDigest, exists, err := digestCodexCodeGuardSkill(targetDir)
	if err != nil || !exists {
		t.Fatalf("digest legacy fixture target: exists=%v err=%v", exists, err)
	}

	opts := SetupOpts{DataDir: filepath.Join(root, "data")}
	legacyReceipt := codexCodeGuardReceipt{
		Version: nativeCodeGuardCodexReceiptVersion,
		Target:  targetDir,
		SHA256:  legacyDigest,
	}
	if err := writeCodexCodeGuardReceipt(codexCodeGuardReceiptPath(opts), legacyReceipt); err != nil {
		t.Fatalf("write legacy fixture receipt: %v", err)
	}
	quarantineDir := codexCodeGuardMigrationQuarantineDir(targetDir)
	rel, err := filepath.Rel(filepath.Dir(targetDir), quarantineDir)
	if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		t.Fatalf("migration quarantine %q is still inside skill discovery root %q", quarantineDir, filepath.Dir(targetDir))
	}

	return codexCodeGuardMigrationFixture{
		root:          root,
		opts:          opts,
		sourceDir:     sourceDir,
		targetDir:     targetDir,
		quarantineDir: quarantineDir,
		legacyReceipt: legacyReceipt,
		pinnedReceipt: codexCodeGuardPinnedReceipt(legacyReceipt, pinnedDigest),
		pinnedDigest:  pinnedDigest,
	}
}

func (fixture codexCodeGuardMigrationFixture) publishJournal(t *testing.T) {
	t.Helper()
	journal := codexCodeGuardMigrationJournal{
		Version:      nativeCodeGuardMigrationVersion,
		Target:       fixture.targetDir,
		Quarantine:   fixture.quarantineDir,
		PriorReceipt: fixture.legacyReceipt,
		PinnedSHA256: fixture.pinnedDigest,
		SourceCommit: nativeCodeGuardRepoCommit,
	}
	if err := writeCodexCodeGuardMigrationJournal(codexCodeGuardMigrationJournalPath(fixture.opts), journal); err != nil {
		t.Fatalf("publish fixture migration journal: %v", err)
	}
}

func (fixture codexCodeGuardMigrationFixture) requireCommitted(t *testing.T) {
	t.Helper()
	digest, exists, err := digestCodexCodeGuardSkill(fixture.targetDir)
	if err != nil || !exists || digest != fixture.pinnedDigest {
		t.Fatalf("recovered target digest = %q exists=%v err=%v, want %q", digest, exists, err, fixture.pinnedDigest)
	}
	receipt, exists, err := loadCodexCodeGuardReceipt(fixture.opts, fixture.targetDir)
	if err != nil || !exists || receipt != fixture.pinnedReceipt {
		t.Fatalf("recovered receipt = %#v exists=%v err=%v, want %#v", receipt, exists, err, fixture.pinnedReceipt)
	}
	for _, retired := range []string{
		fixture.quarantineDir,
		codexCodeGuardMigrationJournalPath(fixture.opts),
	} {
		if _, err := os.Lstat(retired); !os.IsNotExist(err) {
			t.Fatalf("recovered migration retained %s: %v", retired, err)
		}
	}
}

func TestCodexCodeGuardSkillInstallRefusesExistingUnrelatedSkill(t *testing.T) {
	dir := t.TempDir()
	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	codexHome := filepath.Join(dir, "codex-home")
	t.Setenv("CODEX_HOME", codexHome)

	targetSkill := filepath.Join(
		userHome,
		".agents",
		"skills",
		nativeCodeGuardCodexSkillName,
		"SKILL.md",
	)
	writeTestFile(t, targetSkill, `---
name: software-security
---

# User-owned skill
`)

	err = ensureCodexCodeGuardSkill(context.Background(), SetupOpts{DataDir: filepath.Join(dir, "data")})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("ensureCodexCodeGuardSkill error = %v, want refusing to overwrite", err)
	}
	if data, err := os.ReadFile(targetSkill); err != nil {
		t.Fatalf("read target skill: %v", err)
	} else if strings.Contains(string(data), "Project CodeGuard") {
		t.Fatalf("installer overwrote user-owned skill:\n%s", data)
	}
}

func TestCodexCodeGuardSkillTeardownPreservesPreexistingInstall(t *testing.T) {
	dir := t.TempDir()
	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)

	targetSkill := filepath.Join(
		userHome,
		".agents",
		"skills",
		nativeCodeGuardCodexSkillName,
		"SKILL.md",
	)
	original := `---
name: codeguard
---

# Software Security Skill (Project CodeGuard)
`
	writeTestFile(t, targetSkill, original)
	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	if err := ensureCodexCodeGuardSkill(context.Background(), opts); err != nil {
		t.Fatalf("ensure preexisting Codex CodeGuard skill: %v", err)
	}
	if _, err := os.Lstat(codexCodeGuardReceiptPath(opts)); !os.IsNotExist(err) {
		t.Fatalf("preexisting skill was incorrectly claimed by a receipt: %v", err)
	}
	if err := teardownCodexCodeGuardSkill(opts); err != nil {
		t.Fatalf("teardown preexisting Codex CodeGuard skill: %v", err)
	}
	if data, err := os.ReadFile(targetSkill); err != nil {
		t.Fatalf("preexisting Codex CodeGuard skill was removed: %v", err)
	} else if string(data) != original {
		t.Fatalf("preexisting Codex CodeGuard skill changed:\n%s", data)
	}
}

func TestCodexCodeGuardSkillTeardownPreservesOperatorModifiedOwnedInstall(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "project-codeguard")
	sourceDir := filepath.Join(repoDir, "skills", nativeCodeGuardRepoSkillName)
	writeTestFile(t, filepath.Join(sourceDir, "SKILL.md"), `---
name: codeguard
---

# Software Security Skill (Project CodeGuard)
`)
	oldOverride := nativeCodeGuardRepoDirOverride
	nativeCodeGuardRepoDirOverride = repoDir
	t.Cleanup(func() { nativeCodeGuardRepoDirOverride = oldOverride })

	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)

	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	if err := ensureCodexCodeGuardSkill(context.Background(), opts); err != nil {
		t.Fatalf("ensureCodexCodeGuardSkill: %v", err)
	}
	targetSkill := filepath.Join(
		userHome,
		".agents",
		"skills",
		nativeCodeGuardCodexSkillName,
		"SKILL.md",
	)
	file, err := os.OpenFile(targetSkill, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("\n# operator modification\n"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = ensureCodexCodeGuardSkill(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "was modified; refusing to overwrite") {
		t.Fatalf("ensure modified owned skill error = %v, want drift refusal", err)
	}
	if _, err := os.Stat(targetSkill); err != nil {
		t.Fatalf("operator-modified skill was removed during ensure: %v", err)
	}

	err = teardownCodexCodeGuardSkill(opts)
	if err == nil || !strings.Contains(err.Error(), "was modified; preserving it") {
		t.Fatalf("teardown modified owned skill error = %v, want preservation refusal", err)
	}
	if _, err := os.Stat(targetSkill); err != nil {
		t.Fatalf("operator-modified skill was removed: %v", err)
	}
	if _, err := os.Stat(codexCodeGuardReceiptPath(opts)); err != nil {
		t.Fatalf("ownership receipt was removed after drift refusal: %v", err)
	}
}

func TestCodexCodeGuardSkillReceiptFailureRollsBackCopiedTree(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "project-codeguard")
	sourceDir := filepath.Join(repoDir, "skills", nativeCodeGuardRepoSkillName)
	writeTestFile(t, filepath.Join(sourceDir, "SKILL.md"), `---
name: codeguard
---

# Software Security Skill (Project CodeGuard)
`)
	oldOverride := nativeCodeGuardRepoDirOverride
	nativeCodeGuardRepoDirOverride = repoDir
	t.Cleanup(func() { nativeCodeGuardRepoDirOverride = oldOverride })

	oldWriter := nativeCodeGuardCodexReceiptWriter
	nativeCodeGuardCodexReceiptWriter = func(string, codexCodeGuardReceipt) error {
		return errors.New("fixture receipt write failure")
	}
	t.Cleanup(func() { nativeCodeGuardCodexReceiptWriter = oldWriter })

	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)

	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	err = ensureCodexCodeGuardSkill(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "fixture receipt write failure") {
		t.Fatalf("receipt failure error = %v, want injected failure", err)
	}
	for _, removed := range []string{
		filepath.Join(userHome, ".agents", "skills", nativeCodeGuardCodexSkillName),
		filepath.Join(userHome, ".agents", "skills"),
		filepath.Join(userHome, ".agents"),
	} {
		if _, err := os.Lstat(removed); !os.IsNotExist(err) {
			t.Fatalf("receipt failure left copied path %s: %v", removed, err)
		}
	}
}

func TestCodexSetupRollsBackRuntimeAfterHookWriterFailure(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Codex managed-hook lifecycle is Windows-only")
	}
	dir := testenv.PrivateTempDir(t)
	dataDir := filepath.Join(dir, "defenseclaw")
	configPath := filepath.Join(dir, "codex", "config.toml")
	managedPath := filepath.Join(filepath.Dir(configPath), codexManagedConfigLogicalName)
	configBefore := []byte("model = \"gpt-5\"\r\n")
	managedBefore := []byte("[operator_policy]\r\nmode = \"strict\"\r\n")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, managedBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	hookDir := filepath.Join(dataDir, "hooks")
	priorHookPath := filepath.Join(hookDir, "inspect-tool.sh")
	priorHook := []byte("#!/bin/sh\n# preexisting runtime\n")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priorHookPath, priorHook, 0o700); err != nil {
		t.Fatal(err)
	}

	previousConfig := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousConfig })
	previousInspector := codexPolicyInspector
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{Source: "focused lifecycle test"}, nil
	}
	t.Cleanup(func() { codexPolicyInspector = previousInspector })
	setHookBinaryOverride(t, filepath.Join(dir, "DefenseClaw", windowsHookBinaryName))

	previousWriter := codexWriteHookScriptsForSetup
	codexWriteHookScriptsForSetup = func(hookDir string, opts SetupOpts, connector Connector) error {
		if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, connector); err != nil {
			return err
		}
		return errors.New("fixture hook runtime write failure")
	}
	t.Cleanup(func() { codexWriteHookScriptsForSetup = previousWriter })

	err := NewCodexConnector().Setup(context.Background(), SetupOpts{
		DataDir:        dataDir,
		APIAddr:        "127.0.0.1:18970",
		HookContractID: "codex-hooks-v3",
	})
	if err == nil || !strings.Contains(err.Error(), "fixture hook runtime write failure") {
		t.Fatalf("Setup hook runtime failure = %v, want injected post-write failure", err)
	}
	for path, before := range map[string][]byte{
		configPath:    configBefore,
		managedPath:   managedBefore,
		priorHookPath: priorHook,
	} {
		after, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read rolled-back %s: %v", path, readErr)
		}
		if !bytes.Equal(after, before) {
			t.Fatalf("failed repair Setup did not restore %s byte-for-byte\nbefore:\n%s\nafter:\n%s", path, before, after)
		}
	}
	entries, err := os.ReadDir(hookDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(priorHookPath) {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("failed repair Setup changed runtime artifact inventory: %v", names)
	}
	assertCodexFailedSetupBackupsRemoved(t, dataDir)
}

func TestCodexSetupUserConfigFailureRollsBackManagedAndRuntime(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Codex managed-hook lifecycle is Windows-only")
	}
	dir := testenv.PrivateTempDir(t)
	dataDir := filepath.Join(dir, "defenseclaw")
	configPath := filepath.Join(dir, "codex", "config.toml")
	managedPath := filepath.Join(filepath.Dir(configPath), codexManagedConfigLogicalName)
	configBefore := []byte("[features]\r\nhooks = false\r\n")
	managedBefore := []byte("[operator_policy]\r\nmode = \"strict\"\r\n")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, managedBefore, 0o600); err != nil {
		t.Fatal(err)
	}

	previousConfig := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousConfig })
	previousInspector := codexPolicyInspector
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{Source: "focused lifecycle test"}, nil
	}
	t.Cleanup(func() { codexPolicyInspector = previousInspector })
	setHookBinaryOverride(t, filepath.Join(dir, "DefenseClaw", windowsHookBinaryName))

	err := NewCodexConnector().Setup(context.Background(), SetupOpts{
		DataDir:        dataDir,
		APIAddr:        "127.0.0.1:18970",
		HookContractID: "codex-hooks-v3",
	})
	if err == nil || !strings.Contains(err.Error(), "Codex hooks are disabled") {
		t.Fatalf("Setup disabled user config error = %v, want config-patch refusal", err)
	}
	assertCodexFailedSetupRestored(t, dataDir, configPath, managedPath, configBefore, managedBefore)
}

func TestCodexSetupRollsBackBothConfigLayersAfterCodeGuardFailure(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("managed Codex hook layer is native-Windows-only")
	}
	dir := testenv.PrivateTempDir(t)
	dataDir := filepath.Join(dir, "defenseclaw")
	configPath := filepath.Join(dir, "codex", "config.toml")
	managedPath := filepath.Join(filepath.Dir(configPath), codexManagedConfigLogicalName)
	configBefore := []byte("model = \"gpt-5\"\r\n")
	managedBefore := []byte("[operator_policy]\r\nmode = \"strict\"\r\n")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, managedBefore, 0o600); err != nil {
		t.Fatal(err)
	}

	previousConfig := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousConfig })
	previousInspector := codexPolicyInspector
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{Source: "focused lifecycle test"}, nil
	}
	t.Cleanup(func() { codexPolicyInspector = previousInspector })
	setHookBinaryOverride(t, filepath.Join(dir, "DefenseClaw", windowsHookBinaryName))

	emptyRepo := filepath.Join(dir, "invalid-project-codeguard")
	oldOverride := nativeCodeGuardRepoDirOverride
	nativeCodeGuardRepoDirOverride = emptyRepo
	t.Cleanup(func() { nativeCodeGuardRepoDirOverride = oldOverride })

	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)

	err = NewCodexConnector().Setup(context.Background(), SetupOpts{
		DataDir:          dataDir,
		APIAddr:          "127.0.0.1:18970",
		InstallCodeGuard: true,
		HookContractID:   "codex-hooks-v3",
	})
	if err == nil || !strings.Contains(err.Error(), "CodeGuard skill install") {
		t.Fatalf("Setup CodeGuard failure = %v, want post-patch install failure", err)
	}
	assertCodexFailedSetupRestored(t, dataDir, configPath, managedPath, configBefore, managedBefore)
}

func assertCodexFailedSetupRestored(
	t *testing.T,
	dataDir string,
	configPath string,
	managedPath string,
	configBefore []byte,
	managedBefore []byte,
) {
	t.Helper()
	for path, before := range map[string][]byte{
		configPath:  configBefore,
		managedPath: managedBefore,
	} {
		after, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read rolled-back %s: %v", path, readErr)
		}
		if !bytes.Equal(after, before) {
			t.Fatalf("failed Setup did not restore %s byte-for-byte\nbefore:\n%s\nafter:\n%s", path, before, after)
		}
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "hooks")); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(filepath.Join(dataDir, "hooks"))
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("failed fresh Setup left hook scripts or scoped tokens (%v): %v", err, names)
	}
	assertCodexFailedSetupBackupsRemoved(t, dataDir)
}

func assertCodexFailedSetupBackupsRemoved(t *testing.T, dataDir string) {
	t.Helper()
	for _, backupPath := range []string{
		filepath.Join(dataDir, "codex_config_backup.json"),
		managedFileBackupPath(dataDir, "codex", "config.toml"),
		managedFileBackupPath(dataDir, "codex", codexManagedConfigLogicalName),
	} {
		if _, err := os.Lstat(backupPath); !os.IsNotExist(err) {
			t.Fatalf("failed fresh Setup left rollback backup %s: %v", backupPath, err)
		}
	}
}

func TestClaudeCodeCodeGuardPluginInstallRunsMarketplaceAndPluginCommands(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "claude.log")
	claudePath := installFakeClaude(t, dir)
	t.Setenv("DEFENSECLAW_FAKE_CLAUDE_LOG", logPath)
	previousValidator := validateClaudeCodeCodeGuardExecutable
	validateClaudeCodeCodeGuardExecutable = func(SetupOpts) error { return nil }
	t.Cleanup(func() { validateClaudeCodeCodeGuardExecutable = previousValidator })

	if err := ensureClaudeCodeCodeGuardPlugin(context.Background(), SetupOpts{AgentExecutable: claudePath}); err != nil {
		t.Fatalf("ensureClaudeCodeCodeGuardPlugin: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake claude log: %v", err)
	}
	got := string(logData)
	for _, want := range []string{
		"plugin list",
		"plugin marketplace add " + nativeCodeGuardClaudeMarketplace,
		"plugin install --scope user " + nativeCodeGuardClaudePlugin,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("fake claude log missing %q:\n%s", want, got)
		}
	}
}

func TestClaudeCodeCodeGuardPluginInstallSkipsWhenAlreadyInstalled(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "claude.log")
	claudePath := installFakeClaude(t, dir)
	t.Setenv("DEFENSECLAW_FAKE_CLAUDE_LOG", logPath)
	t.Setenv("DEFENSECLAW_FAKE_CLAUDE_LIST", nativeCodeGuardClaudePlugin)
	previousValidator := validateClaudeCodeCodeGuardExecutable
	validateClaudeCodeCodeGuardExecutable = func(SetupOpts) error { return nil }
	t.Cleanup(func() { validateClaudeCodeCodeGuardExecutable = previousValidator })

	if err := ensureClaudeCodeCodeGuardPlugin(context.Background(), SetupOpts{AgentExecutable: claudePath}); err != nil {
		t.Fatalf("ensureClaudeCodeCodeGuardPlugin: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake claude log: %v", err)
	}
	got := strings.TrimSpace(string(logData))
	if got != "plugin list" {
		t.Fatalf("fake claude log = %q, want only plugin list", got)
	}
}

func installFakeClaude(t *testing.T, dir string) string {
	t.Helper()
	binDir := filepath.Join(dir, "bin")
	name := "claude"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	source := filepath.Join(binDir, "main.go")
	writeTestFile(t, source, `package main
import ("fmt"; "os"; "strings")
func main() {
  f, err := os.OpenFile(os.Getenv("DEFENSECLAW_FAKE_CLAUDE_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
  if err != nil { panic(err) }
  _, _ = fmt.Fprintln(f, strings.Join(os.Args[1:], " "))
  _ = f.Close()
  if len(os.Args) >= 3 && os.Args[1] == "plugin" && os.Args[2] == "list" { fmt.Println(os.Getenv("DEFENSECLAW_FAKE_CLAUDE_LIST")) }
}
`)
	claudePath := filepath.Join(binDir, name)
	if output, err := exec.Command("go", "build", "-o", claudePath, source).CombinedOutput(); err != nil {
		t.Fatalf("build fake claude: %v\n%s", err, output)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return claudePath
}

func TestNativeCodeGuardSourceIsPinnedToCommit(t *testing.T) {
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(nativeCodeGuardRepoCommit) {
		t.Fatalf("Project CodeGuard source revision %q is not a full immutable commit", nativeCodeGuardRepoCommit)
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
