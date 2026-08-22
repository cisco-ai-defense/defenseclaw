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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	nativeCodeGuardRepoURL             = "https://github.com/cosai-oasis/project-codeguard.git"
	nativeCodeGuardRepoCommit          = "a6aaed7bba31cfc68463fa5bb69e8ea24f9d5ad0"
	nativeCodeGuardRepoSkillName       = "codeguard"
	nativeCodeGuardCodexSkillName      = "software-security"
	nativeCodeGuardClaudeMarketplace   = "cosai-oasis/project-codeguard"
	nativeCodeGuardClaudeMarketplaceID = "project-codeguard"
	nativeCodeGuardClaudePlugin        = "codeguard-security@project-codeguard"
	nativeCodeGuardCodexReceiptVersion = 1
	nativeCodeGuardCodexReceiptName    = "codex-skill-receipt.json"
	nativeCodeGuardMigrationVersion    = 1
	nativeCodeGuardMigrationName       = "codex-skill-migration.json"
	nativeCodeGuardReceiptMaxBytes     = 16 << 10
	nativeCodeGuardFileMaxBytes        = 16 << 20
	nativeCodeGuardTreeMaxBytes        = 64 << 20
)

var (
	nativeCodeGuardInstallTimeout         = 2 * time.Minute
	validateClaudeCodeCodeGuardExecutable = validateClaudeCodeAgentProvenance

	// nativeCodeGuardRepoDirOverride lets tests exercise the Codex
	// installer without cloning GitHub.
	nativeCodeGuardRepoDirOverride string

	nativeCodeGuardCodexReceiptWriter = writeCodexCodeGuardReceipt
)

type codexCodeGuardReceipt struct {
	Version          int    `json:"version"`
	Target           string `json:"target"`
	SHA256           string `json:"sha256"`
	SourceCommit     string `json:"source_commit,omitempty"`
	SourceTreeSHA256 string `json:"source_tree_sha256,omitempty"`
	CreatedSkillsDir bool   `json:"created_skills_dir,omitempty"`
	CreatedAgentsDir bool   `json:"created_agents_dir,omitempty"`
}

// codexCodeGuardMigrationJournal makes replacement of an already-owned skill
// recoverable across process termination. The prior tree is moved outside the
// Agent Skills discovery root, while this protected journal binds that tree to
// both the old ownership receipt and the intended pinned replacement.
type codexCodeGuardMigrationJournal struct {
	Version      int                   `json:"version"`
	Target       string                `json:"target"`
	Quarantine   string                `json:"quarantine"`
	PriorReceipt codexCodeGuardReceipt `json:"prior_receipt"`
	PinnedSHA256 string                `json:"pinned_sha256"`
	SourceCommit string                `json:"source_commit"`
}

func ensureClaudeCodeCodeGuardPlugin(ctx context.Context, opts SetupOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}
	claudePath := strings.TrimSpace(opts.AgentExecutable)
	if claudePath == "" || !filepath.IsAbs(claudePath) || filepath.Clean(claudePath) != claudePath {
		return errors.New("Claude Code CodeGuard installation requires the sealed absolute agent executable")
	}
	if err := validateClaudeCodeCodeGuardExecutable(opts); err != nil {
		return fmt.Errorf("revalidate Claude Code executable before CodeGuard installation: %w", err)
	}

	if installed, _ := claudeCodeGuardPluginInstalled(ctx, claudePath); installed {
		return nil
	}

	if _, err := runNativeCodeGuardCommand(ctx, claudePath, "plugin", "marketplace", "add", nativeCodeGuardClaudeMarketplace); err != nil && !nativeCodeGuardAlreadyPresent(err) {
		return fmt.Errorf("add Claude Code Project CodeGuard marketplace: %w", err)
	}
	if _, err := runNativeCodeGuardCommand(ctx, claudePath, "plugin", "install", "--scope", "user", nativeCodeGuardClaudePlugin); err != nil && !nativeCodeGuardAlreadyPresent(err) {
		return fmt.Errorf("install Claude Code CodeGuard plugin: %w", err)
	}
	return nil
}

func claudeCodeGuardPluginInstalled(ctx context.Context, claudePath string) (bool, error) {
	out, err := runNativeCodeGuardCommand(ctx, claudePath, "plugin", "list")
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "codeguard-security") ||
		strings.Contains(out, nativeCodeGuardClaudePlugin), nil
}

func ensureCodexCodeGuardSkill(ctx context.Context, opts SetupOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}

	targetDir := filepath.Join(codexPersonalSkillsDir(), nativeCodeGuardCodexSkillName)
	if err := atomicTransformValidateNoReparsePathPlatform(targetDir); err != nil {
		return fmt.Errorf("validate Codex CodeGuard skill path: %w", err)
	}

	priorReceipt, receiptExists, err := loadCodexCodeGuardReceipt(opts, targetDir)
	if err != nil {
		return err
	}
	// Reconcile an interrupted owned-tree replacement before any receipt-based
	// early return. In particular, a pinned receipt may already be visible while
	// the prior tree and journal still await retirement.
	if err := recoverCodexCodeGuardOwnedReplacement(opts, targetDir, priorReceipt, receiptExists); err != nil {
		return fmt.Errorf("recover interrupted Codex CodeGuard migration: %w", err)
	}
	if receiptExists {
		if err := cleanupLegacyCodexCodeGuardDiscoveryTemps(targetDir, priorReceipt.SHA256); err != nil {
			return fmt.Errorf("recover legacy Codex CodeGuard temporary state: %w", err)
		}
	}
	if err := recoverCodexCodeGuardOwnedRemoval(targetDir, priorReceipt, receiptExists); err != nil {
		return fmt.Errorf("recover interrupted Codex CodeGuard removal: %w", err)
	}
	replaceOwnedTarget := false
	if receiptExists {
		digest, exists, err := digestCodexCodeGuardSkill(targetDir)
		if err != nil {
			return fmt.Errorf("verify owned Codex CodeGuard skill: %w", err)
		}
		if exists {
			if digest != priorReceipt.SHA256 {
				return fmt.Errorf(
					"owned Codex CodeGuard skill at %s was modified; refusing to overwrite (expected %s, got %s)",
					targetDir,
					priorReceipt.SHA256,
					digest,
				)
			}
			if codexCodeGuardReceiptUsesPinnedSource(priorReceipt, digest) {
				return nil
			}
			replaceOwnedTarget = true
		}
	}

	if !replaceOwnedTarget {
		if installed, err := codexCodeGuardSkillInstalled(targetDir); err != nil {
			return err
		} else if installed {
			// A valid Project CodeGuard skill without our protected receipt predates
			// this lifecycle. Leave it operator-owned and never claim teardown
			// authority over it.
			return nil
		}

		if info, err := os.Stat(targetDir); err == nil {
			if !info.IsDir() {
				return fmt.Errorf("codex skill target %s already exists and is not a directory", targetDir)
			}
			return fmt.Errorf("codex skill target %s already exists but is not Project CodeGuard; refusing to overwrite", targetDir)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect codex skill target %s: %w", targetDir, err)
		}
	}

	repoDir, cleanup, err := prepareProjectCodeGuardRepo(ctx, opts)
	if err != nil {
		return err
	}
	defer cleanup()

	sourceDir := filepath.Join(repoDir, "skills", nativeCodeGuardRepoSkillName)
	if err := validateCodeGuardSkillSource(sourceDir); err != nil {
		return err
	}
	sourceDigest, sourceExists, err := digestCodexCodeGuardSkill(sourceDir)
	if err != nil || !sourceExists {
		if err == nil {
			err = errors.New("pinned Project CodeGuard skill source disappeared")
		}
		return fmt.Errorf("verify pinned Project CodeGuard skill source: %w", err)
	}
	if err := cleanupLegacyCodexCodeGuardDiscoveryTemps(
		targetDir,
		priorReceipt.SHA256,
		sourceDigest,
	); err != nil {
		return fmt.Errorf("recover legacy Codex CodeGuard temporary state: %w", err)
	}

	skillsDir := filepath.Dir(targetDir)
	agentsDir := filepath.Dir(skillsDir)
	createdSkillsDir := priorReceipt.CreatedSkillsDir
	createdAgentsDir := priorReceipt.CreatedAgentsDir
	if !receiptExists {
		var err error
		createdSkillsDir, err = codexCodeGuardPathMissing(skillsDir)
		if err != nil {
			return err
		}
		createdAgentsDir, err = codexCodeGuardPathMissing(agentsDir)
		if err != nil {
			return err
		}
	}

	digest := sourceDigest
	var replacement *codexCodeGuardOwnedReplacement
	if replaceOwnedTarget && priorReceipt.SHA256 != sourceDigest {
		journal := codexCodeGuardMigrationJournal{
			Version:      nativeCodeGuardMigrationVersion,
			Target:       targetDir,
			Quarantine:   codexCodeGuardMigrationQuarantineDir(targetDir),
			PriorReceipt: priorReceipt,
			PinnedSHA256: sourceDigest,
			SourceCommit: nativeCodeGuardRepoCommit,
		}
		replacement, err = beginCodexCodeGuardOwnedReplacement(
			opts,
			sourceDir,
			targetDir,
			priorReceipt.SHA256,
			sourceDigest,
			journal,
		)
		if err != nil {
			recoveryErr := recoverCodexCodeGuardOwnedReplacement(
				opts,
				targetDir,
				priorReceipt,
				true,
			)
			return errors.Join(
				fmt.Errorf("migrate owned Codex CodeGuard skill to pinned source: %w", err),
				recoveryErr,
			)
		}
	} else if !replaceOwnedTarget {
		if err := copyDirectoryAtomic(sourceDir, targetDir); err != nil {
			return fmt.Errorf("install Codex CodeGuard skill to %s: %w", targetDir, err)
		}

		installedDigest, exists, err := digestCodexCodeGuardSkill(targetDir)
		if err != nil || !exists || installedDigest != sourceDigest {
			if err == nil {
				switch {
				case !exists:
					err = errors.New("installed skill disappeared before receipt publication")
				default:
					err = fmt.Errorf("installed tree digest %s does not match pinned source %s", installedDigest, sourceDigest)
				}
			}
			rollbackErr := removeOwnedCodexCodeGuardTree(
				targetDir,
				installedDigest,
				createdSkillsDir,
				createdAgentsDir,
			)
			return errors.Join(
				fmt.Errorf("verify installed Codex CodeGuard skill: %w", err),
				rollbackErr,
			)
		}
		digest = installedDigest
	}

	receipt := codexCodeGuardReceipt{
		Version:          nativeCodeGuardCodexReceiptVersion,
		Target:           targetDir,
		SHA256:           digest,
		SourceCommit:     nativeCodeGuardRepoCommit,
		SourceTreeSHA256: sourceDigest,
		CreatedSkillsDir: createdSkillsDir,
		CreatedAgentsDir: createdAgentsDir,
	}
	if err := nativeCodeGuardCodexReceiptWriter(codexCodeGuardReceiptPath(opts), receipt); err != nil {
		var rollbackErr error
		if replacement != nil {
			rollbackErr = settleCodexCodeGuardMigrationAfterReceiptError(
				opts,
				targetDir,
				priorReceipt,
				receipt,
				replacement,
			)
		} else if !replaceOwnedTarget {
			rollbackErr = removeOwnedCodexCodeGuardTree(
				targetDir,
				digest,
				createdSkillsDir,
				createdAgentsDir,
			)
		}
		return errors.Join(
			fmt.Errorf("publish Codex CodeGuard ownership receipt: %w", err),
			rollbackErr,
		)
	}
	if replacement != nil {
		if err := replacement.commit(); err != nil {
			return fmt.Errorf("retire prior Codex CodeGuard skill after pinned migration: %w", err)
		}
		if err := removeCodexCodeGuardMigrationJournal(opts); err != nil {
			return fmt.Errorf("retire completed Codex CodeGuard migration journal: %w", err)
		}
	}
	return nil
}

func codexCodeGuardReceiptUsesPinnedSource(receipt codexCodeGuardReceipt, installedDigest string) bool {
	return receipt.SourceCommit == nativeCodeGuardRepoCommit &&
		receipt.SourceTreeSHA256 == installedDigest &&
		receipt.SHA256 == installedDigest
}

type codexCodeGuardOwnedReplacement struct {
	targetDir     string
	quarantineDir string
	priorDigest   string
	pinnedDigest  string
}

func beginCodexCodeGuardOwnedReplacement(
	opts SetupOpts,
	sourceDir, targetDir, priorDigest, pinnedDigest string,
	journal codexCodeGuardMigrationJournal,
) (*codexCodeGuardOwnedReplacement, error) {
	currentDigest, exists, err := digestCodexCodeGuardSkill(targetDir)
	if err != nil {
		return nil, fmt.Errorf("revalidate prior owned skill: %w", err)
	}
	if !exists || currentDigest != priorDigest {
		return nil, fmt.Errorf(
			"prior owned skill changed before migration (exists=%t, expected %s, got %s)",
			exists,
			priorDigest,
			currentDigest,
		)
	}

	replacement := &codexCodeGuardOwnedReplacement{
		targetDir:     targetDir,
		quarantineDir: codexCodeGuardMigrationQuarantineDir(targetDir),
		priorDigest:   priorDigest,
		pinnedDigest:  pinnedDigest,
	}
	if journal.Target != targetDir ||
		journal.Quarantine != replacement.quarantineDir ||
		journal.PriorReceipt.SHA256 != priorDigest ||
		journal.PinnedSHA256 != pinnedDigest {
		return nil, errors.New("Codex CodeGuard migration journal does not match the requested replacement")
	}
	if _, err := os.Lstat(replacement.quarantineDir); err == nil {
		return nil, fmt.Errorf("Codex CodeGuard migration quarantine already exists: %s", replacement.quarantineDir)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect Codex CodeGuard migration quarantine: %w", err)
	}
	if err := writeCodexCodeGuardMigrationJournal(codexCodeGuardMigrationJournalPath(opts), journal); err != nil {
		return nil, fmt.Errorf("publish Codex CodeGuard migration journal: %w", err)
	}
	if err := os.Rename(targetDir, replacement.quarantineDir); err != nil {
		return nil, fmt.Errorf("quarantine prior owned skill: %w", err)
	}
	quarantinedDigest, quarantinedExists, err := digestCodexCodeGuardSkill(replacement.quarantineDir)
	if err != nil || !quarantinedExists || quarantinedDigest != priorDigest {
		if err == nil {
			err = fmt.Errorf(
				"quarantined prior skill digest mismatch: expected %s, got %s",
				priorDigest,
				quarantinedDigest,
			)
		}
		restoreErr := restoreCodexCodeGuardQuarantine(replacement.quarantineDir, targetDir)
		return nil, errors.Join(fmt.Errorf("verify quarantined prior skill: %w", err), restoreErr)
	}

	if err := copyDirectoryAtomic(sourceDir, targetDir); err != nil {
		restoreErr := restoreCodexCodeGuardQuarantine(replacement.quarantineDir, targetDir)
		return nil, errors.Join(fmt.Errorf("install pinned replacement skill: %w", err), restoreErr)
	}
	installedDigest, installedExists, err := digestCodexCodeGuardSkill(targetDir)
	if err != nil || !installedExists || installedDigest != pinnedDigest {
		if err == nil {
			err = fmt.Errorf(
				"pinned replacement digest mismatch: expected %s, got %s",
				pinnedDigest,
				installedDigest,
			)
		}
		rollbackErr := replacement.rollback()
		return nil, errors.Join(fmt.Errorf("verify pinned replacement skill: %w", err), rollbackErr)
	}
	return replacement, nil
}

func (replacement *codexCodeGuardOwnedReplacement) rollback() error {
	if replacement == nil {
		return nil
	}
	quarantinedDigest, quarantinedExists, err := digestCodexCodeGuardSkill(replacement.quarantineDir)
	if err != nil || !quarantinedExists || quarantinedDigest != replacement.priorDigest {
		if err == nil {
			err = fmt.Errorf(
				"prior migration quarantine digest mismatch: expected %s, got %s",
				replacement.priorDigest,
				quarantinedDigest,
			)
		}
		return fmt.Errorf("cannot restore prior Codex CodeGuard skill: %w", err)
	}

	currentDigest, currentExists, err := digestCodexCodeGuardSkill(replacement.targetDir)
	if err != nil {
		return fmt.Errorf("inspect pinned replacement before rollback: %w", err)
	}
	if currentExists {
		if currentDigest != replacement.pinnedDigest {
			return fmt.Errorf(
				"pinned replacement changed during migration; preserving both target %s and quarantine %s",
				replacement.targetDir,
				replacement.quarantineDir,
			)
		}
		discard := codexCodeGuardRollbackQuarantineDir(replacement.targetDir)
		if _, err := os.Lstat(discard); err == nil {
			return fmt.Errorf("Codex CodeGuard rollback quarantine already exists: %s", discard)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect Codex CodeGuard rollback quarantine: %w", err)
		}
		if err := os.Rename(replacement.targetDir, discard); err != nil {
			return fmt.Errorf("quarantine pinned replacement during rollback: %w", err)
		}
		discardDigest, discardExists, err := digestCodexCodeGuardSkill(discard)
		if err != nil || !discardExists || discardDigest != replacement.pinnedDigest {
			if err == nil {
				err = fmt.Errorf(
					"rollback quarantine digest mismatch: expected %s, got %s",
					replacement.pinnedDigest,
					discardDigest,
				)
			}
			return fmt.Errorf("verify pinned rollback quarantine: %w", err)
		}
	}
	if err := os.Rename(replacement.quarantineDir, replacement.targetDir); err != nil {
		return fmt.Errorf("restore prior Codex CodeGuard skill after migration failure: %w", err)
	}
	if err := removeCodexCodeGuardRollbackQuarantine(replacement.targetDir, replacement.pinnedDigest); err != nil {
		return err
	}
	return nil
}

func (replacement *codexCodeGuardOwnedReplacement) commit() error {
	if replacement == nil {
		return nil
	}
	digest, exists, err := digestCodexCodeGuardSkill(replacement.quarantineDir)
	if err != nil {
		return fmt.Errorf("inspect prior migration quarantine before removal: %w", err)
	}
	if !exists || digest != replacement.priorDigest {
		return fmt.Errorf(
			"prior migration quarantine changed; preserving %s (expected %s, got %s)",
			replacement.quarantineDir,
			replacement.priorDigest,
			digest,
		)
	}
	if err := os.RemoveAll(replacement.quarantineDir); err != nil {
		return fmt.Errorf("remove prior migration quarantine: %w", err)
	}
	return nil
}

func codexCodeGuardMigrationJournalPath(opts SetupOpts) string {
	return filepath.Join(opts.DataDir, "native-codeguard", nativeCodeGuardMigrationName)
}

func codexCodeGuardMigrationQuarantineDir(targetDir string) string {
	// Keep the old SKILL.md-bearing tree on the same filesystem as the target
	// for atomic rename, but outside ~/.agents/skills so Codex cannot discover
	// both the old and new skill after an interrupted migration.
	agentsDir := filepath.Dir(filepath.Dir(targetDir))
	return filepath.Join(agentsDir, ".defenseclaw-codeguard-"+nativeCodeGuardCodexSkillName+"-migration")
}

func codexCodeGuardStagingDir(targetDir string) string {
	agentsDir := filepath.Dir(filepath.Dir(targetDir))
	return filepath.Join(agentsDir, ".defenseclaw-codeguard-"+nativeCodeGuardCodexSkillName+"-stage")
}

func codexCodeGuardRemovalQuarantineDir(targetDir string) string {
	agentsDir := filepath.Dir(filepath.Dir(targetDir))
	return filepath.Join(agentsDir, ".defenseclaw-codeguard-"+nativeCodeGuardCodexSkillName+"-removal")
}

func codexCodeGuardRollbackQuarantineDir(targetDir string) string {
	agentsDir := filepath.Dir(filepath.Dir(targetDir))
	return filepath.Join(agentsDir, ".defenseclaw-codeguard-"+nativeCodeGuardCodexSkillName+"-rollback")
}

func codexCodeGuardPinnedReceipt(
	prior codexCodeGuardReceipt,
	pinnedDigest string,
) codexCodeGuardReceipt {
	return codexCodeGuardPinnedReceiptAtCommit(prior, pinnedDigest, nativeCodeGuardRepoCommit)
}

func codexCodeGuardPinnedReceiptAtCommit(
	prior codexCodeGuardReceipt,
	pinnedDigest string,
	sourceCommit string,
) codexCodeGuardReceipt {
	prior.SHA256 = pinnedDigest
	prior.SourceCommit = sourceCommit
	prior.SourceTreeSHA256 = pinnedDigest
	return prior
}

func writeCodexCodeGuardMigrationJournal(
	path string,
	journal codexCodeGuardMigrationJournal,
) error {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("Codex CodeGuard migration journal path is not absolute: %q", path)
	}
	if err := validateCodexCodeGuardMigrationJournal(journal, journal.Target); err != nil {
		return err
	}
	if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
		return fmt.Errorf("validate Codex CodeGuard migration journal path: %w", err)
	}
	if err := ensureManagedBackupDirRestricted(filepath.Dir(path)); err != nil {
		return fmt.Errorf("protect Codex CodeGuard migration journal directory: %w", err)
	}
	if err := validateCodexCodeGuardPrivateStateDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("validate Codex CodeGuard migration journal directory custody: %w", err)
	}
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Codex CodeGuard migration journal: %w", err)
	}
	return safefile.WritePrivate(path, append(data, '\n'))
}

func loadCodexCodeGuardMigrationJournal(
	opts SetupOpts,
	expectedTarget string,
) (codexCodeGuardMigrationJournal, bool, error) {
	var journal codexCodeGuardMigrationJournal
	path := codexCodeGuardMigrationJournalPath(opts)
	if strings.TrimSpace(opts.DataDir) == "" || !filepath.IsAbs(path) {
		return journal, false, errors.New("Codex CodeGuard migration journal requires an absolute data directory")
	}
	if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
		return journal, false, fmt.Errorf("validate Codex CodeGuard migration journal path: %w", err)
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return journal, false, nil
	}
	if err != nil {
		return journal, false, fmt.Errorf("inspect Codex CodeGuard migration journal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return journal, false, errors.New("Codex CodeGuard migration journal is not a regular file")
	}
	data, err := readCodexCodeGuardPrivateStateFile(path, info, nativeCodeGuardReceiptMaxBytes)
	if err != nil {
		return journal, false, fmt.Errorf("read Codex CodeGuard migration journal: %w", err)
	}
	if err := json.Unmarshal(data, &journal); err != nil {
		return journal, false, fmt.Errorf("parse Codex CodeGuard migration journal: %w", err)
	}
	if err := validateCodexCodeGuardMigrationJournal(journal, expectedTarget); err != nil {
		return journal, false, err
	}
	return journal, true, nil
}

func validateCodexCodeGuardMigrationJournal(
	journal codexCodeGuardMigrationJournal,
	expectedTarget string,
) error {
	if journal.Version != nativeCodeGuardMigrationVersion {
		return fmt.Errorf("unsupported Codex CodeGuard migration journal version %d", journal.Version)
	}
	if !sameCodexInventoryPath(journal.Target, expectedTarget) {
		return fmt.Errorf(
			"Codex CodeGuard migration journal target mismatch: captured %q, expected %q",
			journal.Target,
			expectedTarget,
		)
	}
	if err := validateCodexCodeGuardReceipt(journal.PriorReceipt, expectedTarget); err != nil {
		return fmt.Errorf("invalid prior receipt in Codex CodeGuard migration journal: %w", err)
	}
	expectedQuarantine := codexCodeGuardMigrationQuarantineDir(expectedTarget)
	if !sameCodexInventoryPath(journal.Quarantine, expectedQuarantine) {
		return fmt.Errorf(
			"Codex CodeGuard migration journal quarantine mismatch: captured %q, expected %q",
			journal.Quarantine,
			expectedQuarantine,
		)
	}
	if !validNativeCodeGuardCommit(journal.SourceCommit) {
		return errors.New("Codex CodeGuard migration journal contains an invalid immutable source commit")
	}
	if !validCodexCodeGuardDigest(journal.PinnedSHA256) {
		return errors.New("Codex CodeGuard migration journal contains an invalid pinned SHA-256 digest")
	}
	if journal.PinnedSHA256 == journal.PriorReceipt.SHA256 {
		return errors.New("Codex CodeGuard migration journal does not describe a replacement")
	}
	if journal.PriorReceipt.SourceCommit == journal.SourceCommit &&
		journal.PriorReceipt.SourceTreeSHA256 == journal.PriorReceipt.SHA256 {
		return errors.New("Codex CodeGuard migration journal claims an already-current prior receipt")
	}
	return nil
}

func removeCodexCodeGuardMigrationJournal(opts SetupOpts) error {
	path := codexCodeGuardMigrationJournalPath(opts)
	if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
		return fmt.Errorf("validate Codex CodeGuard migration journal removal path: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove Codex CodeGuard migration journal: %w", err)
	}
	return nil
}

func settleCodexCodeGuardMigrationAfterReceiptError(
	opts SetupOpts,
	targetDir string,
	priorReceipt codexCodeGuardReceipt,
	pinnedReceipt codexCodeGuardReceipt,
	replacement *codexCodeGuardOwnedReplacement,
) error {
	current, exists, err := loadCodexCodeGuardReceipt(opts, targetDir)
	if err != nil {
		return fmt.Errorf("inspect receipt after failed Codex CodeGuard publication: %w", err)
	}
	if !exists {
		return errors.New("Codex CodeGuard receipt disappeared after failed migration publication; preserving recoverable state")
	}
	if current == pinnedReceipt {
		// Publication may have succeeded before a durability operation reported
		// failure. Preserve the journal and both trees so the next entry can
		// commit or roll back according to whichever receipt survives.
		return nil
	}
	if current != priorReceipt {
		return errors.New("Codex CodeGuard receipt changed during failed migration publication; preserving recoverable state")
	}
	if err := replacement.rollback(); err != nil {
		return err
	}
	return removeCodexCodeGuardMigrationJournal(opts)
}

func recoverCodexCodeGuardOwnedReplacement(
	opts SetupOpts,
	targetDir string,
	currentReceipt codexCodeGuardReceipt,
	receiptExists bool,
) error {
	journal, exists, err := loadCodexCodeGuardMigrationJournal(opts, targetDir)
	if err != nil || !exists {
		return err
	}
	if !receiptExists {
		return errors.New("migration journal exists without its ownership receipt; preserving recovery state")
	}
	if err := cleanupLegacyCodexCodeGuardDiscoveryTemps(
		targetDir,
		journal.PriorReceipt.SHA256,
		journal.PinnedSHA256,
	); err != nil {
		return err
	}

	pinnedReceipt := codexCodeGuardPinnedReceiptAtCommit(
		journal.PriorReceipt,
		journal.PinnedSHA256,
		journal.SourceCommit,
	)
	isPriorReceipt := currentReceipt == journal.PriorReceipt
	isPinnedReceipt := currentReceipt == pinnedReceipt
	if !isPriorReceipt && !isPinnedReceipt {
		return errors.New("ownership receipt does not match either side of the recorded migration; preserving recovery state")
	}

	targetDigest, targetExists, err := digestCodexCodeGuardSkill(targetDir)
	if err != nil {
		return fmt.Errorf("inspect migration target during recovery: %w", err)
	}
	quarantineDigest, quarantineExists, err := digestCodexCodeGuardSkill(journal.Quarantine)
	if err != nil {
		return fmt.Errorf("inspect migration quarantine during recovery: %w", err)
	}
	rollbackDigest, rollbackExists, err := digestCodexCodeGuardSkill(
		codexCodeGuardRollbackQuarantineDir(targetDir),
	)
	if err != nil {
		return fmt.Errorf("inspect migration rollback quarantine during recovery: %w", err)
	}
	if rollbackExists && rollbackDigest != journal.PinnedSHA256 {
		return errors.New("recorded Codex CodeGuard migration rollback quarantine changed; preserving it")
	}
	replacement := &codexCodeGuardOwnedReplacement{
		targetDir:     targetDir,
		quarantineDir: journal.Quarantine,
		priorDigest:   journal.PriorReceipt.SHA256,
		pinnedDigest:  journal.PinnedSHA256,
	}

	if isPriorReceipt {
		switch {
		case !quarantineExists && targetExists && targetDigest == replacement.priorDigest:
			// The journal was published but the namespace transition did not
			// begin, or rollback completed before journal retirement.
			if err := removeCodexCodeGuardRollbackQuarantine(targetDir, replacement.pinnedDigest); err != nil {
				return err
			}
		case quarantineExists && quarantineDigest == replacement.priorDigest && !targetExists:
			if err := restoreCodexCodeGuardQuarantine(journal.Quarantine, targetDir); err != nil {
				return err
			}
			if err := removeCodexCodeGuardRollbackQuarantine(targetDir, replacement.pinnedDigest); err != nil {
				return err
			}
		case quarantineExists && quarantineDigest == replacement.priorDigest &&
			targetExists && targetDigest == replacement.pinnedDigest && !rollbackExists:
			if err := replacement.rollback(); err != nil {
				return err
			}
		default:
			return fmt.Errorf(
				"recorded Codex CodeGuard migration has unexpected prior state (target exists=%t digest=%q, quarantine exists=%t digest=%q); preserving both paths",
				targetExists,
				targetDigest,
				quarantineExists,
				quarantineDigest,
			)
		}
		return removeCodexCodeGuardMigrationJournal(opts)
	}

	if !targetExists || targetDigest != replacement.pinnedDigest {
		return fmt.Errorf(
			"recorded Codex CodeGuard migration has a pinned receipt but unexpected target state (exists=%t digest=%q); preserving recovery state",
			targetExists,
			targetDigest,
		)
	}
	if rollbackExists {
		return errors.New("pinned Codex CodeGuard receipt conflicts with an interrupted rollback quarantine; preserving recovery state")
	}
	switch {
	case !quarantineExists:
		// Commit completed before journal retirement.
	case quarantineDigest != replacement.priorDigest:
		return fmt.Errorf(
			"recorded Codex CodeGuard migration quarantine changed (expected %s, got %s); preserving it",
			replacement.priorDigest,
			quarantineDigest,
		)
	default:
		if err := replacement.commit(); err != nil {
			return err
		}
	}
	return removeCodexCodeGuardMigrationJournal(opts)
}

func teardownCodexCodeGuardSkill(opts SetupOpts) error {
	targetDir := filepath.Join(codexPersonalSkillsDir(), nativeCodeGuardCodexSkillName)
	receipt, exists, err := loadCodexCodeGuardReceipt(opts, targetDir)
	if err != nil {
		return err
	}
	if err := recoverCodexCodeGuardOwnedReplacement(opts, targetDir, receipt, exists); err != nil {
		return fmt.Errorf("recover interrupted Codex CodeGuard migration before teardown: %w", err)
	}
	if err := cleanupLegacyCodexCodeGuardDiscoveryTemps(targetDir, receipt.SHA256); err != nil {
		return fmt.Errorf("recover legacy Codex CodeGuard temporary state before teardown: %w", err)
	}
	if err := recoverCodexCodeGuardOwnedRemoval(targetDir, receipt, exists); err != nil {
		return fmt.Errorf("recover interrupted Codex CodeGuard removal before teardown: %w", err)
	}
	if !exists {
		return nil
	}
	if err := removeOwnedCodexCodeGuardTree(
		targetDir,
		receipt.SHA256,
		receipt.CreatedSkillsDir,
		receipt.CreatedAgentsDir,
	); err != nil {
		return err
	}

	receiptPath := codexCodeGuardReceiptPath(opts)
	if err := atomicTransformValidateNoReparsePathPlatform(receiptPath); err != nil {
		return fmt.Errorf("validate Codex CodeGuard receipt removal path: %w", err)
	}
	if err := os.Remove(receiptPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove Codex CodeGuard ownership receipt: %w", err)
	}
	return nil
}

func codexCodeGuardReceiptPath(opts SetupOpts) string {
	return filepath.Join(opts.DataDir, "native-codeguard", nativeCodeGuardCodexReceiptName)
}

func writeCodexCodeGuardReceipt(path string, receipt codexCodeGuardReceipt) error {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("Codex CodeGuard receipt path is not absolute: %q", path)
	}
	if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
		return fmt.Errorf("validate Codex CodeGuard receipt path: %w", err)
	}
	if err := ensureManagedBackupDirRestricted(filepath.Dir(path)); err != nil {
		return fmt.Errorf("protect Codex CodeGuard receipt directory: %w", err)
	}
	if err := validateCodexCodeGuardPrivateStateDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("validate Codex CodeGuard receipt directory custody: %w", err)
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Codex CodeGuard receipt: %w", err)
	}
	return safefile.WritePrivate(path, append(data, '\n'))
}

func loadCodexCodeGuardReceipt(
	opts SetupOpts,
	expectedTarget string,
) (codexCodeGuardReceipt, bool, error) {
	var receipt codexCodeGuardReceipt
	path := codexCodeGuardReceiptPath(opts)
	if strings.TrimSpace(opts.DataDir) == "" || !filepath.IsAbs(path) {
		return receipt, false, fmt.Errorf("Codex CodeGuard receipt requires an absolute data directory")
	}
	if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
		return receipt, false, fmt.Errorf("validate Codex CodeGuard receipt path: %w", err)
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return receipt, false, nil
	}
	if err != nil {
		return receipt, false, fmt.Errorf("inspect Codex CodeGuard ownership receipt: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return receipt, false, fmt.Errorf("Codex CodeGuard ownership receipt is not a regular file")
	}
	data, err := readCodexCodeGuardPrivateStateFile(path, info, nativeCodeGuardReceiptMaxBytes)
	if err != nil {
		return receipt, false, fmt.Errorf("read Codex CodeGuard ownership receipt: %w", err)
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		return receipt, false, fmt.Errorf("parse Codex CodeGuard ownership receipt: %w", err)
	}
	if err := validateCodexCodeGuardReceipt(receipt, expectedTarget); err != nil {
		return receipt, false, err
	}
	return receipt, true, nil
}

func validateCodexCodeGuardReceipt(receipt codexCodeGuardReceipt, expectedTarget string) error {
	if receipt.Version != nativeCodeGuardCodexReceiptVersion {
		return fmt.Errorf(
			"unsupported Codex CodeGuard receipt version %d",
			receipt.Version,
		)
	}
	if !sameCodexInventoryPath(receipt.Target, expectedTarget) {
		return fmt.Errorf(
			"Codex CodeGuard receipt target mismatch: captured %q, expected %q",
			receipt.Target,
			expectedTarget,
		)
	}
	if !validCodexCodeGuardDigest(receipt.SHA256) {
		return errors.New("Codex CodeGuard receipt contains an invalid SHA-256 digest")
	}
	commit := strings.TrimSpace(receipt.SourceCommit)
	sourceTreeDigest := strings.TrimSpace(receipt.SourceTreeSHA256)
	if (commit == "") != (sourceTreeDigest == "") {
		return errors.New("Codex CodeGuard receipt has incomplete pinned source identity")
	}
	if commit != "" {
		if commit != receipt.SourceCommit || !validNativeCodeGuardCommit(commit) {
			return errors.New("Codex CodeGuard receipt contains an invalid source commit")
		}
		if sourceTreeDigest != receipt.SourceTreeSHA256 || !validCodexCodeGuardDigest(sourceTreeDigest) {
			return errors.New("Codex CodeGuard receipt contains an invalid source tree digest")
		}
		if sourceTreeDigest != receipt.SHA256 {
			return errors.New("Codex CodeGuard receipt source tree does not match the installed tree")
		}
	}
	if receipt.CreatedAgentsDir && !receipt.CreatedSkillsDir {
		return errors.New(
			"Codex CodeGuard receipt has impossible parent-directory custody",
		)
	}
	return nil
}

func readCodexCodeGuardPrivateStateFile(path string, expected os.FileInfo, limit int64) ([]byte, error) {
	if expected == nil || expected.Mode()&os.ModeSymlink != 0 || !expected.Mode().IsRegular() {
		return nil, errors.New("CodeGuard private state is not a regular file")
	}
	if err := validateCodexCodeGuardPrivateStateDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("validate private-state directory custody: %w", err)
	}
	if err := hookAPIValidateOwner(path, expected); err != nil {
		return nil, fmt.Errorf("validate private-state owner: %w", err)
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return nil, fmt.Errorf("validate private-state protection: %w", err)
	}
	body, err := safefile.ReadRegularFileBounded(path, limit)
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(expected, current) {
		if err == nil {
			err = errors.New("private-state path changed during read")
		}
		return nil, err
	}
	return body, nil
}

func codexCodeGuardPathMissing(path string) (bool, error) {
	if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
		return false, fmt.Errorf("validate Codex CodeGuard parent path %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect Codex CodeGuard parent path %s: %w", path, err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("Codex CodeGuard parent path %s is not a directory", path)
	}
	return false, nil
}

func digestCodexCodeGuardSkill(root string) (string, bool, error) {
	if err := atomicTransformValidateNoReparsePathPlatform(root); err != nil {
		return "", false, err
	}
	if err := validateCodexCodeGuardTreeParentCustody(root); err != nil {
		return "", false, err
	}
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", true, fmt.Errorf("Codex CodeGuard skill target is not an ordinary directory")
	}

	digest := sha256.New()
	var totalBytes int64
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Codex CodeGuard skill contains a symlink: %s", path)
		}
		kind := byte('d')
		if !entryInfo.IsDir() {
			if !entryInfo.Mode().IsRegular() {
				return fmt.Errorf("Codex CodeGuard skill contains a non-regular file: %s", path)
			}
			kind = 'f'
		}
		_, _ = fmt.Fprintf(
			digest,
			"%c\x00%s\x00",
			kind,
			filepath.ToSlash(rel),
		)
		if err := validateCodexCodeGuardTreeEntryCustody(path, entryInfo); err != nil {
			return err
		}
		if kind == 'd' {
			return nil
		}
		body, ok := readStableNativeWindowsFile(path, nativeCodeGuardFileMaxBytes)
		if !ok {
			return fmt.Errorf(
				"Codex CodeGuard skill file is unsafe, changing, or exceeds %d bytes: %s",
				nativeCodeGuardFileMaxBytes,
				path,
			)
		}
		totalBytes += int64(len(body))
		if totalBytes > nativeCodeGuardTreeMaxBytes {
			return fmt.Errorf(
				"Codex CodeGuard skill tree exceeds %d bytes",
				nativeCodeGuardTreeMaxBytes,
			)
		}
		_, _ = fmt.Fprintf(digest, "%d\x00", len(body))
		_, _ = digest.Write(body)
		_, _ = digest.Write([]byte{0})
		return nil
	})
	if err != nil {
		return "", true, err
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), true, nil
}

func validCodexCodeGuardDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	raw := strings.TrimPrefix(value, "sha256:")
	if len(raw) != sha256.Size*2 || strings.ToLower(raw) != raw {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

func validNativeCodeGuardCommit(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func removeOwnedCodexCodeGuardTree(
	targetDir string,
	expectedDigest string,
	createdSkillsDir bool,
	createdAgentsDir bool,
) error {
	digest, exists, err := digestCodexCodeGuardSkill(targetDir)
	if err != nil {
		return fmt.Errorf("inspect owned Codex CodeGuard skill before removal: %w", err)
	}
	if exists {
		if digest != expectedDigest {
			return fmt.Errorf(
				"owned Codex CodeGuard skill at %s was modified; preserving it (expected %s, got %s)",
				targetDir,
				expectedDigest,
				digest,
			)
		}

		quarantine := codexCodeGuardRemovalQuarantineDir(targetDir)
		if _, err := os.Lstat(quarantine); err == nil {
			return fmt.Errorf("Codex CodeGuard removal quarantine already exists: %s", quarantine)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect Codex CodeGuard removal quarantine: %w", err)
		}
		if err := os.Rename(targetDir, quarantine); err != nil {
			return fmt.Errorf("quarantine owned Codex CodeGuard skill: %w", err)
		}

		quarantineDigest, quarantineExists, verifyErr := digestCodexCodeGuardSkill(quarantine)
		if verifyErr != nil || !quarantineExists || quarantineDigest != expectedDigest {
			if verifyErr == nil {
				verifyErr = fmt.Errorf(
					"quarantined skill digest mismatch: expected %s, got %s",
					expectedDigest,
					quarantineDigest,
				)
			}
			restoreErr := restoreCodexCodeGuardQuarantine(quarantine, targetDir)
			return errors.Join(
				fmt.Errorf("verify quarantined Codex CodeGuard skill: %w", verifyErr),
				restoreErr,
			)
		}
		if err := os.RemoveAll(quarantine); err != nil {
			return fmt.Errorf(
				"remove quarantined Codex CodeGuard skill: %w; target remains absent and the out-of-root quarantine is preserved",
				err,
			)
		}
	}

	skillsDir := filepath.Dir(targetDir)
	agentsDir := filepath.Dir(skillsDir)
	if createdSkillsDir {
		if err := removeEmptyCodexCodeGuardParent(skillsDir); err != nil {
			return err
		}
	}
	if createdAgentsDir {
		if err := removeEmptyCodexCodeGuardParent(agentsDir); err != nil {
			return err
		}
	}
	return nil
}

func restoreCodexCodeGuardQuarantine(quarantine, target string) error {
	if _, err := os.Lstat(quarantine); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect Codex CodeGuard quarantine before restore: %w", err)
	}
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf(
			"cannot restore Codex CodeGuard quarantine because target was recreated: %s",
			target,
		)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect Codex CodeGuard target before quarantine restore: %w", err)
	}
	if err := os.Rename(quarantine, target); err != nil {
		return fmt.Errorf("restore Codex CodeGuard quarantine: %w", err)
	}
	return nil
}

func recoverCodexCodeGuardOwnedRemoval(
	targetDir string,
	receipt codexCodeGuardReceipt,
	receiptExists bool,
) error {
	quarantine := codexCodeGuardRemovalQuarantineDir(targetDir)
	digest, exists, err := digestCodexCodeGuardSkill(quarantine)
	if err != nil {
		return fmt.Errorf("inspect Codex CodeGuard removal quarantine: %w", err)
	}
	if !exists {
		return nil
	}
	if !receiptExists || digest != receipt.SHA256 {
		return fmt.Errorf(
			"Codex CodeGuard removal quarantine is not authenticated by the ownership receipt; preserving %s",
			quarantine,
		)
	}
	if _, targetExists, targetErr := digestCodexCodeGuardSkill(targetDir); targetErr != nil {
		return fmt.Errorf("inspect Codex CodeGuard target during removal recovery: %w", targetErr)
	} else if targetExists {
		return fmt.Errorf(
			"Codex CodeGuard target was recreated during interrupted removal; preserving target %s and quarantine %s",
			targetDir,
			quarantine,
		)
	}
	if err := os.RemoveAll(quarantine); err != nil {
		return fmt.Errorf("retire authenticated Codex CodeGuard removal quarantine: %w", err)
	}
	return nil
}

func removeCodexCodeGuardRollbackQuarantine(targetDir, expectedDigest string) error {
	discard := codexCodeGuardRollbackQuarantineDir(targetDir)
	digest, exists, err := digestCodexCodeGuardSkill(discard)
	if err != nil {
		return fmt.Errorf("inspect Codex CodeGuard rollback quarantine: %w", err)
	}
	if !exists {
		return nil
	}
	if digest != expectedDigest {
		return fmt.Errorf(
			"Codex CodeGuard rollback quarantine changed; preserving %s (expected %s, got %s)",
			discard,
			expectedDigest,
			digest,
		)
	}
	if err := os.RemoveAll(discard); err != nil {
		return fmt.Errorf("retire authenticated Codex CodeGuard rollback quarantine: %w", err)
	}
	return nil
}

func cleanupLegacyCodexCodeGuardDiscoveryTemps(targetDir string, trustedDigests ...string) error {
	discoveryRoot := filepath.Dir(targetDir)
	entries, err := os.ReadDir(discoveryRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Codex skill discovery root: %w", err)
	}
	trusted := make(map[string]struct{}, len(trustedDigests))
	for _, digest := range trustedDigests {
		if validCodexCodeGuardDigest(digest) {
			trusted[digest] = struct{}{}
		}
	}
	base := filepath.Base(targetDir)
	for _, entry := range entries {
		name := entry.Name()
		if !legacyCodexCodeGuardTransientName(base, name) {
			continue
		}
		path := filepath.Join(discoveryRoot, name)
		digest, exists, digestErr := digestCodexCodeGuardSkill(path)
		if digestErr != nil || !exists {
			return fmt.Errorf(
				"legacy Codex CodeGuard temporary path %s is unexpected; preserving it: %w",
				path,
				digestErr,
			)
		}
		if _, ok := trusted[digest]; !ok {
			return fmt.Errorf(
				"legacy Codex CodeGuard temporary path %s has unauthenticated digest %s; preserving it",
				path,
				digest,
			)
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove authenticated legacy Codex CodeGuard temporary path %s: %w", path, err)
		}
	}
	return nil
}

func legacyCodexCodeGuardTransientName(targetBase, name string) bool {
	for _, marker := range []string{".tmp-", ".defenseclaw-remove-"} {
		suffix, found := strings.CutPrefix(name, targetBase+marker)
		if !found || suffix == "" {
			continue
		}
		if _, err := strconv.ParseUint(suffix, 10, 64); err == nil {
			return true
		}
	}
	return false
}

func removeEmptyCodexCodeGuardParent(path string) error {
	if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
		return fmt.Errorf("validate owned Codex CodeGuard parent %s: %w", path, err)
	}
	entries, err := os.ReadDir(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read owned Codex CodeGuard parent %s: %w", path, err)
	}
	if len(entries) != 0 {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove empty owned Codex CodeGuard parent %s: %w", path, err)
	}
	return nil
}

func codexHomeDir() string {
	return connectorEnvHomeDir("CODEX_HOME", ".codex")
}

func connectorEnvHomeDir(variable, defaultDir string) string {
	home := strings.TrimSpace(os.Getenv(variable))
	if home == "" {
		home = filepath.Join(strings.TrimSpace(userHomeDir()), defaultDir)
	}
	if home == "" {
		home = filepath.Join(".", defaultDir)
	}
	if home == "~" {
		home = userHomeDir()
	} else if strings.HasPrefix(home, "~/") || strings.HasPrefix(home, `~\`) {
		home = filepath.Join(userHomeDir(), home[2:])
	}
	if !filepath.IsAbs(home) {
		if absolute, err := filepath.Abs(home); err == nil {
			home = absolute
		}
	}
	return filepath.Clean(home)
}

func codexPersonalSkillsDir() string {
	// Codex configuration follows CODEX_HOME, but its personal Agent Skills
	// are discovered from $HOME/.agents/skills. Keep the install target bound
	// to Setup's validated user-home override instead of allowing CODEX_HOME
	// to redirect an explicit CodeGuard install into an undiscovered directory.
	return homePath(".agents", "skills")
}

func codexCodeGuardSkillInstalled(targetDir string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(targetDir, "SKILL.md"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read Codex CodeGuard skill manifest: %w", err)
	}
	text := string(data)
	return strings.Contains(text, "Project CodeGuard") &&
		strings.Contains(text, "name: "+nativeCodeGuardRepoSkillName), nil
}

func prepareProjectCodeGuardRepo(ctx context.Context, opts SetupOpts) (string, func(), error) {
	if override := strings.TrimSpace(nativeCodeGuardRepoDirOverride); override != "" {
		return override, func() {}, nil
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return "", func() {}, fmt.Errorf("data directory unavailable for Project CodeGuard clone")
	}

	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", func() {}, fmt.Errorf("git not found on PATH")
	}

	repoDir := filepath.Join(opts.DataDir, "native-codeguard", nativeCodeGuardClaudeMarketplaceID)
	if err := os.RemoveAll(repoDir); err != nil {
		return "", func() {}, fmt.Errorf("remove stale Project CodeGuard clone %s: %w", repoDir, err)
	}
	if err := os.MkdirAll(filepath.Dir(repoDir), 0o700); err != nil {
		return "", func() {}, fmt.Errorf("create Project CodeGuard clone parent: %w", err)
	}
	if err := os.MkdirAll(repoDir, 0o700); err != nil {
		return "", func() {}, fmt.Errorf("create Project CodeGuard repository: %w", err)
	}
	commands := [][]string{
		{"init", repoDir},
		{"-C", repoDir, "remote", "add", "origin", nativeCodeGuardRepoURL},
		{"-C", repoDir, "fetch", "--depth", "1", "origin", nativeCodeGuardRepoCommit},
		{"-C", repoDir, "checkout", "--detach", "FETCH_HEAD"},
	}
	for _, args := range commands {
		if _, err := runNativeCodeGuardCommand(ctx, gitPath, args...); err != nil {
			return "", func() {}, fmt.Errorf("prepare pinned Project CodeGuard repository: %w", err)
		}
	}
	resolved, err := runNativeCodeGuardCommand(ctx, gitPath, "-C", repoDir, "rev-parse", "HEAD")
	if err != nil {
		return "", func() {}, fmt.Errorf("verify Project CodeGuard revision: %w", err)
	}
	if strings.TrimSpace(resolved) != nativeCodeGuardRepoCommit {
		return "", func() {}, fmt.Errorf(
			"Project CodeGuard revision mismatch: got %s, want %s",
			strings.TrimSpace(resolved),
			nativeCodeGuardRepoCommit,
		)
	}
	return repoDir, func() {}, nil
}

func validateCodeGuardSkillSource(sourceDir string) error {
	data, err := os.ReadFile(filepath.Join(sourceDir, "SKILL.md"))
	if err != nil {
		return fmt.Errorf("read Project CodeGuard skill source: %w", err)
	}
	text := string(data)
	if !strings.Contains(text, "Project CodeGuard") ||
		!strings.Contains(text, "name: "+nativeCodeGuardRepoSkillName) {
		return fmt.Errorf("project CodeGuard skill source %s does not look like %s", sourceDir, nativeCodeGuardCodexSkillName)
	}
	return nil
}

func copyDirectoryAtomic(sourceDir, targetDir string) error {
	tmpDir := codexCodeGuardStagingDir(targetDir)
	sourceDigest, sourceExists, err := digestCodexCodeGuardSkill(sourceDir)
	if err != nil || !sourceExists {
		if err == nil {
			err = errors.New("CodeGuard staging source disappeared")
		}
		return err
	}
	if stagedDigest, stagedExists, stagedErr := digestCodexCodeGuardSkill(tmpDir); stagedErr != nil {
		return fmt.Errorf("inspect prior CodeGuard staging path: %w", stagedErr)
	} else if stagedExists {
		if stagedDigest != sourceDigest {
			return fmt.Errorf(
				"CodeGuard staging path %s has unexpected digest %s; preserving it",
				tmpDir,
				stagedDigest,
			)
		}
		if err := os.RemoveAll(tmpDir); err != nil {
			return fmt.Errorf("retire authenticated CodeGuard staging path: %w", err)
		}
	}
	defer os.RemoveAll(tmpDir)

	if err := copyDirectory(sourceDir, tmpDir); err != nil {
		return err
	}
	stagedDigest, stagedExists, err := digestCodexCodeGuardSkill(tmpDir)
	if err != nil || !stagedExists || stagedDigest != sourceDigest {
		if err == nil {
			err = fmt.Errorf("staged CodeGuard digest %s does not match source %s", stagedDigest, sourceDigest)
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetDir), 0o755); err != nil {
		return err
	}
	if _, err := os.Lstat(targetDir); err == nil {
		return fmt.Errorf("CodeGuard target was recreated before staged publication: %s", targetDir)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tmpDir, targetDir); err != nil {
		return err
	}
	return nil
}

func copyDirectory(sourceDir, targetDir string) error {
	return filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(targetDir, 0o755)
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to copy symlink from Project CodeGuard skill: %s", path)
		}

		dst := filepath.Join(targetDir, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, info.Mode().Perm())
		}

		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return copyFile(path, dst, info.Mode().Perm())
	})
}

func copyFile(source, target string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return nil
}

func runNativeCodeGuardCommand(ctx context.Context, name string, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmdCtx, cancel := context.WithTimeout(ctx, nativeCodeGuardInstallTimeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, name, args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "NO_COLOR=1")
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if cmdCtx.Err() == context.DeadlineExceeded {
		return text, fmt.Errorf("%s %s timed out after %s", filepath.Base(name), strings.Join(args, " "), nativeCodeGuardInstallTimeout)
	}
	if err != nil {
		if text == "" {
			return text, fmt.Errorf("%s %s failed: %w", filepath.Base(name), strings.Join(args, " "), err)
		}
		return text, fmt.Errorf("%s %s failed: %w: %s", filepath.Base(name), strings.Join(args, " "), err, compactCommandOutput(text))
	}
	return text, nil
}

func nativeCodeGuardAlreadyPresent(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "already") ||
		strings.Contains(lower, "exists") ||
		strings.Contains(lower, "installed")
}

func compactCommandOutput(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 1200 {
		return s[:1200] + "..."
	}
	return s
}
