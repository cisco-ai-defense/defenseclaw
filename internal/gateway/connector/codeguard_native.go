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
)

const (
	nativeCodeGuardRepoURL             = "https://github.com/cosai-oasis/project-codeguard.git"
	nativeCodeGuardRepoBranch          = "main"
	nativeCodeGuardCodexSkillName      = "software-security"
	nativeCodeGuardClaudeMarketplace   = "cosai-oasis/project-codeguard"
	nativeCodeGuardClaudeMarketplaceID = "project-codeguard"
	nativeCodeGuardClaudePlugin        = "codeguard-security@project-codeguard"
	nativeCodeGuardCodexReceiptVersion = 1
	nativeCodeGuardCodexReceiptName    = "codex-skill-receipt.json"
	nativeCodeGuardReceiptMaxBytes     = 16 << 10
	nativeCodeGuardFileMaxBytes        = 16 << 20
	nativeCodeGuardTreeMaxBytes        = 64 << 20
)

var (
	nativeCodeGuardInstallTimeout = 2 * time.Minute

	// nativeCodeGuardRepoDirOverride lets tests exercise the Codex
	// installer without cloning GitHub.
	nativeCodeGuardRepoDirOverride string

	nativeCodeGuardCodexReceiptWriter = writeCodexCodeGuardReceipt
)

type codexCodeGuardReceipt struct {
	Version          int    `json:"version"`
	Target           string `json:"target"`
	SHA256           string `json:"sha256"`
	CreatedSkillsDir bool   `json:"created_skills_dir,omitempty"`
	CreatedAgentsDir bool   `json:"created_agents_dir,omitempty"`
}

func ensureClaudeCodeCodeGuardPlugin(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	claudePath, err := exec.LookPath("claude")
	if err != nil {
		return fmt.Errorf("claude CLI not found on PATH")
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
			return nil
		}
	}

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

	repoDir, cleanup, err := prepareProjectCodeGuardRepo(ctx, opts)
	if err != nil {
		return err
	}
	defer cleanup()

	sourceDir := filepath.Join(repoDir, "skills", nativeCodeGuardCodexSkillName)
	if err := validateCodeGuardSkillSource(sourceDir); err != nil {
		return err
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

	if err := copyDirectoryAtomic(sourceDir, targetDir); err != nil {
		return fmt.Errorf("install Codex CodeGuard skill to %s: %w", targetDir, err)
	}

	digest, exists, err := digestCodexCodeGuardSkill(targetDir)
	if err != nil || !exists {
		if err == nil {
			err = errors.New("installed skill disappeared before receipt publication")
		}
		rollbackErr := removeOwnedCodexCodeGuardTree(
			targetDir,
			digest,
			createdSkillsDir,
			createdAgentsDir,
		)
		return errors.Join(
			fmt.Errorf("verify installed Codex CodeGuard skill: %w", err),
			rollbackErr,
		)
	}

	receipt := codexCodeGuardReceipt{
		Version:          nativeCodeGuardCodexReceiptVersion,
		Target:           targetDir,
		SHA256:           digest,
		CreatedSkillsDir: createdSkillsDir,
		CreatedAgentsDir: createdAgentsDir,
	}
	if err := nativeCodeGuardCodexReceiptWriter(codexCodeGuardReceiptPath(opts), receipt); err != nil {
		rollbackErr := removeOwnedCodexCodeGuardTree(
			targetDir,
			digest,
			createdSkillsDir,
			createdAgentsDir,
		)
		return errors.Join(
			fmt.Errorf("publish Codex CodeGuard ownership receipt: %w", err),
			rollbackErr,
		)
	}
	return nil
}

func teardownCodexCodeGuardSkill(opts SetupOpts) error {
	targetDir := filepath.Join(codexPersonalSkillsDir(), nativeCodeGuardCodexSkillName)
	receipt, exists, err := loadCodexCodeGuardReceipt(opts, targetDir)
	if err != nil {
		return err
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
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Codex CodeGuard receipt: %w", err)
	}
	return atomicWriteFile(path, append(data, '\n'), 0o600)
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
	data, ok := readStableNativeWindowsFile(path, nativeCodeGuardReceiptMaxBytes)
	if !ok {
		return receipt, false, fmt.Errorf(
			"Codex CodeGuard ownership receipt is unsafe, changing, or exceeds %d bytes",
			nativeCodeGuardReceiptMaxBytes,
		)
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		return receipt, false, fmt.Errorf("parse Codex CodeGuard ownership receipt: %w", err)
	}
	if receipt.Version != nativeCodeGuardCodexReceiptVersion {
		return receipt, false, fmt.Errorf(
			"unsupported Codex CodeGuard receipt version %d",
			receipt.Version,
		)
	}
	if !sameCodexInventoryPath(receipt.Target, expectedTarget) {
		return receipt, false, fmt.Errorf(
			"Codex CodeGuard receipt target mismatch: captured %q, expected %q",
			receipt.Target,
			expectedTarget,
		)
	}
	if !validCodexCodeGuardDigest(receipt.SHA256) {
		return receipt, false, fmt.Errorf("Codex CodeGuard receipt contains an invalid SHA-256 digest")
	}
	if receipt.CreatedAgentsDir && !receipt.CreatedSkillsDir {
		return receipt, false, fmt.Errorf(
			"Codex CodeGuard receipt has impossible parent-directory custody",
		)
	}
	return receipt, true, nil
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

		quarantine := targetDir + ".defenseclaw-remove-" + strconv.FormatInt(time.Now().UnixNano(), 10)
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
			restoreErr := restoreCodexCodeGuardQuarantine(quarantine, targetDir)
			return errors.Join(
				fmt.Errorf("remove quarantined Codex CodeGuard skill: %w", err),
				restoreErr,
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
		strings.Contains(text, "name: "+nativeCodeGuardCodexSkillName), nil
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
	if _, err := runNativeCodeGuardCommand(ctx, gitPath, "clone", "--depth", "1", "--branch", nativeCodeGuardRepoBranch, nativeCodeGuardRepoURL, repoDir); err != nil {
		return "", func() {}, fmt.Errorf("clone Project CodeGuard: %w", err)
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
		!strings.Contains(text, "name: "+nativeCodeGuardCodexSkillName) {
		return fmt.Errorf("project CodeGuard skill source %s does not look like %s", sourceDir, nativeCodeGuardCodexSkillName)
	}
	return nil
}

func copyDirectoryAtomic(sourceDir, targetDir string) error {
	tmpDir := targetDir + ".tmp-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	_ = os.RemoveAll(tmpDir)
	defer os.RemoveAll(tmpDir)

	if err := copyDirectory(sourceDir, tmpDir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetDir), 0o755); err != nil {
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
