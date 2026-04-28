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
)

var (
	nativeCodeGuardInstallTimeout = 2 * time.Minute

	// nativeCodeGuardRepoDirOverride lets tests exercise the Codex
	// installer without cloning GitHub.
	nativeCodeGuardRepoDirOverride string
)

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

	targetDir := filepath.Join(codexSkillsDir(), nativeCodeGuardCodexSkillName)
	if installed, err := codexCodeGuardSkillInstalled(targetDir); err != nil {
		return err
	} else if installed {
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
	if err := copyDirectoryAtomic(sourceDir, targetDir); err != nil {
		return fmt.Errorf("install Codex CodeGuard skill to %s: %w", targetDir, err)
	}
	return nil
}

func codexHomeDir() string {
	if home := strings.TrimSpace(os.Getenv("CODEX_HOME")); home != "" {
		return home
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		return filepath.Join(home, ".codex")
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".codex")
	}
	return filepath.Join(".", ".codex")
}

func codexSkillsDir() string {
	return filepath.Join(codexHomeDir(), "skills")
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
