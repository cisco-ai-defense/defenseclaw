//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	claudeCodeDarwinIdentifier = "com.anthropic.claude-code"
	claudeCodeDarwinTeamID     = "Q6L2SF6YDW"
)

var runClaudeCodeDarwinIdentityCommand = func(path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", fmt.Errorf("%s timed out", path)
	}
	if len(output) > 64<<10 {
		return "", fmt.Errorf("%s output exceeds 65536 bytes", path)
	}
	return string(output), err
}

var errClaudeCodeDarwinXattrMissing = errors.New("extended attribute is absent")

// claudeCodeDarwinTrustedParentStop is a package-private test seam. Production
// leaves it empty so provenance validation walks every ancestor to the volume
// root; tests can stop at a private fixture root instead of inheriting the
// world-writable /private/tmp ancestor used by macOS test runners.
var claudeCodeDarwinTrustedParentStop string

func validateClaudeCodeAgentProvenance(opts SetupOpts) error {
	path := strings.TrimSpace(opts.AgentExecutable)
	if path == "" {
		// Preserve upgrade/bootstrap compatibility for configurations created
		// before executable receipts existed. New CLI Setup always supplies a
		// selection; Doctor classifies a missing protected identity as repair
		// required instead of making an unrelated gateway restart destructive.
		return nil
	}
	normalizedVersion := NormalizeAgentVersion("claudecode", opts.AgentVersion)
	if normalizedVersion == "" || compareVersion(normalizedVersion, "2.1.219") >= 0 {
		return errors.New(
			"Claude Code macOS releases >=2.1.219 are uncertified because DirectoryAdded has no published hook schema",
		)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("selected Claude Code executable path is not canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect selected Claude Code executable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("selected Claude Code executable is not a protected regular file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("selected Claude Code executable resolves through a symlink")
	}
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		parent, statErr := os.Stat(current)
		if statErr != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("selected Claude Code executable has an unsafe parent directory: %s", current)
		}
		if claudeCodeDarwinTrustedParentStop != "" && current == claudeCodeDarwinTrustedParentStop {
			break
		}
		next := filepath.Dir(current)
		if next == current {
			break
		}
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open selected Claude Code executable: %w", err)
	}
	var magic [4]byte
	_, readErr := file.Read(magic[:])
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !isMachOMagic(magic) {
		return errors.New("selected Claude Code executable is not a Mach-O image")
	}

	if _, err := runClaudeCodeDarwinIdentityCommand(
		"/usr/bin/codesign", "--verify", "--strict", "--verbose=2", path,
	); err != nil {
		return fmt.Errorf("Claude Code Mach-O code signature verification failed: %w", err)
	}
	detail, err := runClaudeCodeDarwinIdentityCommand(
		"/usr/bin/codesign", "-d", "--verbose=4", path,
	)
	required := []string{
		"Identifier=" + claudeCodeDarwinIdentifier,
		"TeamIdentifier=" + claudeCodeDarwinTeamID,
		"Authority=Developer ID Application: Anthropic PBC (" + claudeCodeDarwinTeamID + ")",
	}
	if err != nil {
		return fmt.Errorf("inspect Claude Code Mach-O signature identity: %w", err)
	}
	for _, marker := range required {
		if !strings.Contains(detail, marker) {
			return errors.New("Claude Code Mach-O signature identity is not Anthropic's pinned Developer ID")
		}
	}

	nativeArchitecture := runtime.GOARCH
	if nativeArchitecture == "amd64" {
		nativeArchitecture = "x86_64"
	}
	architectures, err := runClaudeCodeDarwinIdentityCommand("/usr/bin/lipo", "-archs", path)
	if err != nil || !containsWord(architectures, nativeArchitecture) {
		return fmt.Errorf("Claude Code Mach-O does not contain the native %s architecture", nativeArchitecture)
	}
	quarantine, err := runClaudeCodeDarwinIdentityCommand(
		"/usr/bin/xattr", "-p", "com.apple.quarantine", path,
	)
	if err == nil && strings.TrimSpace(quarantine) != "" {
		return errors.New("Claude Code Mach-O is still quarantined; launch/approve the official client before setup")
	}
	if err != nil {
		if errors.Is(err, errClaudeCodeDarwinXattrMissing) {
			// Attribute absence is the expected approved/native state.
		} else {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				return fmt.Errorf("inspect Claude Code quarantine state: %w", err)
			}
		}
	}

	expectedPath := ""
	expectedVersion := ""
	expectedDigest := ""
	if selection, ok := loadSetupAgentSelection(opts.DataDir, "claudecode"); ok {
		expectedPath = selection.Executable
		expectedVersion = selection.RawVersion
		expectedDigest = selection.SHA256
	} else if entry, exists := loadProtectedHookContractEntry(opts.DataDir, "claudecode"); exists {
		if !validSetupSelectedAgentExecutableEvidence(entry, "claudecode") {
			return errors.New("Claude Code hook contract has invalid setup-selected executable evidence")
		}
		expectedPath = entry.AgentExecutable
		expectedVersion = entry.RawAgentVersion
		expectedDigest = entry.AgentExecutableSHA256
	} else {
		return errors.New("Claude Code provenance requires protected setup-selected executable evidence")
	}
	if path != strings.TrimSpace(expectedPath) {
		return fmt.Errorf("selected Claude Code executable does not match protected evidence: %s", path)
	}
	if strings.TrimSpace(opts.AgentVersion) != strings.TrimSpace(expectedVersion) {
		return errors.New("selected Claude Code executable evidence is bound to a different agent version")
	}
	stablePath, digest, ok := setupSelectedAgentExecutableEvidence(path)
	if !ok || stablePath != path {
		return fmt.Errorf("selected Claude Code executable changed during validation: %s", path)
	}
	if !strings.EqualFold(digest, expectedDigest) {
		return fmt.Errorf("selected Claude Code executable digest does not match protected evidence: %s", path)
	}
	return nil
}

func isMachOMagic(magic [4]byte) bool {
	switch magic {
	case [4]byte{0xce, 0xfa, 0xed, 0xfe},
		[4]byte{0xcf, 0xfa, 0xed, 0xfe},
		[4]byte{0xfe, 0xed, 0xfa, 0xce},
		[4]byte{0xfe, 0xed, 0xfa, 0xcf},
		[4]byte{0xca, 0xfe, 0xba, 0xbe},
		[4]byte{0xbe, 0xba, 0xfe, 0xca},
		[4]byte{0xca, 0xfe, 0xba, 0xbf},
		[4]byte{0xbf, 0xba, 0xfe, 0xca}:
		return true
	default:
		return false
	}
}

func containsWord(value, wanted string) bool {
	for _, word := range strings.Fields(value) {
		if word == wanted {
			return true
		}
	}
	return false
}
