// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	claudeCodeDarwinIdentifier  = "com.anthropic.claude-code"
	claudeCodeDarwinTeamID      = "Q6L2SF6YDW"
	claudeCodeDarwinRequirement = `=identifier "com.anthropic.claude-code" and anchor apple generic and certificate leaf[subject.OU] = "Q6L2SF6YDW" and certificate leaf[subject.CN] = "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)"`
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

var readClaudeCodeDarwinQuarantine = func(path string) (string, error) {
	value := make([]byte, 4096)
	size, err := unix.Getxattr(path, "com.apple.quarantine", value)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(value[:size])), nil
}

var (
	validateClaudeCodeDarwinDirectory = hookAPIValidateDirectory
	validateClaudeCodeDarwinOwner     = hookAPIValidateOwner
	validateClaudeCodeDarwinFileACL   = hookAPIValidateDirectoryACL
	probeClaudeCodeDarwinAgentVersion = runProtectedDarwinAgentVersionProbe
)

func validateClaudeCodeAgentProvenance(opts SetupOpts) error {
	path := strings.TrimSpace(opts.AgentExecutable)
	if path == "" {
		if claudeCodeProtectedExecutableEvidenceExists(opts.DataDir) {
			return errors.New(
				"Claude Code protected executable evidence exists but the selected executable is missing; run connector repair",
			)
		}
		// Preserve upgrade/bootstrap compatibility for configurations created
		// before executable receipts existed. Fresh CLI setup supplies a sealed
		// executable selection, and CodeGuard installation requires one.
		return nil
	}
	if err := validateClaudeCodeDarwinNativeImage(path); err != nil {
		return err
	}

	expectedPath := ""
	expectedVersion := ""
	expectedDigest := ""
	if entry, exists := loadProtectedHookContractEntry(opts.DataDir, "claudecode"); exists {
		if selection, supersedes := supersedingProtectedSetupSelection(
			opts.DataDir,
			"claudecode",
			entry,
		); supersedes {
			expectedPath = selection.Executable
			expectedVersion = selection.RawVersion
			expectedDigest = selection.SHA256
		} else {
			if !validSetupSelectedAgentExecutableEvidence(entry, "claudecode") {
				return errors.New("Claude Code hook contract has invalid setup-selected executable evidence")
			}
			expectedPath = entry.AgentExecutable
			expectedVersion = entry.RawAgentVersion
			expectedDigest = entry.AgentExecutableSHA256
		}
	} else if selection, ok := loadSetupAgentSelection(opts.DataDir, "claudecode"); ok {
		expectedPath = selection.Executable
		expectedVersion = selection.RawVersion
		expectedDigest = selection.SHA256
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
	probedVersion, err := probeClaudeCodeDarwinAgentVersion("claudecode", path, expectedDigest)
	if err != nil {
		return fmt.Errorf("probe selected Claude Code executable version: %w", err)
	}
	if err := validateProtectedDarwinAgentVersion("claudecode", expectedVersion, probedVersion); err != nil {
		return err
	}
	postProbePath, postProbeDigest, ok := setupSelectedAgentExecutableEvidence(path)
	if !ok || postProbePath != path || !strings.EqualFold(postProbeDigest, expectedDigest) {
		return errors.New("selected Claude Code executable changed during its version probe")
	}
	return nil
}

func validateClaudeCodeDarwinNativeImage(path string) error {
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
	if err := validateClaudeCodeDarwinDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("validate selected Claude Code executable ancestry: %w", err)
	}
	if err := validateClaudeCodeDarwinOwner(path, info); err != nil {
		return fmt.Errorf("validate selected Claude Code executable owner: %w", err)
	}
	if err := validateClaudeCodeDarwinFileACL(path); err != nil {
		return fmt.Errorf("validate selected Claude Code executable ACL: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("selected Claude Code executable resolves through a symlink")
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open selected Claude Code executable: %w", err)
	}
	var magic [4]byte
	_, readErr := file.Read(magic[:])
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !isClaudeCodeMachOMagic(magic) {
		return errors.New("selected Claude Code executable is not a Mach-O image")
	}

	if _, err := runClaudeCodeDarwinIdentityCommand(
		"/usr/bin/codesign", "--verify", "--strict", "--verbose=2", "-R", claudeCodeDarwinRequirement, path,
	); err != nil {
		return fmt.Errorf("Claude Code Mach-O code signature verification failed: %w", err)
	}
	detail, err := runClaudeCodeDarwinIdentityCommand(
		"/usr/bin/codesign", "-d", "--verbose=4", path,
	)
	if err != nil {
		return fmt.Errorf("inspect Claude Code Mach-O signature identity: %w", err)
	}
	if !claudeCodeDarwinSignatureHasPinnedIdentity(detail) {
		return errors.New("Claude Code Mach-O signature identity is not Anthropic's pinned Developer ID")
	}

	nativeArchitecture := runtime.GOARCH
	if nativeArchitecture == "amd64" {
		nativeArchitecture = "x86_64"
	}
	architectures, err := runClaudeCodeDarwinIdentityCommand("/usr/bin/lipo", "-archs", path)
	if err != nil || !containsClaudeCodeArchitecture(architectures, nativeArchitecture) {
		return fmt.Errorf("Claude Code Mach-O does not contain the native %s architecture", nativeArchitecture)
	}
	quarantine, err := readClaudeCodeDarwinQuarantine(path)
	if err == nil {
		return fmt.Errorf(
			"Claude Code Mach-O is still quarantined; launch/approve the official client before setup: %q",
			quarantine,
		)
	} else if !errors.Is(err, unix.ENOATTR) {
		return fmt.Errorf("inspect Claude Code quarantine state: %w", err)
	}
	return nil
}

func claudeCodeProtectedExecutableEvidenceExists(dataDir string) bool {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return false
	}
	if claudeCodeProtectedHookContractEvidenceExists(dataDir) {
		return true
	}
	path := filepath.Join(dataDir, agentSelectionFile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return false
	} else if err != nil {
		return true
	}
	data, valid := readStablePrivateStateFile(dataDir, agentSelectionFile, agentSelectionMaxBytes)
	if !valid {
		return true
	}
	var receipt agentSelectionReceipt
	if err := json.Unmarshal(data, &receipt); err != nil ||
		receipt.SchemaVersion != agentSelectionSchemaVersion ||
		receipt.Selections == nil {
		return true
	}
	if _, err := time.Parse(time.RFC3339, receipt.UpdatedAt); err != nil {
		return true
	}

	// A protected receipt for another connector is not Claude evidence. Still
	// fail closed if any entry aliases Claude or the receipt cannot unambiguously
	// bind each map key to one structurally valid connector selection.
	for key, selection := range receipt.Selections {
		trimmedKey := strings.TrimSpace(key)
		trimmedSelection := strings.TrimSpace(selection.Connector)
		canonicalKey := normalizeConnectorName(trimmedKey)
		canonicalSelection := normalizeConnectorName(trimmedSelection)
		if canonicalKey == "claudecode" || canonicalSelection == "claudecode" {
			return true
		}
		if trimmedKey == "" || key != trimmedKey || selection.Connector != trimmedSelection ||
			canonicalKey != trimmedKey || canonicalSelection != trimmedSelection ||
			canonicalSelection != canonicalKey ||
			!claudeCodeOtherSelectionIsStructurallyValid(selection) {
			return true
		}
	}
	return false
}

func claudeCodeProtectedHookContractEvidenceExists(dataDir string) bool {
	path := filepath.Join(dataDir, hookContractLockFile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return false
	} else if err != nil {
		return true
	}
	data, valid := readStablePrivateStateFile(dataDir, hookContractLockFile, hookContractLockMaxBytes)
	if !valid {
		return true
	}
	var lock hookContractLock
	if err := json.Unmarshal(data, &lock); err != nil ||
		lock.Version < 1 || lock.Version > hookContractLockVersion ||
		lock.Connectors == nil {
		return true
	}
	if _, err := time.Parse(time.RFC3339, lock.UpdatedAt); err != nil {
		return true
	}
	for key, entry := range lock.Connectors {
		trimmedKey := strings.TrimSpace(key)
		trimmedConnector := strings.TrimSpace(entry.Connector)
		canonicalKey := normalizeConnectorName(trimmedKey)
		canonicalConnector := normalizeConnectorName(trimmedConnector)
		if canonicalKey == "claudecode" || canonicalConnector == "claudecode" {
			return true
		}
		if trimmedKey == "" || key != trimmedKey || entry.Connector != trimmedConnector ||
			canonicalKey != trimmedKey || canonicalConnector != trimmedConnector ||
			canonicalConnector != canonicalKey {
			return true
		}
		if _, err := time.Parse(time.RFC3339, entry.UpdatedAt); err != nil {
			return true
		}
	}
	return false
}

func claudeCodeOtherSelectionIsStructurallyValid(selection agentSelectionEvidence) bool {
	if selection.Source != "setup-selected" ||
		strings.ContainsAny(selection.Executable, "\x00\r\n") ||
		!filepath.IsAbs(selection.Executable) ||
		filepath.Clean(selection.Executable) != selection.Executable ||
		!validLowerHexSHA256(selection.SHA256) ||
		strings.TrimSpace(selection.RawVersion) == "" ||
		strings.TrimSpace(selection.NormalizedVersion) == "" {
		return false
	}
	selectedAt, selectedErr := time.Parse(time.RFC3339, selection.SelectedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, selection.ExpiresAt)
	if selectedErr != nil || expiresErr != nil || !expiresAt.After(selectedAt) ||
		expiresAt.Sub(selectedAt) > agentSelectionMaxLifetime {
		return false
	}
	return true
}

func claudeCodeDarwinSignatureHasPinnedIdentity(detail string) bool {
	wantIdentifier := "Identifier=" + claudeCodeDarwinIdentifier
	wantTeam := "TeamIdentifier=" + claudeCodeDarwinTeamID
	wantAuthority := "Authority=Developer ID Application: Anthropic PBC (" + claudeCodeDarwinTeamID + ")"
	foundIdentifier := false
	foundTeam := false
	foundAuthority := false
	for _, line := range strings.Split(detail, "\n") {
		switch strings.TrimSpace(line) {
		case wantIdentifier:
			foundIdentifier = true
		case wantTeam:
			foundTeam = true
		case wantAuthority:
			foundAuthority = true
		}
	}
	return foundIdentifier && foundTeam && foundAuthority
}

func isClaudeCodeMachOMagic(magic [4]byte) bool {
	value := binary.BigEndian.Uint32(magic[:])
	switch value {
	case 0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe,
		0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca:
		return true
	default:
		return false
	}
}

func containsClaudeCodeArchitecture(value, wanted string) bool {
	for _, word := range strings.Fields(value) {
		if word == wanted {
			return true
		}
	}
	return false
}
