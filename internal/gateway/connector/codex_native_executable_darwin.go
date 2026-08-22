// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	codexMacOSTeamID      = "2DC432GLL2"
	codexMacOSIdentifier  = "codex"
	codexMacOSRequirement = `=identifier "codex" and anchor apple generic and certificate leaf[subject.OU] = "2DC432GLL2" and certificate leaf[subject.CN] = "Developer ID Application: OpenAI OpCo, LLC (2DC432GLL2)"`
)

var runCodexDarwinIdentityCommand = func(path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

var readCodexDarwinQuarantine = func(path string) (string, error) {
	value := make([]byte, 4096)
	size, err := unix.Getxattr(path, "com.apple.quarantine", value)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(value[:size])), nil
}

var validateCodexDarwinFileACL = hookAPIValidateDirectoryACL

var probeCodexDarwinAgentVersion = runProtectedDarwinAgentVersionProbe

func validateCodexNativeExecutablePlatform(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect selected Codex macOS executable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("selected Codex macOS executable is not a regular non-link file: %s", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("selected Codex macOS executable has unsafe writable mode %04o: %s", info.Mode().Perm(), path)
	}
	if err := validateCodexDarwinFileACL(path); err != nil {
		return fmt.Errorf("validate selected Codex macOS executable ACL: %w", err)
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open selected Codex macOS executable: %w", err)
	}
	var magic [4]byte
	_, readErr := file.Read(magic[:])
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !isCodexMachOMagic(magic) {
		return fmt.Errorf("selected Codex policy executable is not a Mach-O image: %s", path)
	}

	archOutput, err := runCodexDarwinIdentityCommand("/usr/bin/lipo", "-archs", path)
	if err != nil {
		return fmt.Errorf("inspect selected Codex macOS architecture: %w: %s", err, strings.TrimSpace(archOutput))
	}
	expectedArchitecture := "x86_64"
	if runtime.GOARCH == "arm64" {
		expectedArchitecture = "arm64"
	}
	if !codexMacOSArchitectureListContains(archOutput, expectedArchitecture) {
		return fmt.Errorf(
			"selected Codex macOS executable does not contain the host architecture %s: %s",
			expectedArchitecture,
			strings.TrimSpace(archOutput),
		)
	}
	if output, err := runCodexDarwinIdentityCommand(
		"/usr/bin/codesign", "--verify", "--strict", "--verbose=2", "-R", codexMacOSRequirement, path,
	); err != nil {
		return fmt.Errorf("verify selected Codex macOS signature: %w: %s", err, strings.TrimSpace(output))
	}
	output, err := runCodexDarwinIdentityCommand("/usr/bin/codesign", "-dvvv", path)
	if err != nil {
		return fmt.Errorf("inspect selected Codex macOS signature: %w: %s", err, strings.TrimSpace(output))
	}
	if !codexDarwinSignatureHasPinnedIdentity(output) {
		return errors.New("selected Codex macOS executable is not signed by the expected OpenAI Developer ID")
	}

	quarantine, err := readCodexDarwinQuarantine(path)
	if err == nil {
		return fmt.Errorf("selected Codex macOS executable is quarantined: %q", quarantine)
	}
	if !errors.Is(err, unix.ENOATTR) {
		return fmt.Errorf("inspect selected Codex macOS quarantine attribute: %w", err)
	}
	return nil
}

func validateCodexNativeExecutableVersionPlatform(path, expectedVersion, expectedDigest string) error {
	probedVersion, err := probeCodexDarwinAgentVersion("codex", path, expectedDigest)
	if err != nil {
		return fmt.Errorf("probe selected Codex macOS executable version: %w", err)
	}
	if err := validateProtectedDarwinAgentVersion("codex", expectedVersion, probedVersion); err != nil {
		return err
	}
	stablePath, digest, ok := setupSelectedAgentExecutableEvidence(path)
	if !ok || stablePath != path || !strings.EqualFold(digest, expectedDigest) {
		return errors.New("selected Codex macOS executable changed during its version probe")
	}
	return nil
}

func codexMacOSArchitectureListContains(output, expected string) bool {
	for _, architecture := range strings.Fields(output) {
		if architecture == expected {
			return true
		}
	}
	return false
}

func codexDarwinSignatureHasPinnedIdentity(detail string) bool {
	wantIdentifier := "Identifier=" + codexMacOSIdentifier
	wantTeam := "TeamIdentifier=" + codexMacOSTeamID
	wantAuthority := "Authority=Developer ID Application: OpenAI OpCo, LLC (" + codexMacOSTeamID + ")"
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

func isCodexMachOMagic(magic [4]byte) bool {
	value := binary.BigEndian.Uint32(magic[:])
	switch value {
	case 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca:
		return true
	default:
		return false
	}
}
