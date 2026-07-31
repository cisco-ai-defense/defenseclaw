// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"bytes"
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
	codexMacOSTeamID     = "2DC432GLL2"
	codexMacOSIdentifier = "codex"
)

func validateCodexNativeExecutablePlatform(path string) error {
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	archs := exec.CommandContext(ctx, "/usr/bin/lipo", "-archs", path)
	archOutput, err := archs.CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect selected Codex macOS architecture: %w: %s", err, strings.TrimSpace(string(archOutput)))
	}
	expectedArchitecture := "x86_64"
	if runtime.GOARCH == "arm64" {
		expectedArchitecture = "arm64"
	}
	if !codexMacOSArchitectureListContains(string(archOutput), expectedArchitecture) {
		return fmt.Errorf(
			"selected Codex macOS executable does not contain the host architecture %s: %s",
			expectedArchitecture,
			strings.TrimSpace(string(archOutput)),
		)
	}
	verify := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "--verbose=2", path)
	if output, err := verify.CombinedOutput(); err != nil {
		return fmt.Errorf("verify selected Codex macOS signature: %w: %s", err, strings.TrimSpace(string(output)))
	}
	details := exec.CommandContext(ctx, "/usr/bin/codesign", "-dvvv", path)
	output, err := details.CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect selected Codex macOS signature: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if !bytes.Contains(output, []byte("Identifier="+codexMacOSIdentifier)) ||
		!bytes.Contains(output, []byte("TeamIdentifier="+codexMacOSTeamID)) ||
		!bytes.Contains(output, []byte("Authority=Developer ID Application: OpenAI OpCo, LLC ("+codexMacOSTeamID+")")) {
		return errors.New("selected Codex macOS executable is not signed by the expected OpenAI Developer ID")
	}

	quarantine := make([]byte, 4096)
	size, err := unix.Getxattr(path, "com.apple.quarantine", quarantine)
	if err == nil {
		return fmt.Errorf("selected Codex macOS executable is quarantined: %q", strings.TrimSpace(string(quarantine[:size])))
	}
	if !errors.Is(err, unix.ENOATTR) {
		return fmt.Errorf("inspect selected Codex macOS quarantine attribute: %w", err)
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

func isCodexMachOMagic(magic [4]byte) bool {
	value := binary.BigEndian.Uint32(magic[:])
	switch value {
	case 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca:
		return true
	default:
		return false
	}
}
