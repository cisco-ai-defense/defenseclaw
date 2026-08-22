// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package safefile

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const darwinPrivateACLTimeout = 5 * time.Second

type darwinPrivateACLCommand func(context.Context, string, ...string) ([]byte, error)

func runDarwinPrivateACLCommand(ctx context.Context, executable string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	return cmd.Output()
}

// protectPrivateACL removes inherited or explicit macOS ACL authority and
// verifies the exact path still names the object the caller protected. POSIX
// chmod does not clear extended ACLs, so mode 0600/0700 alone is insufficient
// for private DefenseClaw state.
func protectPrivateACL(path string, expected os.FileInfo) error {
	return protectPrivateACLWithCommand(
		path, expected, darwinPrivateACLTimeout, runDarwinPrivateACLCommand,
	)
}

func protectPrivateACLWithCommand(
	path string,
	expected os.FileInfo,
	timeout time.Duration,
	run darwinPrivateACLCommand,
) error {
	if timeout <= 0 {
		return fmt.Errorf("safefile: invalid macOS ACL protection timeout for %s", path)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("safefile: resolve macOS ACL path %s: %w", path, err)
	}
	if err := validateDarwinPrivateACLIdentity(absolute, expected); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if _, err := run(ctx, "/bin/chmod", "-N", absolute); err != nil {
		return darwinPrivateACLCommandError(ctx, "remove", path, timeout, err)
	}
	if err := validateDarwinPrivateACLIdentity(absolute, expected); err != nil {
		return err
	}
	return inspectDarwinPrivateACL(ctx, path, absolute, expected, timeout, run)
}

func validatePrivateACL(path string, expected os.FileInfo) error {
	return validatePrivateACLWithCommand(
		path, expected, darwinPrivateACLTimeout, runDarwinPrivateACLCommand,
	)
}

func validatePrivateACLWithCommand(
	path string,
	expected os.FileInfo,
	timeout time.Duration,
	run darwinPrivateACLCommand,
) error {
	if timeout <= 0 {
		return fmt.Errorf("safefile: invalid macOS ACL inspection timeout for %s", path)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("safefile: resolve macOS ACL path %s: %w", path, err)
	}
	if err := validateDarwinPrivateACLIdentity(absolute, expected); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return inspectDarwinPrivateACL(ctx, path, absolute, expected, timeout, run)
}

func inspectDarwinPrivateACL(
	ctx context.Context,
	path string,
	absolute string,
	expected os.FileInfo,
	timeout time.Duration,
	run darwinPrivateACLCommand,
) error {
	output, err := run(ctx, "/bin/ls", "-lde", "--", absolute)
	if err != nil {
		return darwinPrivateACLCommandError(ctx, "inspect", path, timeout, err)
	}
	if err := validateDarwinPrivateACLIdentity(absolute, expected); err != nil {
		return err
	}
	return validateDarwinPrivateACLOutput(path, output)
}

func darwinPrivateACLCommandError(
	ctx context.Context,
	action string,
	path string,
	timeout time.Duration,
	err error,
) error {
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("safefile: %s macOS ACL for %s: timed out after %s", action, path, timeout)
	}
	return fmt.Errorf("safefile: %s macOS ACL for %s: %w", action, path, err)
}

func validateDarwinPrivateACLIdentity(path string, expected os.FileInfo) error {
	if expected == nil {
		return fmt.Errorf("safefile: missing expected identity for macOS ACL path: %s", path)
	}
	current, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("safefile: revalidate macOS ACL path %s: %w", path, err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !os.SameFile(expected, current) {
		return fmt.Errorf("safefile: private path changed during macOS ACL protection: %s", path)
	}
	return nil
}

// validateDarwinPrivateACLOutput mirrors the private-authority contract used
// by the macOS uninstaller: every allow entry is refused, even a read-only
// grant. Deny entries do not broaden authority and remain acceptable.
func validateDarwinPrivateACLOutput(path string, output []byte) error {
	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 {
		return fmt.Errorf("safefile: cannot interpret macOS ACL for %s", path)
	}
	modeFields := strings.Fields(lines[0])
	if len(modeFields) == 0 || !validDarwinPrivateACLModeField(modeFields[0]) {
		return fmt.Errorf("safefile: cannot interpret macOS ACL for %s", path)
	}

	aclEntries := 0
	for _, line := range lines[1:] {
		normalized := strings.ToLower(strings.TrimSpace(line))
		colon := strings.IndexByte(normalized, ':')
		if colon <= 0 {
			continue
		}
		if _, err := strconv.ParseUint(normalized[:colon], 10, 32); err != nil {
			continue
		}
		aclEntries++
		padded := " " + normalized + " "
		allowIndex := strings.LastIndex(padded, " allow ")
		denyIndex := strings.LastIndex(padded, " deny ")
		switch {
		case allowIndex > denyIndex:
			return fmt.Errorf("safefile: private path has a macOS allow ACL entry: %s", path)
		case denyIndex > allowIndex:
			continue
		default:
			return fmt.Errorf("safefile: cannot interpret macOS ACL entry for %s", path)
		}
	}
	if strings.Contains(modeFields[0], "+") && aclEntries == 0 {
		return fmt.Errorf("safefile: cannot interpret macOS ACL for %s", path)
	}
	return nil
}

func validDarwinPrivateACLModeField(mode string) bool {
	if len(mode) != 10 && len(mode) != 11 {
		return false
	}
	if mode[0] != '-' && mode[0] != 'd' {
		return false
	}
	for i := 1; i < 10; i++ {
		if !strings.ContainsRune("rwxstST-", rune(mode[i])) {
			return false
		}
	}
	return len(mode) == 10 || mode[10] == '+' || mode[10] == '@'
}
