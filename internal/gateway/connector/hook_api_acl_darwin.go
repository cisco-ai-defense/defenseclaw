// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const hookAPIACLInspectionTimeout = 5 * time.Second

// hookAPIDarwinACLVerdicts keeps the clean ACL verdicts of the directories
// above the hook API token (hookAPIACLVerdicts, rel-1-0-6 GAP-0129).
var hookAPIDarwinACLVerdicts hookAPIACLVerdicts

func hookAPIValidateDirectoryACL(path string) error {
	return hookAPIDarwinACLVerdicts.check(path, hookAPIDarwinDirectoryIdentity(path), func() error {
		return hookAPIValidateDirectoryACLWithInspector(path, hookAPIACLInspectionTimeout, func(ctx context.Context, path string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, "/bin/ls", "-lde", "--", path)
			cmd.Env = []string{"LANG=C", "LC_ALL=C"}
			return cmd.Output()
		})
	})
}

// hookAPIDarwinDirectoryIdentity is the identity a clean ACL verdict of path
// is kept under: device, inode, mode, owner, group and status-change time
// (chmod +a and every other ACL change set the status-change time). "" when
// path cannot be read.
func hookAPIDarwinDirectoryIdentity(path string) string {
	info, err := os.Lstat(path)
	if err != nil {
		return ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%o:%d:%d:%d.%09d", stat.Dev, stat.Ino, stat.Mode, stat.Uid, stat.Gid,
		stat.Ctimespec.Sec, stat.Ctimespec.Nsec)
}

func hookAPIValidateDirectoryACLWithInspector(path string, timeout time.Duration, inspect func(context.Context, string) ([]byte, error)) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := inspect(ctx, path)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("inspect macOS ACL for %s: timed out after %s", path, timeout)
		}
		return fmt.Errorf("inspect macOS ACL for %s: %w", path, err)
	}
	// The managed rule judges effective write authority for principals other
	// than root, wheel and admin, and leaves read, deny and inherit-only
	// entries alone. A standalone process keeps the strict rule: any allow
	// entry with a write-class right.
	if managed.StandaloneTrustScope() {
		return managed.JudgeDarwinACLOutputStrict(path, output)
	}
	return managed.JudgeDarwinACLOutput(path, output)
}
