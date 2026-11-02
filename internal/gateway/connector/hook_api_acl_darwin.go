// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const hookAPIACLInspectionTimeout = 5 * time.Second

func hookAPIValidateDirectoryACL(path string) error {
	return hookAPIValidateDirectoryACLWithInspector(path, hookAPIACLInspectionTimeout, func(ctx context.Context, path string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "/bin/ls", "-lde", "--", path)
		cmd.Env = []string{"LANG=C", "LC_ALL=C"}
		return cmd.Output()
	})
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
	// entries alone.
	return managed.JudgeDarwinACLOutput(path, output)
}
