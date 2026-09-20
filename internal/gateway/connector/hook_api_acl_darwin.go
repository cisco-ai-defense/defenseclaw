// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
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
	for _, line := range strings.Split(string(output), "\n") {
		normalized := strings.ToLower(strings.TrimSpace(line))
		colon := strings.IndexByte(normalized, ':')
		if colon <= 0 {
			continue
		}
		if _, err := strconv.ParseUint(normalized[:colon], 10, 32); err != nil {
			continue
		}
		allowIndex := strings.Index(normalized, " allow ")
		if allowIndex < 0 {
			continue
		}
		fields := strings.Fields(normalized[allowIndex+len(" allow "):])
		if len(fields) == 0 {
			return fmt.Errorf("cannot parse macOS allow ACL on %s", path)
		}
		for _, permission := range strings.Split(fields[0], ",") {
			switch permission {
			case "write", "add_file", "append", "add_subdirectory", "delete", "delete_child",
				"writeattr", "writeextattr", "writesecurity", "chown":
				return fmt.Errorf("%s has write-capable macOS ACL entry", path)
			}
		}
	}
	return nil
}
