// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const freshIdentityACLInspectionTimeout = 2 * time.Second

var freshIdentityWriteACLPermissions = map[string]struct{}{
	"add_file": {}, "add_subdirectory": {}, "append": {}, "chown": {},
	"delete": {}, "delete_child": {}, "write": {}, "writeattr": {},
	"writeextattr": {}, "writesecurity": {},
}

var freshIdentityReadACLPermissions = map[string]struct{}{
	"read": {}, "readattr": {}, "readextattr": {},
}

func validateFreshIdentityPathACL(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), freshIdentityACLInspectionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/ls", "-lde", "--", path)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("gateway: inspect macOS ACL for %s: timed out", path)
		}
		return fmt.Errorf("gateway: inspect macOS ACL for %s: %w", path, err)
	}
	return validateFreshIdentityACLOutput(path, output)
}

func validateFreshIdentityACLOutput(path string, output []byte) error {
	lines := strings.Split(strings.TrimRight(string(output), "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return fmt.Errorf("gateway: macOS ACL for %s could not be inspected", path)
	}
	modeFields := strings.Fields(lines[0])
	if len(modeFields) == 0 {
		return fmt.Errorf("gateway: macOS ACL for %s could not be inspected", path)
	}

	interpreted := false
	for _, rawLine := range lines[1:] {
		normalized := strings.ToLower(strings.TrimSpace(rawLine))
		colon := strings.IndexByte(normalized, ':')
		if colon <= 0 {
			continue
		}
		if _, err := strconv.ParseUint(normalized[:colon], 10, 32); err != nil {
			continue
		}
		allowIndex := strings.LastIndex(normalized, " allow ")
		denyIndex := strings.LastIndex(normalized, " deny ")
		if allowIndex < 0 && denyIndex < 0 {
			continue
		}
		interpreted = true
		if allowIndex < 0 {
			continue
		}
		fields := strings.Fields(normalized[allowIndex+len(" allow "):])
		if len(fields) == 0 {
			return fmt.Errorf("gateway: cannot parse macOS allow ACL on %s", path)
		}
		for _, rawPermission := range strings.Split(fields[0], ",") {
			permission := strings.TrimSpace(rawPermission)
			if _, unsafe := freshIdentityWriteACLPermissions[permission]; unsafe {
				return fmt.Errorf("gateway: %s has write-capable macOS ACL entry", path)
			}
			if _, unsafe := freshIdentityReadACLPermissions[permission]; unsafe {
				return fmt.Errorf("gateway: %s has confidentiality-breaking macOS ACL entry", path)
			}
		}
	}
	if strings.Contains(modeFields[0], "+") && !interpreted {
		return fmt.Errorf("gateway: macOS ACL for %s could not be interpreted", path)
	}
	return nil
}
