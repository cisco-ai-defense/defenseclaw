//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// validateTrustedPathACL rejects effective macOS ACL entries that grant
// write-like authority beyond the POSIX owner/group/mode metadata validated by
// trust_unix.go. macOS keeps those mode bits unchanged when an ACL is added, so
// ignoring the extended entries would misclassify an attacker-writable path as
// administrator-trusted.
func validateTrustedPathACL(path string) error {
	cmd := exec.Command("/bin/ls", "-lde", "--", path)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
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
