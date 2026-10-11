//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"os/exec"
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
	entries, err := ParseDarwinACLListing(string(output), []string{path})
	if err != nil {
		return fmt.Errorf("inspect macOS ACL: %w", err)
	}
	for _, entry := range entries[path] {
		if entry.GrantsWrite() {
			return fmt.Errorf("%s has write-capable macOS ACL entry", path)
		}
	}
	return nil
}
