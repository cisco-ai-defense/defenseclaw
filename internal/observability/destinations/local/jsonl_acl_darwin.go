//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"fmt"
	"os/exec"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// jsonlACLProblem fails closed when an existing private output has an allow
// ACL entry, including read-only entries that mode 0600 cannot reveal.
func jsonlACLProblem(path string) string {
	cmd := exec.Command("/bin/ls", "-lde", "--", path)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		return fmt.Sprintf("has a macOS ACL that cannot be inspected: %v", err)
	}
	entries, err := managed.ParseDarwinACLListing(string(output), []string{path})
	if err != nil {
		return fmt.Sprintf("has a macOS ACL that cannot be inspected: %v", err)
	}
	for _, entry := range entries[path] {
		if entry.GrantsAccess() {
			return "has a macOS ACL entry granting another account access"
		}
	}
	return ""
}
