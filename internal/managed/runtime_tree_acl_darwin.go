// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package managed

import (
	"bufio"
	"bytes"
	"os/exec"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

var darwinACLEntryLine = lazyregexp.New(`^\s+\d+: `)

// runtimeTreeHasNoACL reports whether no entry below root carries a macOS
// ACL, from one recursive `ls -le` listing. The per-entry check runs
// `ls -lde` once for each of the scanner runtime's ~22,000 entries and took
// minutes per scan; a tree with any ACL entry still gets that check.
func runtimeTreeHasNoACL(root string) bool {
	cmd := exec.Command("/bin/ls", "-leRA", "--", root)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	lines := bufio.NewScanner(bytes.NewReader(output))
	lines.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for lines.Scan() {
		if darwinACLEntryLine.Match(lines.Bytes()) {
			return false
		}
	}
	return lines.Err() == nil
}
