// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestFindExecWithoutTerminatorRunsNoChild: bash ends the statement at an
// unescaped ;, so a find -exec that no ; or + word ends is incomplete: find
// refuses the whole expression and runs no child, and the next statement
// runs on its own. A project link made before it stays an ordinary link
// (rel-1-0-6:GAP-0189). Every write that reaches the keys file, through a
// link made in the command or the project link, still blocks.
func TestFindExecWithoutTerminatorRunsNoChild(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"project link then an unterminated find -exec mv", "project", `cd {P} && ln -s src/main.go alias6.go; find . -type f -name "*.tmp" -exec mv {} build/ ;`, "allow"},
		{"project link then an unterminated find -exec mv to /tmp", "project", `cd {P} && ln -s README.md docs.md; find . -name "*.bak" -exec mv {} /tmp/ ;`, "allow"},
		{"no cd, project link, unterminated find", "project", `ln -s README.md docs.md; find . -name "*.bak" -exec mv {} /tmp/ ;`, "allow"},
		{"unterminated -execdir after a project link", "project", `ln -s README.md docs.md; find . -name "*.bak" -execdir mv {} old/ ;`, "allow"},
		{"escaped terminator after a project link", "project", `cd {P} && ln -s src/main.go alias6.go; find . -type f -name "*.tmp" -exec mv {} build/ \;`, "allow"},
		{"unterminated find without a link", "project", `cd {P} && find . -type f -name "*.tmp" -exec mv {} build/ ;`, "allow"},
		{"keys link, unterminated find, then a write through the link", "project", `ln -s ../.ssh/authorized_keys kl; find . -name "*.tmp" -exec mv {} build/ ; echo k >> kl`, "block"},
		{"unterminated find, then an append to the keys file", "project", `ln -s README.md docs.md; find . -name "*.tmp" -exec mv {} build/ ; echo k >> ~/.ssh/authorized_keys`, "block"},
		{"unterminated find, then a write through the project keys link", "project", `ln -s README.md docs.md; find . -name "*.tmp" -exec mv {} build/ ; echo k >> keylink`, "block"},
		{"find -exec mv of a keys link, then a write to the new name", "project", `ln -s ../.ssh/authorized_keys kl; find . -name kl -exec mv {} moved \; ; echo k >> moved`, "block"},
		{"terminated move, then a pattern word that reads as -exec", "project", `ln -s ../.ssh/authorized_keys kl; find . -name kl -exec mv {} moved \; -name -exec ; echo k >> moved`, "block"},
		{"find -exec mv with + of a keys link, then a write", "project", `ln -s ../.ssh/authorized_keys kl; find . -name kl -exec mv -t sub {} + ; echo k >> sub/kl`, "block"},
	})
}
