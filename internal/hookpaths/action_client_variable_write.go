// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

// A whole-command target scan can also see read operands and the entry of
// an ordinary link removed by rm. The client carries it as evidence for any
// command with a parameter expansion: a managed gateway cannot read the
// user's home, so it cannot settle a variable operand itself, and a list of
// writer verbs (tee, install, rsync, dd, touch, ...) always left one out
// (GAP-0298: touch; GAP-0327: chmod, chown). The read-only commands return
// at the top of the target scan, so the extra decision stays cheap.
func actionClientVariableWriteCandidate(command, _ string) bool {
	return strings.ContainsRune(command, '$')
}
