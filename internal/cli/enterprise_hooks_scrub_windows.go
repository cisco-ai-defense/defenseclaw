// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "os"

// fileOwner returns -1, -1 on Windows: the ACL owner concept doesn't
// map to uid/gid the way writeConfigAtomic uses it. The atomic-write
// helper still runs, just without an explicit chown call — which is
// the same behaviour the Windows uninstall path uses today (Cursor /
// Codex / Claude Code hook configs on Windows inherit their creator's
// ACL and we don't touch it).
func fileOwner(_ os.FileInfo) (int, int) {
	return -1, -1
}
