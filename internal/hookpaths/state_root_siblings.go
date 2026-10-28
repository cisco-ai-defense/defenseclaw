// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
)

// StateRootSiblingsPrefix + the state root carries the hook client's
// listing, read as the user, of the state root's parent directory:
// StateRootSiblings. A managed gateway runs as a service account that
// cannot list the user's home (_defenseclaw on macOS, ProtectHome on
// Linux), so it reads this fact instead (GAP-2404 pod check20).
const StateRootSiblingsPrefix = "\x00state-root-siblings:"

// StateRootSiblings is "0" when no name in the parent directory of root
// but root's own starts with root's name, in any letter case, and "1"
// when one does or the directory cannot be read. An archive named
// ~/.defenseclaw.zip strips to the state root ("${1%.zip}"), so a find
// that unzips each archive into its stripped name may reach the state
// only when this is "1".
func StateRootSiblings(root string) string {
	root = filepath.Clean(root)
	name := strings.ToLower(filepath.Base(root))
	entries, err := os.ReadDir(filepath.Dir(root))
	if err != nil || name == "." || name == string(filepath.Separator) {
		return "1"
	}
	for _, entry := range entries {
		other := strings.ToLower(entry.Name())
		if other != name && strings.HasPrefix(other, name) {
			return "1"
		}
	}
	return "0"
}
