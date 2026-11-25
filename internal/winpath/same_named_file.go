// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// SameNamedFile reports whether path names the file want names, by want's
// own name. The two spellings must share one ComparisonKey (on Windows the
// \\?\ prefix dropped, the 8.3 short names of existing components expanded
// and case folded) and identify the same filesystem object
// (pathidentity.Same).
//
// Ownership checks of an administrator hook binary use it (GAP-2175): an
// 8.3 alias such as C:\PROGRA~1\...\DEFENS~1.EXE names the installed binary
// itself, while pathidentity.Same alone also accepts any other name for the
// same object. A junction, a symbolic link or a hard link in another folder
// keeps its own name after expansion, so it is refused: whoever can write
// that folder could point the name at another file after the check. A path
// that does not exist, a relative alias and a different file are refused
// too.
func SameNamedFile(path, want string) bool {
	path, want = strings.TrimSpace(path), strings.TrimSpace(want)
	if path == "" || want == "" {
		return false
	}
	return ComparisonKey(path) == ComparisonKey(want) && pathidentity.Same(path, want)
}
