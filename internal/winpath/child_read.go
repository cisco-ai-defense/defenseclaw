// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"fmt"
	"io/fs"
	"strings"
)

// A held-parent lookup accepts a single directory entry, never another path,
// an alternate stream, or a name that ends early at an embedded NUL.
func validateReadChildName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "\\/:\x00") {
		return fmt.Errorf("%w: expected one child name", fs.ErrInvalid)
	}
	return nil
}

// normalizedReadLinkTarget matches Go 1.26's default Windows os.Readlink
// spelling without resolving or opening the target. The legacy
// GODEBUG=winreadlinkvolume=0 behavior opens volume targets and is deliberately
// not used by a no-follow metadata reader.
func normalizedReadLinkTarget(link reparseLink) string {
	if link.relative || !strings.HasPrefix(link.target, `\??\`) {
		return link.target
	}
	target := link.target[4:]
	switch {
	case len(target) >= 2 && target[1] == ':':
		return target
	case strings.HasPrefix(target, `UNC\`):
		return `\\` + target[4:]
	default:
		return `\\?\` + target
	}
}
