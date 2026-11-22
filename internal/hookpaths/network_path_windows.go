// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"errors"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// pathOpenDirectory is pathOpen on Windows: directory, junction, share and
// MSYS path handling stay as pathOpen reads them (#1486).
func pathOpenDirectory(name string) (*os.File, error) {
	return pathOpen(name)
}

// networkShareRoot is the \\server\share volume of a path on a network share,
// in every spelling Windows opens one by (windowsShareRoot), as the path
// spells it; "" for a drive path, a relative path and every other device
// path (\\?\C:\..., \\.\pipe\...).
func networkShareRoot(path string) string {
	root, _ := windowsShareRoot(path)
	return root
}

// gatedPath is the share gate for a read network_path.go does not make
// itself (a Windows API call on the path: file identity, link count, DACL):
// ok is false when it must not be made, and otherwise read is the path to
// hand it, held as readGated holds it until release.
func gatedPath(name string) (read string, release func() bool, ok bool) {
	gate := networkPathGate(name, true)
	if gate.unanswered {
		return "", nil, false
	}
	if !gate.proved {
		return gate.read, func() bool { return true }, true
	}
	still, err := pathidentity.HoldUnlinked(fixturefs.Map(gate.read))
	switch {
	case errors.Is(err, pathidentity.ErrLinked):
		return "", nil, false
	case err != nil:
		// Nothing to hold (a missing file): the call fails as it would.
		return gate.read, func() bool { return true }, true
	}
	return gate.read, still, true
}
