// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// testSymlink makes a symbolic-link fixture (testenv.Symlink: a skip where a
// standard Windows account may not create one).
func testSymlink(t testing.TB, target, link string) {
	t.Helper()
	testenv.Symlink(t, target, link)
}
