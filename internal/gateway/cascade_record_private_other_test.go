// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// assertCascadeRecordPrivate checks that the record is owner-only: mode 0600.
func assertCascadeRecordPrivate(t *testing.T, path string) {
	t.Helper()
	testenv.AssertPrivateFile(t, path)
}
