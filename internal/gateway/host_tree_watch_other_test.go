// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package gateway

import "testing"

// watchHostTreeOpens needs inotify; elsewhere it observes nothing and the
// copy-mode test relies on its FSView count and unreadable pass.
func watchHostTreeOpens(t *testing.T, _ string) func() []string {
	t.Helper()
	t.Log("host open watch needs Linux inotify; skipped")
	return func() []string { return nil }
}
