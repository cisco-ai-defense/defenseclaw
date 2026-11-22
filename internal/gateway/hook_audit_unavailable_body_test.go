// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// rel-1-0-10:GAP-1222: the 503 of a call whose delivery journal the full
// disk could not take says so (cause=disk_full), so the per-user hook can
// name the full disk; any other journal failure keeps the plain answer.
func TestHookAuditUnavailableBodyNamesAFullDisk(t *testing.T) {
	for _, tc := range []struct {
		err  error
		full bool
	}{
		{fmt.Errorf("journal hook delivery: %w", syscall.ENOSPC), true},
		{errors.New("audit: journal hook delivery: database or disk is full"), true},
		{errors.New("audit: journal hook delivery: database is locked"), false},
	} {
		body := hookAuditUnavailableBody(tc.err)
		if body["error"] != "hook audit is unavailable" {
			t.Fatalf("%v: error = %q", tc.err, body["error"])
		}
		if got := body["cause"] == hookexec.HookAuditCauseDiskFull; got != tc.full {
			t.Fatalf("%v: body = %v, want disk_full=%v", tc.err, body, tc.full)
		}
	}
}
