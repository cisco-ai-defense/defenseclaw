// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"strings"
	"testing"
)

// rel-1-0-6 GAP-0174: with the audit filesystem full, managed hooks blocked
// every agent prompt and tool call (an audit write failure fails closed on a
// managed install), while status and verify said that enforcement continues
// and only the audit trail stops. The warnings now say the filesystem is
// full, that managed hooks block agent work until space is freed, and how
// it resumes.
func TestStatusSaysManagedHooksBlockWhileTheAuditFilesystemIsFull(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	for _, tc := range []struct {
		name  string
		avail uint64
		want  []string
	}{
		{"full", 0, []string{h.env.Layout.DataDir + " is full (0 KiB free of 10.0 GiB)", "managed hooks block agent prompts and tool calls (fail closed)", "free space on it", "resumes by itself"}},
		{"nearly full", 100 << 20, []string{h.env.Layout.DataDir + " has 100.0 MiB free", "when it fills", "managed hooks then block agent prompts and tool calls (fail closed)"}},
	} {
		h.env.DiskSpace = func(string) (uint64, uint64, uint64, error) { return tc.avail, 10 << 30, 1, nil }
		for _, action := range []string{ActionStatus, ActionVerify} {
			got := messagesOf(h.run(Options{Action: action}).Warnings, codeDiskSpaceLow)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("%s %s: disk_space_low %q does not say %q", tc.name, action, got, want)
				}
			}
			if strings.Contains(strings.ToLower(got), "enforcement continues") {
				t.Fatalf("%s %s: disk_space_low still says enforcement continues: %q", tc.name, action, got)
			}
		}
	}
	h.env.DiskSpace = func(string) (uint64, uint64, uint64, error) { return 0, 10 << 30, 1, nil }
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		return 200, []byte(`{"api":{"state":"running"},"telemetry":{"state":"error","details":{"event_history_failure":"sqlite_write_failed","event_history_last_sqlite_class":"full"}}}`), nil
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		got := messagesOf(h.run(Options{Action: action}).Warnings, codeAuditWriteFailed)
		for _, want := range []string{"managed hooks block", "fail closed", h.env.Layout.DataDir + " is full", "free space on it"} {
			if !strings.Contains(got, want) {
				t.Fatalf("%s: audit_write_failed %q does not say %q", action, got, want)
			}
		}
	}
}
