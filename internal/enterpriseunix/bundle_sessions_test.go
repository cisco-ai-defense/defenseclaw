// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestDarwinBundleSessionScanFromFakeProcessLister(t *testing.T) {
	const command = "ps -axww -o pid=,user=,lstart=,comm="
	runner := &fakeRunner{replies: map[string]fakeReply{
		command: {result: CommandResult{Stdout: []byte("8664 dcw-std1 Tue Oct 13 06:00:00 2026 /usr/local/bin/claude\n")}},
	}}
	env := &Env{Runner: runner}
	processes, err := env.bundleDarwinProcesses(context.Background(), map[string]string{"claude": "claudecode"})
	if err != nil {
		t.Fatal(err)
	}
	changed := time.Date(2026, 10, 13, 7, 0, 0, 0, time.Local)
	status := enterprisestatus.ScanSessions(func() ([]enterprisestatus.SessionProcess, error) { return processes, nil }, map[string]time.Time{"claudecode": changed}, true)
	if status.State != "known" || status.Count != 1 || status.Entries[0].PID != 8664 || status.Entries[0].User != "dcw-std1" {
		t.Fatalf("macOS old Claude session = %+v", status)
	}
}
