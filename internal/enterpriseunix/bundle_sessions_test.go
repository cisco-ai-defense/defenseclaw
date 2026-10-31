// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestDarwinBundleSessionScanFromFakeProcessLister(t *testing.T) {
	const command = "ps -axww -o pid=,uid=,etime=,args="
	runner := &fakeRunner{replies: map[string]fakeReply{
		command: {result: CommandResult{Stdout: []byte("8664 501 2-00:00:00 /usr/local/bin/claude\n")}},
	}}
	setDarwinProcessArgv(t, func(int) ([]string, error) { return nil, errors.New("fake macOS host: no process argv") })
	now := time.Date(2026, 10, 15, 6, 0, 0, 0, time.Local)
	env := &Env{Runner: runner, Now: func() time.Time { return now }}
	processes, err := env.bundleDarwinProcesses(context.Background(), map[string]string{"claude": "claudecode"})
	if err != nil {
		t.Fatal(err)
	}
	changed := time.Date(2026, 10, 13, 7, 0, 0, 0, time.Local)
	status := enterprisestatus.ScanSessions(func() ([]enterprisestatus.SessionProcess, error) { return processes, nil }, map[string]time.Time{"claudecode": changed}, true)
	if status.State != "known" || status.Count != 1 || status.Entries[0].PID != 8664 || status.Entries[0].User == "" {
		t.Fatalf("macOS old Claude session = %+v", status)
	}
}
