// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

type rowsAcquirer struct {
	acquire.Acquirer
	rows []procprobe.Process
}

func (a rowsAcquirer) Processes(context.Context) ([]procprobe.Process, int, error) {
	return append([]procprobe.Process(nil), a.rows...), 2, nil
}

// GAP-1105: a per-user gateway's runtime planes must not read or export
// another account's command lines.
func TestOwnAccountProcessesDropsOtherAccounts(t *testing.T) {
	name, _ := inventory.CurrentProcessOwner()
	if name == "" {
		t.Skip("current account cannot be resolved")
	}
	base := rowsAcquirer{rows: []procprobe.Process{
		{PID: 10, Name: "claude", User: name, Cmdline: "claude"},
		{PID: 11, Name: "python", User: "dc-other-account", Cmdline: "python other"},
	}}
	rows, skipped, err := ownAccountProcesses(&config.Config{}, base).Processes(context.Background())
	if err != nil || skipped != 2 || len(rows) != 1 || rows[0].PID != 10 {
		t.Fatalf("per-user rows = %+v skipped=%d err=%v, want only pid 10", rows, skipped, err)
	}
	managedCfg := &config.Config{DeploymentMode: "managed_enterprise"}
	if _, wrapped := ownAccountProcesses(managedCfg, base).(ownerProcessAcquirer); wrapped {
		t.Fatal("managed gateway acquirer was wrapped")
	}
}
