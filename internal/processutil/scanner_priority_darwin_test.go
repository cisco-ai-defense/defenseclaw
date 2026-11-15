// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package processutil

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A skill or plugin scan the gateway starts runs nicer than the gateway, so a
// startup rescan that admits many plugins at once does not take the CPU the
// gateway needs to answer a hook call within its budget (rel-1-0-10
// GAP-0251). The processes a scanner starts inherit the value (here: ps).
func TestScannerRunsBelowTheGatewayPriority(t *testing.T) {
	own, err := unix.Getpriority(unix.PRIO_PROCESS, 0)
	if err != nil {
		t.Fatalf("getpriority: %v", err)
	}
	if own >= 19 {
		t.Skip("the test already runs at the lowest priority")
	}
	want := min(own+10, 19)
	var out strings.Builder
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", `exec ps -o nice= -p $$`)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("RunTracked: %v: %s", err, out.String())
	}
	got, err := strconv.Atoi(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatalf("nice of the scanner = %q", out.String())
	}
	if got != want {
		t.Fatalf("the scanner ran at nice %d, want %d (the gateway runs at nice %d): a scan competes with the hook answers for the CPU",
			got, want, own)
	}
}
