// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A scan the gateway starts runs nicer than the gateway, so a startup rescan
// that admits many plugins at once does not take the CPU the gateway needs to
// answer a hook call within its budget (rel-1-0-10 GAP-0251). The skill and
// plugin scans run through RunTracked, MCP scans through RunTreeIsolated; the
// processes a scanner starts inherit the value (here: cat).
func TestScannerRunsBelowTheGatewayPriority(t *testing.T) {
	own := testThreadNice(t)
	if own >= 19 {
		t.Skip("the test already runs at the lowest priority")
	}
	want := min(own+10, 19)
	read := `set -- $(cat /proc/self/stat); echo "${19}"`
	for _, run := range []struct {
		name string
		run  func(*testing.T, *strings.Builder) error
	}{
		{"RunTracked", func(t *testing.T, out *strings.Builder) error {
			cmd := CommandContext(context.Background(), "/bin/sh", "-c", read)
			cmd.Stdout, cmd.Stderr = out, out
			return RunTracked(cmd)
		}},
		{"RunTreeIsolated", func(t *testing.T, out *strings.Builder) error {
			cmd := CommandContext(context.Background(), "/bin/sh", "-c", read)
			cmd.Stdout, cmd.Stderr = out, out
			return RunTreeIsolated(context.Background(), cmd)
		}},
	} {
		t.Run(run.name, func(t *testing.T) {
			var out strings.Builder
			if err := run.run(t, &out); err != nil {
				t.Fatalf("%s: %v: %s", run.name, err, out.String())
			}
			got, err := strconv.Atoi(strings.TrimSpace(out.String()))
			if err != nil {
				t.Fatalf("%s: nice of the scanner = %q", run.name, out.String())
			}
			if got != want {
				t.Fatalf("%s: the scanner ran at nice %d, want %d (the gateway runs at nice %d): a scan competes with the hook answers for the CPU",
					run.name, got, want, own)
			}
		})
	}
}

// testThreadNice is the nice value of the calling thread (Linux keeps one
// per thread; getpriority returns 20 minus it).
func testThreadNice(t *testing.T) int {
	t.Helper()
	prio, err := unix.Getpriority(unix.PRIO_PROCESS, 0)
	if err != nil {
		t.Fatalf("getpriority: %v", err)
	}
	return 20 - prio
}
