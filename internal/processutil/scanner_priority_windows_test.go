// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package processutil

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const scannerPriorityHelperEnv = "DC_PROCESSUTIL_SCANNER_PRIORITY_HELPER"

// A scan the gateway starts runs in the below-normal priority class, so a
// startup rescan that admits many plugins at once does not take the CPU the
// gateway needs to answer a hook call within its budget (rel-1-0-10
// GAP-0251). The skill and plugin scans run through RunTracked, MCP scans
// through RunTreeIsolated.
func TestScannerRunsBelowTheGatewayPriority(t *testing.T) {
	if os.Getenv(scannerPriorityHelperEnv) == "1" {
		class, err := windows.GetPriorityClass(windows.CurrentProcess())
		if err != nil {
			fmt.Printf("error=%v\n", err)
			return
		}
		fmt.Printf("class=%#x\n", class)
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range []struct {
		name string
		run  func(cmd *exec.Cmd) error
	}{
		{"RunTracked", RunTracked},
		{"RunTreeIsolated", func(cmd *exec.Cmd) error { return RunTreeIsolated(context.Background(), cmd) }},
	} {
		t.Run(run.name, func(t *testing.T) {
			var out strings.Builder
			cmd := CommandContext(context.Background(), self, "-test.run=^TestScannerRunsBelowTheGatewayPriority$")
			cmd.Env = append(os.Environ(), scannerPriorityHelperEnv+"=1")
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := run.run(cmd); err != nil {
				t.Fatalf("%s: %v: %s", run.name, err, out.String())
			}
			if want := fmt.Sprintf("class=%#x", windows.BELOW_NORMAL_PRIORITY_CLASS); !strings.Contains(out.String(), want) {
				t.Fatalf("%s: the scanner reported %q, want %s: a scan competes with the hook answers for the CPU", run.name, out.String(), want)
			}
		})
	}
}
