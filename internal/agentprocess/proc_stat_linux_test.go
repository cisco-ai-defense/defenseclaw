// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package agentprocess

import (
	"os"
	"testing"
)

// parseStat reads the parent, start time and state after a name that holds
// spaces and parentheses, and refuses a line with too few fields.
func TestParseStatReadsFieldsAfterAnAwkwardName(t *testing.T) {
	line := "4242 (a) b (c) S 77 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n"
	process, err := parseStat(4242, []byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if process.Name != "a) b (c" || process.Parent != 77 || process.Start != 987654 || process.Exited {
		t.Errorf("parsed %+v", process)
	}
	zombie, err := parseStat(4242, []byte("4242 (z) Z 77 4242 4242 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0"))
	if err != nil || !zombie.Exited || zombie.Start != 5 {
		t.Errorf("zombie parsed %+v, %v", zombie, err)
	}
	for _, short := range []string{"4242 (z) S 77 4242 4242 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0\n", "4242 (z)", "4242 z S 77"} {
		if _, err := parseStat(4242, []byte(short)); err == nil {
			t.Errorf("accepted the short line %q", short)
		}
	}
}

// The cheaper read finds this process and its parent as the process table does.
func TestLookupProcReadsThisProcessAndItsParent(t *testing.T) {
	process, err := lookupProc(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if process.PID != os.Getpid() || process.Parent != os.Getppid() || process.Start <= 0 || process.Name == "" {
		t.Errorf("lookup of this process: %+v (parent %d)", process, os.Getppid())
	}
	if _, err := lookupProc(1 << 30); err != errNotFound {
		t.Errorf("a missing process gave %v, want errNotFound", err)
	}
}
