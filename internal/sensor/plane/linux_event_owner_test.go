// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package plane

import (
	"os"
	"os/user"
	"testing"
)

// p0-round GAP-1389: a process-creation event names the account that owns
// the process as it is read, so a session that exits before the next poll
// still names who ran it.
func TestProcessEventNamesTheAccountOwningTheProcess(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("no current account: %v", err)
	}
	event := (&linuxSource{}).describe(os.Getpid())
	if event.User != current.Username {
		t.Fatalf("event user = %q, want %q", event.User, current.Username)
	}
}
