// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package plane

import (
	"os"
	"os/user"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// p0-round GAP-1389: a process-creation event carries the uid that owns the
// process as it is read, and the account's name once the account database
// has answered for that uid, so a session that exits before the next poll
// still names who ran it. The event loop never waits on the lookup.
func TestProcessEventCarriesTheUIDOwningTheProcessAndItsCachedAccount(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("no current account: %v", err)
	}
	if procprobe.OwnerNameOfUID(os.Geteuid()) == "" {
		t.Skip("the account database does not name this uid")
	}
	event := (&linuxSource{}).describe(os.Getpid())
	if event.UID == nil || *event.UID != os.Geteuid() {
		t.Fatalf("event uid = %v, want %d", event.UID, os.Geteuid())
	}
	if event.User != current.Username {
		t.Fatalf("event user = %q, want %q", event.User, current.Username)
	}
}
