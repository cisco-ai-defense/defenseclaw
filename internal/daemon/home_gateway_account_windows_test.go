// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"os"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// rel-1-0-10:GAP-1164: the creation time the kernel's process list gives
// without a handle is the start identity a gateway records about itself, in
// the same text, so an elevated gateway another logon session started (it
// does not open for this caller) is matched by the time alone.
func TestHolderStartIdentityWithoutAHandle(t *testing.T) {
	want, err := processStartIdentity(os.Getpid())
	if err != nil || want == "" {
		t.Fatalf("processStartIdentity(self) = %q, %v", want, err)
	}
	created, ok := procprobe.CreationTime(os.Getpid())
	if !ok {
		t.Fatal("the kernel process list names no creation time for this process")
	}
	if got := strconv.FormatInt(created.UnixNano(), 10); got != want {
		t.Fatalf("creation time from the process list %s, start identity %s", got, want)
	}
	if got, err := holderStartIdentity(os.Getpid()); err != nil || got != want {
		t.Fatalf("holderStartIdentity(self) = %q, %v; want %q", got, err, want)
	}
	if got := SelfStartIdentity(); got != want {
		t.Fatalf("SelfStartIdentity() = %q, want %q", got, want)
	}
	if _, err := holderStartIdentity(0x3ffffff0); err == nil {
		t.Fatal("a PID that does not exist has no start identity")
	}
	if _, ok := procprobe.CreationTime(0x3ffffff0); ok {
		t.Fatal("the process list names no PID that does not exist")
	}
}
