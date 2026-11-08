// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package procidentity

import (
	"os"
	"regexp"
	"testing"
)

// Recorded is the kern.proc start time as seconds.microseconds, the text the
// gateway writes in gateway.pid; it is not the lstart text of Of.
func TestRecordedIsTheNativeStartTheGatewayWrites(t *testing.T) {
	got, ok := Recorded(os.Getpid())
	if !ok || !regexp.MustCompile(`^[0-9]+\.[0-9]{6}$`).MatchString(got) {
		t.Fatalf("Recorded = %q, %v; want seconds.microseconds", got, ok)
	}
	lock, _ := Of(os.Getpid())
	if !IsRecorded(os.Getpid(), got) || IsRecorded(os.Getpid(), lock) || IsRecorded(os.Getpid(), "") {
		t.Fatalf("IsRecorded does not tell %q from the lock text %q", got, lock)
	}
}
