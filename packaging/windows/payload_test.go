// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package windowspayload

import (
	"bytes"
	"runtime"
	"testing"
)

func TestPayloadOperatingSystemBoundary(t *testing.T) {
	wantAvailable := runtime.GOOS == "windows"
	if got := Available(); got != wantAvailable {
		t.Fatalf("Available() = %v on %s, want %v", got, runtime.GOOS, wantAvailable)
	}
	if !wantAvailable {
		if len(Installer()) != 0 || len(Module()) != 0 {
			t.Fatal("non-Windows build carries a Windows lifecycle payload")
		}
		return
	}
	if !bytes.Contains(Module(), []byte("function Set-DefenseClawGatewayServiceLogonRight")) {
		t.Fatal("Windows build does not embed service logon provisioning")
	}
}

func TestPayloadAccessorsReturnIndependentCopies(t *testing.T) {
	for name, getter := range map[string]func() []byte{
		"installer": Installer,
		"module":    Module,
	} {
		t.Run(name, func(t *testing.T) {
			first := getter()
			if len(first) == 0 {
				return // Non-Windows payloads are deliberately empty.
			}
			original := append([]byte(nil), first...)
			first[0] ^= 0xff
			if !bytes.Equal(getter(), original) {
				t.Fatal("caller mutation changed the embedded lifecycle payload")
			}
		})
	}
}
