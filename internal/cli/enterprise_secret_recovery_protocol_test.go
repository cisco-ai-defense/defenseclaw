// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWindowsSecretRecoveryProtocolOnlyStartsAfterUnfinishedRestart(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		wantStart   bool
		wantLock    bool
	}{
		{name: "absent credential with stopped gateway", input: ""},
		{name: "refused change", input: ""},
		{name: "normal restarted gateway", input: "ARM\nCANCEL\n", wantLock: true},
		{name: "killed after stop attempt", input: "ARM\n", wantLock: true, wantStart: true},
		{name: "restart failed", input: "ARM\n", wantLock: true, wantStart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ready bytes.Buffer
			locked, started := false, false
			err := runWindowsSecretRecoveryProtocol(strings.NewReader(tc.input), &ready,
				func() (func(), error) {
					locked = true
					return func() {}, nil
				},
				func() error {
					if !locked {
						t.Fatal("gateway recovery ran outside both change locks")
					}
					started = true
					return nil
				})
			if err != nil || ready.String() != "READY\n" || locked != tc.wantLock || started != tc.wantStart {
				t.Fatalf("protocol: ready=%q lock=%t start=%t err=%v", ready.String(), locked, started, err)
			}
		})
	}
}

func TestWindowsSecretRecoveryProtocolRefusesBadArm(t *testing.T) {
	for _, input := range []string{"A", "NOPE", "BAD\n"} {
		called := false
		err := runWindowsSecretRecoveryProtocol(strings.NewReader(input), &bytes.Buffer{},
			func() (func(), error) { called = true; return func() {}, nil },
			func() error { called = true; return nil })
		if err == nil || called {
			t.Fatalf("invalid arm %q entered recovery: %v", input, err)
		}
	}
	wantErr := errors.New("lock denied")
	if err := runWindowsSecretRecoveryProtocol(strings.NewReader("ARM\n"), &bytes.Buffer{},
		func() (func(), error) { return nil, wantErr }, func() error { t.Fatal("start after lock refusal"); return nil }); !errors.Is(err, wantErr) {
		t.Fatalf("lock error = %v", err)
	}
}
