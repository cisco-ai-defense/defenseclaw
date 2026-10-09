// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// `enterprise linux tetragon status|pause|resume` is registered on the Linux
// group only, with the flags the docs name, and refuses bad arguments with
// the lifecycle's invalid-arguments exit code.
func TestUnixTetragonCommandTree(t *testing.T) {
	want := enterprisestatus.InvalidArgsExitCode(runtime.GOOS)
	for _, action := range []string{"verify", "status", "pause", "resume"} {
		cmd, _, err := rootCmd.Find([]string{"enterprise", "linux", "tetragon", action})
		if err != nil || cmd == nil || cmd.Name() != action || cmd.Flags().Lookup("json") == nil {
			t.Fatalf("enterprise linux tetragon %s: %v", action, err)
		}
		parseErr := cmd.ParseFlags([]string{"--bogus"})
		if parseErr == nil || commandExitCode(cmd.FlagErrorFunc()(cmd, parseErr)) != want {
			t.Fatalf("tetragon %s --bogus: %v", action, parseErr)
		}
		if err := cmd.ValidateArgs([]string{"extra"}); err == nil || commandExitCode(err) != want {
			t.Fatalf("tetragon %s extra: %v", action, err)
		}
	}
	if cmd, _, err := rootCmd.Find([]string{"enterprise", "macos", "tetragon"}); err == nil && cmd.Name() == "tetragon" {
		t.Fatal("tetragon is a Linux sensor; the macOS group must not have it")
	}
	group, _, err := rootCmd.Find([]string{"enterprise", "linux", "tetragon"})
	if err != nil {
		t.Fatal(err)
	}
	var coded *exitCodeError
	if runErr := group.RunE(group, []string{"bogus"}); !errors.As(runErr, &coded) || coded.ExitCode() != want {
		t.Fatalf("tetragon bogus: %v", runErr)
	}

	pause, _, _ := rootCmd.Find([]string{"enterprise", "linux", "tetragon", "pause"})
	for _, name := range []string{"for", "until-reboot", "reason"} {
		if pause.Flags().Lookup(name) == nil {
			t.Fatalf("tetragon pause lacks --%s", name)
		}
	}
	for value, want := range map[string]time.Duration{"4h": 4 * time.Hour, "30m": 30 * time.Minute, "7d": 7 * 24 * time.Hour, "2d": 48 * time.Hour} {
		var got time.Duration
		if err := (&pauseDurationValue{d: &got}).Set(value); err != nil || got != want {
			t.Fatalf("--for %s = %s, %v", value, got, err)
		}
	}
	if !strings.Contains(plainFlagValueError(pause.ParseFlags([]string{"--for=soon"})), "--for takes a duration up to 7d") {
		t.Fatal("--for=soon has no plain message")
	}
	if err := pause.ParseFlags([]string{"--for=0"}); err != nil {
		t.Fatal(err)
	}
	if usage := pause.Flags().Lookup("for").Usage; !strings.Contains(usage, "default 4h, at most 7d") {
		t.Fatalf("--for usage %q", usage)
	}

	verify, _, _ := rootCmd.Find([]string{"enterprise", "linux", "tetragon", "verify"})
	if verify.Flags().Lookup("ready-for") == nil || verify.Flags().Lookup("user") != nil {
		t.Fatal("tetragon verify takes --ready-for only")
	}
	for _, mode := range []string{"consume", "observe", "Enforce"} {
		var got string
		if err := (&readyForValue{mode: &got}).Set(mode); err != nil || got != strings.ToLower(mode) {
			t.Fatalf("--ready-for %s = %q, %v", mode, got, err)
		}
	}
	if !strings.Contains(plainFlagValueError(verify.ParseFlags([]string{"--ready-for=off"})), "--ready-for takes consume, observe or enforce") {
		t.Fatal("--ready-for=off has no plain message")
	}
	status, _, _ := rootCmd.Find([]string{"enterprise", "linux", "tetragon", "status"})
	if status.Flags().Lookup("user") == nil || status.Flags().Lookup("ready-for") != nil {
		t.Fatal("tetragon status takes --user")
	}
}
