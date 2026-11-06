// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookguard

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

func TestMain(m *testing.M) {
	if value := os.Getenv("DC_HOOKGUARD_AVAILABILITY_TEST_CHILD"); value != "" {
		code, err := strconv.Atoi(value)
		if err != nil {
			os.Exit(99)
		}
		fmt.Fprint(os.Stdout, "ordinary answer\n")
		fmt.Fprint(os.Stderr, "ordinary note\n")
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func availabilityTestLauncher(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	launcher := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	out, err := os.OpenFile(launcher, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return launcher
}

func TestAvailabilityAnswersByEventAndStartResult(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	args := []string{"hook", "--connector", "claudecode"}
	var output, warning bytes.Buffer
	if code := RunEvent(missing, args, "UserPromptSubmit", false, nil, &output, &warning); code != 2 ||
		!strings.Contains(warning.String(), MissingMessage) {
		t.Fatalf("missing prompt: code=%d warning=%q", code, warning.String())
	}
	warning.Reset()
	if code := RunEvent(missing, args, "Stop", false, nil, &output, &warning); code != 1 ||
		!strings.Contains(warning.String(), NonBlockingExitMessage) {
		t.Fatalf("missing stop: code=%d warning=%q", code, warning.String())
	}
	folder := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	warning.Reset()
	if code := RunEvent(folder, args, "UserPromptSubmit", false, nil, &output, &warning); code != 2 ||
		!strings.Contains(warning.String(), CannotStartMessage) {
		t.Fatalf("folder prompt: code=%d warning=%q", code, warning.String())
	}

	launcher := availabilityTestLauncher(t)
	for _, tc := range []struct {
		name, event, child string
		wrapped            bool
		want               int
	}{
		{"ordinary allow", "UserPromptSubmit", "0", false, 0},
		{"ordinary nonblocking", "UserPromptSubmit", "7", false, 7},
		{"wrapped nonblocking", "UserPromptSubmit", "7", true, WrappedExitBase + 7},
		{"ordinary block", "UserPromptSubmit", "2", false, 2},
		{"started stop policy block", "Stop", "2", false, 2},
		{"wrapped started stop policy block", "SubagentStop", "2", true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DC_HOOKGUARD_AVAILABILITY_TEST_CHILD", tc.child)
			output.Reset()
			warning.Reset()
			code := RunEvent(launcher, args, tc.event, tc.wrapped, nil, &output, &warning)
			wantWarning := "ordinary note\n"
			if code != tc.want || output.String() != "ordinary answer\n" || warning.String() != wantWarning {
				t.Fatalf("code=%d stdout=%q stderr=%q, want %d and exact child output", code, output.String(), warning.String(), tc.want)
			}
		})
	}
}

func TestGuardInvocationAndCrashClass(t *testing.T) {
	launcher := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	for _, tc := range []struct {
		args    []string
		event   string
		wrapped bool
	}{
		{[]string{Subcommand, launcher, "hook", "--connector", "claudecode"}, "PreToolUse", false},
		{[]string{Subcommand, launcher, "hook", "--connector", "claudecode", "--event", "Stop"}, "Stop", false},
		{[]string{WrappedSubcommand, launcher, "hook", "--connector", "claudecode", "--event", "UserPromptSubmit"}, "UserPromptSubmit", true},
	} {
		got, argv, event, wrapped, ok := ParseInvocation(tc.args)
		if !ok || got != launcher || !reflect.DeepEqual(argv, []string{"hook", "--connector", "claudecode"}) ||
			event != tc.event || wrapped != tc.wrapped {
			t.Fatalf("ParseInvocation(%q) = %q %q %q %v %v", tc.args, got, argv, event, wrapped, ok)
		}
	}
	for _, args := range [][]string{
		{WrappedSubcommand, launcher, "hook", "--connector", "claudecode"},
		{Subcommand, launcher, "hook", "--connector", "claudecode", "--event", "Stop&exit"},
	} {
		if _, _, _, _, ok := ParseInvocation(args); ok {
			t.Errorf("accepted invalid argv %q", args)
		}
	}
	for _, code := range []int{int(uint32(0xC0000005)), int(uint32(0xC0000135)), -1} {
		if !ExceptionStatus(code) {
			t.Errorf("exit %x was not a crash", code)
		}
	}
	if ExceptionStatus(7) || ExceptionStatus(2) {
		t.Error("ordinary exits were classified as crashes")
	}
}

func TestNeutralEventsMatchHookLifecycle(t *testing.T) {
	want := hookexec.NeutralLifecycleEvents("claudecode")
	sort.Strings(want)
	got := []string{"Stop", "SubagentStop", "TeammateIdle", "StopFailure", "SessionEnd"}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("guard neutral events %q differ from hookexec %q", got, want)
	}
	for _, event := range got {
		if !NeutralEvent(event) {
			t.Errorf("%s was not neutral", event)
		}
	}
	if NeutralEvent("PreToolUse") || NeutralEvent("UserPromptSubmit") {
		t.Error("blocking hook events marked neutral")
	}
}
