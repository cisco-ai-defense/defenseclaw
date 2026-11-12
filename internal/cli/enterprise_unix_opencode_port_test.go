// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// gas-ux-r1 GAP-0053, REVIEW-gx053-11: the administrator's clear of a
// contested OpenCode port: root only, needs --yes, clears only the named port
// and says what it cleared.
func TestOpenCodePortClearCommand(t *testing.T) {
	previousClear, previousEUID, previousPath := openCodePortClear, openCodePortClearGeteuid, openCodePortClearRecordPath
	t.Cleanup(func() {
		openCodePortClear, openCodePortClearGeteuid, openCodePortClearRecordPath = previousClear, previousEUID, previousPath
	})
	openCodePortClearRecordPath = func(string) (string, error) {
		return "/var/lib/defenseclaw-hook-guardian/opencode-service-ports.json", nil
	}
	var cleared []int
	openCodePortClear = func(path string, port int, by string, _ time.Time) ([]int, error) {
		cleared = append(cleared, port)
		return []int{1001, 1002}, nil
	}
	run := func(euid int, args ...string) (string, error) {
		openCodePortClearGeteuid = func() int { return euid }
		cmd := newUnixOpenCodePortClearCommand("linux")
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}
	if _, err := run(1000, "25003", "--yes"); err == nil || !strings.Contains(err.Error(), "must run as root") || len(cleared) != 0 {
		t.Fatalf("a non-root clear was not refused: %v %v", err, cleared)
	}
	if _, err := run(0, "25003"); err == nil || !strings.Contains(err.Error(), "--yes") || len(cleared) != 0 {
		t.Fatalf("a clear without --yes was not refused: %v %v", err, cleared)
	}
	if _, err := run(0, "not-a-port", "--yes"); err == nil || len(cleared) != 0 {
		t.Fatalf("a bad port was not refused: %v", err)
	}
	out, err := run(0, "25003", "--yes")
	if err != nil || len(cleared) != 1 || cleared[0] != 25003 {
		t.Fatalf("clear: %v %v", err, cleared)
	}
	if !strings.Contains(out, "cleared the contested mark of OpenCode port 25003") || !strings.Contains(out, "1001, 1002") {
		t.Fatalf("the clear is not reported: %q", out)
	}
	if got := openCodePortClearCommand("linux", 25003); got != "sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux opencode-port-clear 25003 --yes" {
		t.Fatalf("clear command %q", got)
	}
}

// GAP-0904: the stale-entry removal is root only, needs --yes, removes the
// entry of a uid without an account and refuses a live uid (the host account
// check answers true) or an unanswered check.
func TestOpenCodePortUnknownClearCommand(t *testing.T) {
	previousClear, previousEUID, previousPath, previousHas := openCodePortUnknownClear, openCodePortClearGeteuid, openCodePortClearRecordPath, openCodePortUnknownUIDHasAccount
	t.Cleanup(func() {
		openCodePortUnknownClear, openCodePortClearGeteuid, openCodePortClearRecordPath, openCodePortUnknownUIDHasAccount = previousClear, previousEUID, previousPath, previousHas
	})
	openCodePortClearRecordPath = func(string) (string, error) {
		return filepath.Join(os.TempDir(), "opencode-service-ports.json"), nil
	}
	var removed []int
	openCodePortUnknownClear = func(_ string, uid int, hasAccount func(int) (bool, error)) (enterprisehooks.UnixOpenCodeServicePortUnknown, error) {
		has, err := hasAccount(uid)
		if err != nil || has {
			return enterprisehooks.UnixOpenCodeServicePortUnknown{}, errors.New("refused")
		}
		removed = append(removed, uid)
		return enterprisehooks.UnixOpenCodeServicePortUnknown{UID: uid, User: "gone"}, nil
	}
	has, hasErr := false, error(nil)
	openCodePortUnknownUIDHasAccount = func(string, int) (bool, error) { return has, hasErr }
	run := func(euid int, args ...string) (string, error) {
		openCodePortClearGeteuid = func() int { return euid }
		cmd := newUnixOpenCodePortUnknownClearCommand("linux")
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}
	if _, err := run(1000, "1234", "--yes"); err == nil || len(removed) != 0 {
		t.Fatalf("a non-root removal was not refused: %v", err)
	}
	if _, err := run(0, "1234"); err == nil || !strings.Contains(err.Error(), "--yes") || len(removed) != 0 {
		t.Fatalf("a removal without --yes was not refused: %v", err)
	}
	if _, err := run(0, "alice", "--yes"); err == nil || len(removed) != 0 {
		t.Fatalf("a name was accepted as a uid: %v", err)
	}
	has = true
	if _, err := run(0, "1234", "--yes"); err == nil || len(removed) != 0 {
		t.Fatalf("a uid that still has an account was removed: %v", err)
	}
	has, hasErr = false, errors.New("lookup did not answer")
	if _, err := run(0, "1234", "--yes"); err == nil || len(removed) != 0 {
		t.Fatalf("an unanswered account check removed the entry: %v", err)
	}
	hasErr = nil
	out, err := run(0, "1234", "--yes")
	if err != nil || len(removed) != 1 || removed[0] != 1234 || !strings.Contains(out, "removed the OpenCode port record entry of uid 1234") {
		t.Fatalf("removal: %q %v %v", out, err, removed)
	}
}
