// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// reverseDotDotFixture is dotDotLinkFixture with the roles swapped: the
// cleaned spelling project/status is the protected link, and the entry the
// kernel opens from project/jump (other/status) is an ordinary file.
func reverseDotDotFixture(t *testing.T) (home, project string) {
	t.Helper()
	home, project = dotDotLinkFixture(t)
	other := filepath.Join(filepath.Dir(project), "other")
	if err := os.Remove(filepath.Join(project, "status")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "status")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(other, "status")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "status"), []byte("ordinary"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, project
}

// windowsReadsDotDotLexically is true where a dot-dot step after a link has a
// second reading. Win32 removes the step from the text before it opens the
// name; Git Bash and the hook follow the link first. A name is ordinary only
// when both readings are, so in this fixture (the cleaned spelling is a
// protected link) the name is protected on Windows and ordinary elsewhere.
var windowsReadsDotDotLexically = runtime.GOOS == "windows"

// GAP-0641 / GAP-0679 review 10: an ordinary file reached through a linked
// working directory is an ordinary late call even when the cleaned spelling
// names a protected link, where the link is followed before the step (POSIX).
// On Windows the cleaned spelling is the other reading, so the name is
// protected. The direct protected name stays closed everywhere.
func TestGAP0641LinkedParentOrdinaryFileIsAnOrdinaryPayload(t *testing.T) {
	home, project := reverseDotDotFixture(t)
	cwd := filepath.Join(project, "jump")
	t.Chdir(cwd)
	ordinary := !windowsReadsDotDotLexically
	for _, row := range []struct {
		dir, command string
		ordinary     bool
	}{
		{cwd, "cat ../status", ordinary},
		{cwd, "cat ./../status", ordinary},
		{cwd, "cat " + cwd + "/../status", ordinary},
		{cwd, "grep --file=../status x", ordinary},
		{project, "cat jump/../status", ordinary},
		{project, "cat status", false},
	} {
		if got := ordinaryNoAnswerPayloadInHome(gap0641Payload(row.dir, row.command), home); got != row.ordinary {
			t.Errorf("payload ordinary %q in %s=%v, want %v", row.command, row.dir, got, row.ordinary)
		}
	}
}

// An ordinary file reached through a linked working directory stays open at the
// OSS deadline; the plain protected name stays closed.
func TestGAP0641LinkedParentOrdinaryFileStaysOpenAtTheOSSDeadline(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	addr := hungGateway(t)
	_, project := reverseDotDotFixture(t)
	cwd := filepath.Join(project, "jump")
	t.Chdir(cwd)
	for _, row := range []struct {
		dir, command string
		blocked      bool
	}{
		{cwd, "cat ../status", windowsReadsDotDotLexically},
		{project, "cat status", true},
	} {
		t.Run(row.command, func(t *testing.T) {
			result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
				opts.FailMode = "open"
				opts.OutageFailModeNow = func() string { return "open" }
				opts.Stdin = strings.NewReader(string(gap0641Payload(row.dir, row.command)))
			})
			if got := nativeOutageBlocked(result); got != row.blocked {
				t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", got, row.blocked, result.code, result.stdout, result.stderr)
			}
		})
	}
}

func TestGAP0679LinkedParentOrdinaryFileStaysOpenInTheManagedAdminOpenOutage(t *testing.T) {
	shortAnswerBudget(t, 550*time.Millisecond)
	fastRestartRetries(t)
	_, project := reverseDotDotFixture(t)
	cwd := filepath.Join(project, "jump")
	t.Chdir(cwd)
	for _, row := range []struct {
		dir, command string
		blocked      bool
	}{
		{cwd, "cat ../status", windowsReadsDotDotLexically},
		{project, "cat status", true},
	} {
		t.Run(row.command, func(t *testing.T) {
			rt := &stubRT{onRequest: func(rt *stubRT, req *http.Request) (*http.Response, error) {
				if rt.requests == 1 {
					return nil, fakeStoppedSCM()
				}
				<-req.Context().Done()
				return nil, req.Context().Err()
			}}
			result := run(t, "codex", rt, func(opts *Options) {
				managedCodex(opts)
				opts.FailMode = "open"
				opts.ExplainUnenrolledAccount = true
				opts.StartedAt = time.Now()
				opts.FailureLogHome = userLogHome(opts.Home)
				opts.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"exec_command","cwd":%q,"tool_input":{"cmd":%q}}`, row.dir, row.command))
			})
			if got := blocked(result); got != row.blocked {
				t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", got, row.blocked, result.code, result.stdout, result.stderr)
			}
		})
	}
}
