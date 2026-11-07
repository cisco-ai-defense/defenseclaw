// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"net/http"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dotDotLinkFixture links jump to a directory whose "status" is a link to
// the authorized_keys of the test account. The kernel follows jump before
// "..", so jump/../status opens the protected file; the clean spelling is
// ordinary.
func dotDotLinkFixture(t *testing.T) (home, cwd string) {
	t.Helper()
	account, err := osuser.Current()
	if err != nil {
		t.Fatal(err)
	}
	home = account.HomeDir
	root := t.TempDir()
	cwd = filepath.Join(root, "project")
	other := filepath.Join(root, "other")
	for _, dir := range []string{cwd, filepath.Join(other, "child")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(other, "status")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "child"), filepath.Join(cwd, "jump")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "status"), []byte("ordinary"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, cwd
}

// GAP-0641 / GAP-0679 review 8: a protected link reached through a directory
// link and a dot-dot step is not an ordinary late call, in the payload
// classifier and in the delivered answers. The clean twin stays ordinary.
func TestGAP0641LinkBeforeDotDotPayloadIsNotOrdinary(t *testing.T) {
	home, cwd := dotDotLinkFixture(t)
	for _, row := range []struct {
		command  string
		ordinary bool
	}{
		{"cat jump/../status", false},
		{"cat " + cwd + "/jump/../status", false},
		{"cat status", true},
		{"cat ../project/status", true},
	} {
		if got := ordinaryNoAnswerPayloadInHome(gap0641Payload(cwd, row.command), home); got != row.ordinary {
			t.Errorf("payload ordinary %q=%v, want %v", row.command, got, row.ordinary)
		}
	}
	readPayload := fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":%q,"tool_input":{"file_path":%q}}`, cwd, cwd+"/jump/../status")
	if ordinaryNoAnswerPayloadInHome([]byte(readPayload), home) {
		t.Error("a Read through a linked directory and dot-dot was accepted as ordinary")
	}
}

func TestGAP0641LinkBeforeDotDotStaysClosedAtTheOSSDeadline(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	addr := hungGateway(t)
	_, cwd := dotDotLinkFixture(t)
	for _, row := range []struct {
		name, command string
		blocked       bool
	}{
		{"protected link behind dot-dot", "cat jump/../status", true},
		{"clean twin", "cat status", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
				opts.FailMode = "open"
				opts.OutageFailModeNow = func() string { return "open" }
				opts.Stdin = strings.NewReader(string(gap0641Payload(cwd, row.command)))
			})
			if got := nativeOutageBlocked(result); got != row.blocked {
				t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", got, row.blocked, result.code, result.stdout, result.stderr)
			}
		})
	}
}

func TestGAP0679LinkBeforeDotDotStaysClosedInTheManagedAdminOpenOutage(t *testing.T) {
	shortAnswerBudget(t, 550*time.Millisecond)
	fastRestartRetries(t)
	_, cwd := dotDotLinkFixture(t)
	for _, row := range []struct {
		name, command string
		blocked       bool
	}{
		{"protected link behind dot-dot", "cat jump/../status", true},
		{"clean twin", "cat status", false},
	} {
		t.Run(row.name, func(t *testing.T) {
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
				opts.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"exec_command","cwd":%q,"tool_input":{"cmd":%q}}`, cwd, row.command))
			})
			if got := blocked(result); got != row.blocked {
				t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", got, row.blocked, result.code, result.stdout, result.stderr)
			}
		})
	}
}

// GAP-0641 / GAP-0679 review 9: the same protected link reached with a
// leading dot-dot step from a working directory that is itself a link.
func TestGAP0641LeadingParentFromLinkedWorkingDirectory(t *testing.T) {
	home, project := dotDotLinkFixture(t)
	cwd := filepath.Join(project, "jump")
	t.Chdir(cwd)
	for _, row := range []struct {
		command  string
		ordinary bool
	}{
		{"cat ../status", false},
		{"cat ./../status", false},
		{"cat " + cwd + "/../status", false},
		{"cat status", true},
	} {
		if got := ordinaryNoAnswerPayloadInHome(gap0641Payload(cwd, row.command), home); got != row.ordinary {
			t.Errorf("payload ordinary %q=%v, want %v", row.command, got, row.ordinary)
		}
	}
}

func TestGAP0641LeadingParentStaysClosedAtTheOSSDeadline(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	addr := hungGateway(t)
	_, project := dotDotLinkFixture(t)
	cwd := filepath.Join(project, "jump")
	t.Chdir(cwd)
	for _, row := range []struct {
		command string
		blocked bool
	}{
		{"cat ../status", true},
		{"cat status", false},
	} {
		t.Run(row.command, func(t *testing.T) {
			result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
				opts.FailMode = "open"
				opts.OutageFailModeNow = func() string { return "open" }
				opts.Stdin = strings.NewReader(string(gap0641Payload(cwd, row.command)))
			})
			if got := nativeOutageBlocked(result); got != row.blocked {
				t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", got, row.blocked, result.code, result.stdout, result.stderr)
			}
		})
	}
}

func TestGAP0679LeadingParentStaysClosedInTheManagedAdminOpenOutage(t *testing.T) {
	shortAnswerBudget(t, 550*time.Millisecond)
	fastRestartRetries(t)
	_, project := dotDotLinkFixture(t)
	cwd := filepath.Join(project, "jump")
	t.Chdir(cwd)
	for _, row := range []struct {
		command string
		blocked bool
	}{
		{"cat ../status", true},
		{"cat status", false},
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
				opts.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"exec_command","cwd":%q,"tool_input":{"cmd":%q}}`, cwd, row.command))
			})
			if got := blocked(result); got != row.blocked {
				t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", got, row.blocked, result.code, result.stdout, result.stderr)
			}
		})
	}
}
