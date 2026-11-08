// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func openCodeRecordWarnings(t *testing.T, env *Env) map[string]string {
	t.Helper()
	r := &enterprisestatus.Result{}
	env.warnOpenCodePortsRecord(r)
	codes := map[string]string{}
	for _, warning := range r.Warnings {
		codes[warning.Code] = warning.Message
	}
	return codes
}

// gas-ux-r1 GAP-0053, REVIEW-gx053-4/5 MF2: status and verify warn when the
// guardian's OpenCode ports record cannot be read; a non-root status that
// cannot open the guardian folder says it could not check, where OpenCode is
// on the machine policy.
func TestStatusWarnsOnAnUnreadableOpenCodePortsRecord(t *testing.T) {
	root := t.TempDir()
	env := &Env{GOOS: "linux", Root: root, Layout: mustLayout(t, "linux")}
	record := env.P(filepath.Join(env.Layout.GuardianAuthDir, enterprisehooks.UnixOpenCodeServicePortsFileName))
	if err := os.MkdirAll(filepath.Dir(record), 0o750); err != nil {
		t.Fatal(err)
	}
	previous := openCodePortsRecordGeteuid
	t.Cleanup(func() { openCodePortsRecordGeteuid = previous })
	openCodePortsRecordGeteuid = func() int { return 0 }

	if codes := openCodeRecordWarnings(t, env); len(codes) != 0 {
		t.Fatalf("no record: %v", codes)
	}
	if err := os.WriteFile(record, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if codes := openCodeRecordWarnings(t, env); codes["opencode_port_record_unreadable"] == "" {
		t.Fatalf("a corrupt record is not reported: %v", codes)
	}

	if os.Geteuid() == 0 {
		t.Skip("the non-root case needs a non-root test runner")
	}
	openCodePortsRecordGeteuid = func() int { return 1000 }
	folder := filepath.Dir(record)
	if err := os.Chmod(folder, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(folder, 0o750) })
	if codes := openCodeRecordWarnings(t, env); len(codes) != 0 {
		t.Fatalf("without OpenCode on the machine policy nothing is said: %v", codes)
	}
	plugin := env.P(filepath.Join(openCodePluginDir(env.Layout), "index.js"))
	if err := os.MkdirAll(filepath.Dir(plugin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plugin, []byte("//"), 0o644); err != nil {
		t.Fatal(err)
	}
	codes := openCodeRecordWarnings(t, env)
	if msg := codes["opencode_port_record_unchecked"]; msg == "" || !filepath.IsAbs(env.Layout.GuardianAuthDir) {
		t.Fatalf("a non-root status says nothing: %v", codes)
	}
}

// Status, verify (and doctor, from status) name each contested port, its
// claimants and the exact clear command.
func TestStatusNamesContestedOpenCodePorts(t *testing.T) {
	root := t.TempDir()
	env := &Env{GOOS: "linux", Root: root, Layout: mustLayout(t, "linux")}
	record := env.P(filepath.Join(env.Layout.GuardianAuthDir, enterprisehooks.UnixOpenCodeServicePortsFileName))
	if err := os.MkdirAll(filepath.Dir(record), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := loadOpenCodePortsRecord
	t.Cleanup(func() { loadOpenCodePortsRecord = previous })
	loadOpenCodePortsRecord = func(string) (enterprisehooks.UnixOpenCodeServicePortsState, error) {
		return enterprisehooks.UnixOpenCodeServicePortsState{Exists: true,
			Contested: []enterprisehooks.UnixOpenCodeContestedPort{{Port: 25003, UIDs: []int{1001, 1002}}}}, nil
	}
	msg := openCodeRecordWarnings(t, env)["opencode_port_contested"]
	for _, want := range []string{"port 25003", "uids 1001, 1002", "sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux opencode-port-clear 25003 --yes"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the contested line %q lacks %q", msg, want)
		}
	}
}

func openCodeUnknownEnv(t *testing.T, unknown []enterprisehooks.UnixOpenCodeServicePortUnknown, runner *fakeRunner, local []int) *Env {
	t.Helper()
	root := t.TempDir()
	env := &Env{GOOS: "linux", Root: root, Layout: mustLayout(t, "linux"), Runner: runner}
	record := env.P(filepath.Join(env.Layout.GuardianAuthDir, enterprisehooks.UnixOpenCodeServicePortsFileName))
	if err := os.MkdirAll(filepath.Dir(record), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousLoad, previousLocal, previousDirectory := loadOpenCodePortsRecord, openCodePortLocalUIDs, openCodePortDirectoryShowsUnused
	t.Cleanup(func() {
		loadOpenCodePortsRecord, openCodePortLocalUIDs, openCodePortDirectoryShowsUnused = previousLoad, previousLocal, previousDirectory
	})
	loadOpenCodePortsRecord = func(string) (enterprisehooks.UnixOpenCodeServicePortsState, error) {
		return enterprisehooks.UnixOpenCodeServicePortsState{Exists: true, Unknown: unknown}, nil
	}
	openCodePortLocalUIDs = func(context.Context) ([]int, error) { return local, nil }
	openCodePortDirectoryShowsUnused = func(context.Context, int) error { return nil }
	return env
}

func openCodeUnknownWarnings(t *testing.T, env *Env) (messages []string, errorsFound int) {
	t.Helper()
	r := &enterprisestatus.Result{}
	env.warnOpenCodePortsRecord(r)
	for _, warning := range r.Warnings {
		if warning.Code == "opencode_port_account_unknown" {
			messages = append(messages, warning.Message)
		}
	}
	return messages, len(r.Errors)
}

func noAccountReply(uid string) map[string]fakeReply {
	return map[string]fakeReply{"getent passwd " + uid: {result: CommandResult{ExitCode: 2}, err: errors.New("exit 2")}}
}

const staleClearCommand = "sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux opencode-port-unknown-clear 1234 --yes"

// GAP-0904: a port record entry whose uid no account holds is never hidden.
// Status and verify say what is known and name the one command that removes
// it; it is a warning, never an error.
func TestStatusReportsAnOpenCodePortRecordWithNoAccount(t *testing.T) {
	unknown := []enterprisehooks.UnixOpenCodeServicePortUnknown{{UID: 1234, User: "gone", Reason: "home does not answer", Path: "/home/gone/.config/opencode/service.json"}}
	env := openCodeUnknownEnv(t, unknown, &fakeRunner{replies: noAccountReply("1234")}, []int{0})
	messages, errs := openCodeUnknownWarnings(t, env)
	if len(messages) != 1 || errs != 0 {
		t.Fatalf("want one warning and no error, got %q, %d errors", messages, errs)
	}
	for _, want := range []string{"OpenCode port record for UID 1234 (no account found)", staleClearCommand} {
		if !strings.Contains(messages[0], want) {
			t.Fatalf("the warning %q lacks %q", messages[0], want)
		}
	}
}

// A name reused by another account with a different uid does not make the
// old uid look alive: the warning shows until the entry is cleaned up.
func TestStatusKeepsTheOpenCodePortRecordWarningWhenTheNameIsReusedByAnotherUID(t *testing.T) {
	unknown := []enterprisehooks.UnixOpenCodeServicePortUnknown{{UID: 1234, User: "alice", Reason: "home does not answer", Path: "/home/alice/.config/opencode/service.json"}}
	runner := &fakeRunner{replies: map[string]fakeReply{
		"getent passwd 1234":  {result: CommandResult{ExitCode: 2}, err: errors.New("exit 2")},
		"getent passwd alice": {result: CommandResult{Stdout: []byte("alice:x:5678:5678::/home/alice:/bin/bash\n")}},
	}}
	env := openCodeUnknownEnv(t, unknown, runner, []int{5678})
	messages, _ := openCodeUnknownWarnings(t, env)
	if len(messages) != 1 || !strings.Contains(messages[0], "(no account found)") || !strings.Contains(messages[0], staleClearCommand) {
		t.Fatalf("the warning of the old uid went away: %q", messages)
	}
}

// Benign twins: an account that is there (NSS, or only in an altfiles or
// systemd-userdb database while NSS misses) is not called a record with no
// account; the lookup that does not answer keeps the account wording too. The
// warning still shows, with the account, the file and its own clear step.
func TestStatusDoesNotCallALiveOrUnconfirmedOpenCodePortAccountGone(t *testing.T) {
	unknown := []enterprisehooks.UnixOpenCodeServicePortUnknown{{UID: 1234, User: "kim", Reason: "home does not answer", Path: "/home/kim/.config/opencode/service.json", Fix: "sudo -u kim opencode service set port 25001"}}
	cases := map[string]struct {
		replies map[string]fakeReply
		local   []int
		mutate  func()
	}{
		"nss answers":   {replies: map[string]fakeReply{"getent passwd 1234": {result: CommandResult{Stdout: []byte("kim:x:1234:1234::/home/kim:/bin/bash\n")}}}},
		"altfiles only": {replies: noAccountReply("1234"), local: []int{1234}},
		"lookup fails":  {replies: map[string]fakeReply{"getent passwd 1234": {result: CommandResult{ExitCode: 1}, err: errors.New("exit 1")}}},
		// getent exit 2 is also what a directory that cannot be reached
		// gives: without proof it answers, the account is not called gone.
		"directory cannot answer": {replies: noAccountReply("1234"), mutate: func() {
			openCodePortDirectoryShowsUnused = func(context.Context, int) error { return errors.New("SSSD is offline") }
		}},
		"local database unreadable": {replies: noAccountReply("1234"), mutate: func() {
			openCodePortLocalUIDs = func(context.Context) ([]int, error) { return nil, errors.New("altfiles unreadable") }
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := openCodeUnknownEnv(t, unknown, &fakeRunner{replies: tc.replies}, tc.local)
			if tc.mutate != nil {
				tc.mutate()
			}
			messages, errs := openCodeUnknownWarnings(t, env)
			if len(messages) != 1 || errs != 0 {
				t.Fatalf("want one warning and no error, got %q, %d errors", messages, errs)
			}
			if strings.Contains(messages[0], "no account found") || strings.Contains(messages[0], "unknown-clear") {
				t.Fatalf("an account that is there was called gone: %q", messages[0])
			}
			if !strings.Contains(messages[0], "kim (uid 1234)") || !strings.Contains(messages[0], "sudo -u kim opencode service set port 25001") {
				t.Fatalf("the account wording is missing: %q", messages[0])
			}
		})
	}
}

func TestUIDHasAccountTreatsAMissingAnswerAsNoProof(t *testing.T) {
	stub := func(t *testing.T, local []int, localErr, directoryErr error) {
		t.Helper()
		previousLocal, previousDirectory := openCodePortLocalUIDs, openCodePortDirectoryShowsUnused
		t.Cleanup(func() { openCodePortLocalUIDs, openCodePortDirectoryShowsUnused = previousLocal, previousDirectory })
		openCodePortLocalUIDs = func(context.Context) ([]int, error) { return local, localErr }
		openCodePortDirectoryShowsUnused = func(context.Context, int) error { return directoryErr }
	}
	t.Run("macOS search policy lists the uid", func(t *testing.T) {
		stub(t, nil, nil, nil)
		runner := &fakeRunner{replies: map[string]fakeReply{"dscl /Search -search /Users UniqueID 700": {result: CommandResult{Stdout: []byte("dirkim\tUniqueID = (700)\n")}}}}
		env := &Env{GOOS: "darwin", Runner: runner}
		if has, err := env.UIDHasAccount(context.Background(), 700); err != nil || !has {
			t.Fatalf("a directory account was not found: %v %v", has, err)
		}
		if has, err := env.UIDHasAccount(context.Background(), 701); err != nil || has {
			t.Fatalf("an empty dscl answer with the directory answering is no account: %v %v", has, err)
		}
	})
	t.Run("macOS with a directory node offline is no proof", func(t *testing.T) {
		stub(t, nil, nil, errors.New("Open Directory node /Active Directory/CORP is offline"))
		env := &Env{GOOS: "darwin", Runner: &fakeRunner{}}
		if has, err := env.UIDHasAccount(context.Background(), 701); err == nil || has {
			t.Fatalf("an empty dscl answer while a directory is offline was taken as no account: %v %v", has, err)
		}
	})
	t.Run("Linux exit 2 while the directory cannot answer is no proof", func(t *testing.T) {
		stub(t, nil, nil, errors.New("SSSD is offline"))
		env := &Env{GOOS: "linux", Runner: &fakeRunner{replies: noAccountReply("1234")}}
		if has, err := env.UIDHasAccount(context.Background(), 1234); err == nil || has {
			t.Fatalf("got %v %v, want an error", has, err)
		}
	})
	t.Run("a uid in a local database NSS misses is an account", func(t *testing.T) {
		stub(t, []int{5, 1234}, nil, nil)
		env := &Env{GOOS: "linux", Runner: &fakeRunner{replies: noAccountReply("1234")}}
		if has, err := env.UIDHasAccount(context.Background(), 1234); err != nil || !has {
			t.Fatalf("got %v %v, want an account", has, err)
		}
	})
	t.Run("an unreadable local database is no proof", func(t *testing.T) {
		stub(t, nil, errors.New("unreadable"), nil)
		env := &Env{GOOS: "linux", Runner: &fakeRunner{replies: noAccountReply("1234")}}
		if has, err := env.UIDHasAccount(context.Background(), 1234); err == nil || has {
			t.Fatalf("got %v %v, want an error", has, err)
		}
	})
	t.Run("every source answering with no uid is no account", func(t *testing.T) {
		stub(t, []int{0, 1000}, nil, nil)
		env := &Env{GOOS: "linux", Runner: &fakeRunner{replies: noAccountReply("1234")}}
		if has, err := env.UIDHasAccount(context.Background(), 1234); err != nil || has {
			t.Fatalf("got %v %v, want a clean miss", has, err)
		}
	})
	t.Run("no runner", func(t *testing.T) {
		if _, err := (&Env{GOOS: "linux"}).UIDHasAccount(context.Background(), 1); err == nil {
			t.Fatal("want an error")
		}
	})
}
