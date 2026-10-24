// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// Package sharedfiletest is the one concurrency harness for the machine
// policy files DefenseClaw shares with administrators and agents: Cursor's
// C:\ProgramData\Cursor\hooks.json and Codex's requirements.toml. An Admin
// changes the file the way an administrator does, without the DefenseClaw
// lock: it saves new content in place, changes the access list, or changes
// an attribute. A Watch reads the file from another goroutine for the whole
// of a DefenseClaw setup, repair, rollback or restore and reports the first
// moment the file breaks an invariant (for example, the machine policy
// without its hook). Both connector and enterprise hook tests use it.
package sharedfiletest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Change is one kind of administrator change.
type Change string

const (
	// Content is a save of new bytes, in place, as an editor saves.
	Content Change = "content"
	// AccessList adds a read entry for Backup Operators and keeps the bytes.
	AccessList Change = "access list"
	// Attributes sets the not-content-indexed attribute and keeps the bytes.
	Attributes Change = "attributes"
)

// Changes is every kind of administrator change.
var Changes = []Change{Content, AccessList, Attributes}

// Admin is an administrator who edits Path while DefenseClaw works on it.
type Admin struct {
	Path string
	// Edit returns data, the file as it is now (nil when it is absent), with
	// the administrator's own content added.
	Edit func(data []byte) []byte
	// Kept reports whether data still holds that content.
	Kept func(data []byte) bool
}

// Apply makes change to the file now. A Content change of an absent file
// creates it; the other changes need the file.
func (admin Admin) Apply(t testing.TB, change Change) {
	t.Helper()
	switch change {
	case Content:
		data, _, err := ReadShared(admin.Path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(admin.Path, admin.Edit(data), 0o600); err != nil {
			t.Fatal(err)
		}
	case AccessList:
		GrantBackupOperatorsRead(t, admin.Path)
	case Attributes:
		name := utf16(t, admin.Path)
		attributes, err := windows.GetFileAttributes(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetFileAttributes(name, attributes|windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown administrator change %q", change)
	}
}

// RequireKept fails t unless the file still carries change.
func (admin Admin) RequireKept(t testing.TB, change Change) {
	t.Helper()
	data, exists, err := ReadShared(admin.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatalf("%s is gone; the administrator's %s change was lost", admin.Path, change)
	}
	switch change {
	case Content:
		if !admin.Kept(data) {
			t.Fatalf("%s lost the administrator's save:\n%s", admin.Path, data)
		}
	case AccessList:
		RequireBackupOperatorsRead(t, admin.Path)
	case Attributes:
		attributes, err := windows.GetFileAttributes(utf16(t, admin.Path))
		if err != nil {
			t.Fatal(err)
		}
		if attributes&windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED == 0 {
			t.Fatalf("%s lost the administrator's attribute change: %#x", admin.Path, attributes)
		}
	}
}

// GrantBackupOperatorsRead adds a read entry for Backup Operators to the
// access list of path, as an administrator's icacls /grant does.
func GrantBackupOperatorsRead(t testing.TB, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	operators, err := windows.CreateWellKnownSid(windows.WinBuiltinBackupOperatorsSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(operators),
		},
	}}, dacl)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

// RequireBackupOperatorsRead fails t unless the access list of path still
// has the entry GrantBackupOperatorsRead adds.
func RequireBackupOperatorsRead(t testing.TB, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(descriptor.String(), ";;;BO)") {
		t.Fatalf("%s lost the administrator's access-list entry: %s", path, descriptor)
	}
}

// ReadShared reads path as Cursor and Codex read their policy: sharing
// reads, writes and deletion, so it never holds up a writer. A missing file
// is reported as absent.
func ReadShared(path string) ([]byte, bool, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	data, err := io.ReadAll(file)
	return data, true, err
}

// Watch runs a check over and over from another goroutine and keeps the
// first failure.
type Watch struct {
	stop  chan struct{}
	done  sync.WaitGroup
	mu    sync.Mutex
	err   error
	polls int
}

// StartWatch starts checking. check is called about every 50 microseconds
// until Stop; a check that cannot read a file because a writer holds it
// should report nil.
func StartWatch(check func() error) *Watch {
	watch := &Watch{stop: make(chan struct{})}
	watch.done.Add(1)
	go func() {
		defer watch.done.Done()
		for {
			select {
			case <-watch.stop:
				return
			default:
			}
			err := check()
			watch.mu.Lock()
			watch.polls++
			if err != nil && watch.err == nil {
				watch.err = fmt.Errorf("poll %d: %w", watch.polls, err)
			}
			watch.mu.Unlock()
			time.Sleep(50 * time.Microsecond)
		}
	}()
	return watch
}

// Stop stops the watch and returns the first failure.
func (watch *Watch) Stop() error {
	close(watch.stop)
	watch.done.Wait()
	watch.mu.Lock()
	defer watch.mu.Unlock()
	return watch.err
}

// Busy reports a read refused because another handle holds the file.
func Busy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

func utf16(t testing.TB, path string) *uint16 {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	return name
}
