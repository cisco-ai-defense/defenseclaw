// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package testenv

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Windows process start time (image scan, cold runtime start) has no useful
// upper bound on a loaded runner, so these helpers order waits on events
// instead of wall-clock deadlines. The only bound is go test -timeout.

// WaitForFile returns the contents of path once a helper process has
// published it (exists and is non-empty). If done delivers first, the helper
// exited before publishing and WaitForFile returns an error carrying its exit
// result, so a crashed helper fails at once instead of looking like a slow
// start.
func WaitForFile(path string, done <-chan error) ([]byte, error) {
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	for {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return data, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) &&
			!errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, err
		}
		select {
		case exitErr := <-done:
			return nil, fmt.Errorf("helper exited before publishing %s: %v", path, exitErr)
		case <-poll.C:
		}
	}
}

// PublishFile writes data to path by renaming a complete temporary file into
// place, so a WaitForFile reader never sees a partial write.
func PublishFile(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

// ProcessExit returns a channel that receives the exit code of process pid
// once it exits. The process must still exist when ProcessExit is called.
func ProcessExit(t testing.TB, pid int) <-chan uint32 {
	t.Helper()
	handle, err := windows.OpenProcess(
		windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		t.Fatalf("open process %d: %v", pid, err)
	}
	exited := make(chan uint32, 1)
	go func() {
		defer windows.CloseHandle(handle)
		if _, err := windows.WaitForSingleObject(handle, windows.INFINITE); err != nil {
			panic(fmt.Sprintf("wait for process %d: %v", pid, err))
		}
		var code uint32
		if err := windows.GetExitCodeProcess(handle, &code); err != nil {
			panic(fmt.Sprintf("exit code of process %d: %v", pid, err))
		}
		exited <- code
	}()
	return exited
}

var releaseSequence atomic.Uint64

// Release is a named event that holds a helper process at a known point
// until the test signals it.
type Release struct {
	name  string
	event windows.Handle
}

// NewRelease creates an unsignalled release event owned by the test process.
func NewRelease(t testing.TB) *Release {
	t.Helper()
	name := fmt.Sprintf(`Local\DefenseClaw-test-release-%d-%d`, os.Getpid(), releaseSequence.Add(1))
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	event, err := windows.CreateEvent(nil, 1, 0, pointer)
	if err != nil {
		t.Fatalf("create release event: %v", err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(event) })
	return &Release{name: name, event: event}
}

// Token identifies the event and its owning test process for AwaitRelease.
func (release *Release) Token() string {
	return release.name + "|" + strconv.Itoa(os.Getpid())
}

// Signal lets every helper blocked in AwaitRelease proceed.
func (release *Release) Signal(t testing.TB) {
	t.Helper()
	if err := windows.SetEvent(release.event); err != nil {
		t.Fatalf("signal release event: %v", err)
	}
}

// AwaitRelease blocks a helper process until the test signals token. It
// returns false when the owning test process exits first, so an abandoned
// helper never outlives its test.
func AwaitRelease(token string) (bool, error) {
	name, ownerText, ok := strings.Cut(token, "|")
	if !ok {
		return false, fmt.Errorf("malformed release token %q", token)
	}
	ownerPID, err := strconv.Atoi(ownerText)
	if err != nil {
		return false, fmt.Errorf("malformed release owner %q: %w", ownerText, err)
	}
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	event, err := windows.OpenEvent(windows.SYNCHRONIZE, false, pointer)
	if err != nil {
		return false, fmt.Errorf("open release event: %w", err)
	}
	defer windows.CloseHandle(event)
	owner, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(ownerPID))
	if err != nil {
		return false, fmt.Errorf("open release owner %d: %w", ownerPID, err)
	}
	defer windows.CloseHandle(owner)
	result, err := windows.WaitForMultipleObjects([]windows.Handle{event, owner}, false, windows.INFINITE)
	if err != nil {
		return false, fmt.Errorf("wait for release: %w", err)
	}
	return result == windows.WAIT_OBJECT_0, nil
}
