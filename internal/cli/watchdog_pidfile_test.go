// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// Regression tests for the S3.HIGH_BUG fix
// "Stale watchdog PID file can stop an unrelated process".
//
// The watchdog now writes a JSON fingerprint (pid + executable + start
// time) and protects the file with an exclusive flock. start refuses
// to spawn when the lock is held; stop / status verify the fingerprint
// before signalling so a stale PID that has been recycled by an
// unrelated process is detected and the file removed instead of
// SIGTERM'ing whatever now owns that PID.

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestWatchdogPIDFile_RoundTripJSON(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "watchdog.pid")
	want := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    "/some/path/defenseclaw-gateway",
		StartTime:     time.Now().Unix(),
		StartIdentity: "opaque-kernel-identity",
	}

	f, err := acquireWatchdogPIDFile(pidPath, want)
	if err != nil {
		t.Fatalf("acquireWatchdogPIDFile: %v", err)
	}
	defer f.Close()

	got, err := readWatchdogPIDInfo(pidPath)
	if err != nil {
		t.Fatalf("readWatchdogPIDInfo: %v", err)
	}
	if got.PID != want.PID || got.Executable != want.Executable || got.StartTime != want.StartTime ||
		got.StartIdentity != want.StartIdentity {
		t.Fatalf("round-trip mismatch: got=%+v want=%+v", got, want)
	}

	// File MUST be 0600 -- it embeds the watchdog identity, not a
	// secret per se, but world-readable would let any local user
	// derive the daemon's exe path.
	st, err := os.Stat(pidPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("pid file perms = %v, want 0600", st.Mode().Perm())
	}
}

func TestWatchdogPIDFile_LegacyPlainTextPID(t *testing.T) {
	// Old watchdog binaries wrote a bare integer PID. The new reader
	// MUST still accept those during the roll-out window so an in-place
	// upgrade doesn't lose the ability to stop a still-running legacy
	// watchdog.
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "watchdog.pid")
	if err := os.WriteFile(pidPath, []byte("12345\n"), 0o600); err != nil {
		t.Fatalf("seed legacy pid: %v", err)
	}

	info, err := readWatchdogPIDInfo(pidPath)
	if err != nil {
		t.Fatalf("readWatchdogPIDInfo legacy: %v", err)
	}
	if info.PID != 12345 {
		t.Errorf("PID = %d, want 12345", info.PID)
	}
	if info.Executable != "" || info.StartTime != 0 {
		t.Errorf("legacy info should have empty fingerprint; got %+v", info)
	}
}

func TestWatchdogPIDFile_RejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "watchdog.pid")
	if err := os.WriteFile(pidPath, []byte("not a pid"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := readWatchdogPIDInfo(pidPath); err == nil {
		t.Fatal("readWatchdogPIDInfo should reject non-integer non-JSON file")
	}
}

func TestAcquireWatchdogPIDFile_RejectsConcurrentAcquire(t *testing.T) {
	// hardening: the flock prevents a second watchdog from
	// taking ownership of the same data dir. The first acquirer holds
	// the lock for the lifetime of its process; the second acquirer
	// MUST fail immediately rather than overwrite the fingerprint.
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "watchdog.pid")

	first, err := acquireWatchdogPIDFile(pidPath, watchdogPIDInfo{PID: os.Getpid()})
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer first.Close()

	if _, err := acquireWatchdogPIDFile(pidPath, watchdogPIDInfo{PID: os.Getpid()}); err == nil {
		t.Fatal("second acquire should fail while first still holds the flock")
	}
}

func TestAcquireWatchdogPIDFile_ReleasedOnClose(t *testing.T) {
	// Closing the file releases the kernel-level flock, so the next
	// watchdog start (e.g. after a graceful shutdown) MUST be able to
	// re-acquire the same path.
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "watchdog.pid")

	first, err := acquireWatchdogPIDFile(pidPath, watchdogPIDInfo{PID: os.Getpid()})
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	_ = first.Close()

	second, err := acquireWatchdogPIDFile(pidPath, watchdogPIDInfo{PID: os.Getpid()})
	if err != nil {
		t.Fatalf("second acquire after close: %v", err)
	}
	_ = second.Close()
}

func TestWatchdogIsLocked(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "watchdog.pid")

	// File missing => not locked.
	if locked, _ := watchdogIsLocked(pidPath); locked {
		t.Fatal("expected !locked for missing file")
	}

	// Hold the lock from one fd; watchdogIsLocked must report locked.
	holder, err := os.OpenFile(pidPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("flock holder: %v", err)
	}
	defer syscall.Flock(int(holder.Fd()), syscall.LOCK_UN) //nolint:errcheck // best-effort cleanup

	// Seed a fingerprint so the helper can return it.
	enc := json.NewEncoder(holder)
	if err := enc.Encode(watchdogPIDInfo{PID: 99999, Executable: "/probe"}); err != nil {
		t.Fatalf("seed fingerprint: %v", err)
	}
	if err := holder.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	locked, info := watchdogIsLocked(pidPath)
	if !locked {
		t.Fatal("expected locked while holder still owns the flock")
	}
	if info.PID != 99999 {
		t.Errorf("info.PID = %d, want 99999 from holder fingerprint", info.PID)
	}
}

func TestVerifyWatchdogProcess_StaleFingerprintRejected(t *testing.T) {
	// On Linux, /proc/self/exe resolves to the test binary path.
	// Recording a different "executable" for our own PID must make
	// verifyWatchdogProcess return false -- this is the exact
	// scenario the finding warned about (PID reuse where the
	// recorded fingerprint no longer matches the live process).
	if _, err := os.Readlink("/proc/self/exe"); err != nil {
		t.Skipf("/proc/self/exe not readable on this platform: %v", err)
	}

	bogus := watchdogPIDInfo{
		PID:        os.Getpid(),
		Executable: "/nonexistent/fake-defenseclaw",
	}
	if verifyWatchdogProcess(bogus) {
		t.Fatal("verifyWatchdogProcess accepted mismatched executable -- stale-PID protection is broken")
	}
}

func TestVerifyWatchdogProcess_LiveProcessAccepted(t *testing.T) {
	// The test process IS alive at its own PID; a fingerprint with
	// no Executable falls back to the signal-0 check and must accept.
	if !verifyWatchdogProcess(watchdogPIDInfo{PID: os.Getpid()}) {
		t.Fatal("verifyWatchdogProcess rejected the live test process")
	}
}

func TestVerifyWatchdogProcess_UnverifiableStartIdentityRejected(t *testing.T) {
	info := watchdogPIDInfo{PID: os.Getpid(), StartIdentity: "stale-process-identity"}
	if verifyWatchdogProcess(info) {
		t.Fatal("verifyWatchdogProcess accepted an unverifiable start identity")
	}
}

func TestVerifyWatchdogProcess_DeadPIDRejected(t *testing.T) {
	// PID 0 is never a valid process; the signal-0 path must reject.
	if verifyWatchdogProcess(watchdogPIDInfo{PID: 0}) {
		t.Fatal("verifyWatchdogProcess accepted PID 0")
	}
}
