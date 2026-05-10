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

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestWriteAndReadPIDInfo(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	now := time.Now().Unix()
	err := d.writePIDInfo(12345, "/usr/bin/defenseclaw-gateway")
	if err != nil {
		t.Fatalf("writePIDInfo: %v", err)
	}

	info, err := d.readPIDInfo()
	if err != nil {
		t.Fatalf("readPIDInfo: %v", err)
	}
	if info.PID != 12345 {
		t.Errorf("PID = %d, want 12345", info.PID)
	}
	if info.Executable != "/usr/bin/defenseclaw-gateway" {
		t.Errorf("Executable = %q, want /usr/bin/defenseclaw-gateway", info.Executable)
	}
	if info.StartTime < now-1 || info.StartTime > now+1 {
		t.Errorf("StartTime = %d, want ~%d", info.StartTime, now)
	}
}

func TestPIDFileIsJSON(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)
	_ = d.writePIDInfo(42, "/tmp/test-bin")

	data, err := os.ReadFile(d.pidFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("PID file is not valid JSON: %v\ncontent: %s", err, data)
	}
	if raw["pid"] == nil {
		t.Error("JSON should contain 'pid' field")
	}
	if raw["executable"] == nil {
		t.Error("JSON should contain 'executable' field")
	}
	if raw["start_time"] == nil {
		t.Error("JSON should contain 'start_time' field")
	}
}

func TestReadPIDInfoParsesLegacyPlainText(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	os.WriteFile(d.pidFile, []byte("12345\n"), 0644)

	info, err := d.readPIDInfo()
	if err != nil {
		t.Fatalf("readPIDInfo should parse legacy plain-text PID: %v", err)
	}
	if info.PID != 12345 {
		t.Errorf("PID = %d, want 12345", info.PID)
	}
	if info.Executable != "" {
		t.Errorf("Executable should be empty for legacy format, got %q", info.Executable)
	}
	if info.StartTime != 0 {
		t.Errorf("StartTime should be 0 for legacy format, got %d", info.StartTime)
	}
}

func TestReadPIDInfoRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	os.WriteFile(d.pidFile, []byte("not-a-pid-or-json\n"), 0644)

	_, err := d.readPIDInfo()
	if err == nil {
		t.Fatal("readPIDInfo should reject files that are neither JSON nor a valid PID")
	}
}

func TestReadPIDInfoRejectsNegativePID(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	os.WriteFile(d.pidFile, []byte("-1\n"), 0644)

	_, err := d.readPIDInfo()
	if err == nil {
		t.Fatal("readPIDInfo should reject negative PIDs")
	}
}

func TestReadPIDInfoParsesLegacyNoNewline(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	os.WriteFile(d.pidFile, []byte("54321"), 0644)

	info, err := d.readPIDInfo()
	if err != nil {
		t.Fatalf("readPIDInfo should parse plain PID without trailing newline: %v", err)
	}
	if info.PID != 54321 {
		t.Errorf("PID = %d, want 54321", info.PID)
	}
}

func TestReadPIDInfoMissingFile(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	_, err := d.readPIDInfo()
	if err == nil {
		t.Fatal("readPIDInfo should error on missing file")
	}
}

func TestIsRunningFalseWithStalePID(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	// PID that almost certainly doesn't exist
	info := pidInfo{PID: 999999999, Executable: "/nonexistent", StartTime: time.Now().Unix()}
	data, _ := json.Marshal(info)
	os.WriteFile(d.pidFile, data, 0644)

	running, pid := d.IsRunning()
	if running {
		t.Errorf("IsRunning should be false for non-existent PID, got pid=%d", pid)
	}

	// PID file should be cleaned up
	if _, err := os.Stat(d.pidFile); !os.IsNotExist(err) {
		t.Error("stale PID file should be removed")
	}
}

func TestNewDaemonPaths(t *testing.T) {
	dir := "/tmp/test-dclaw"
	d := New(dir)
	if d.PIDFile() != filepath.Join(dir, PIDFileName) {
		t.Errorf("PIDFile = %q, want %q", d.PIDFile(), filepath.Join(dir, PIDFileName))
	}
	if d.LogFile() != filepath.Join(dir, LogFileName) {
		t.Errorf("LogFile = %q, want %q", d.LogFile(), filepath.Join(dir, LogFileName))
	}
}

func TestIsDaemonChild(t *testing.T) {
	t.Setenv(EnvDaemon, "1")
	if !IsDaemonChild() {
		t.Error("IsDaemonChild should be true when DEFENSECLAW_DAEMON=1")
	}

	t.Setenv(EnvDaemon, "")
	if IsDaemonChild() {
		t.Error("IsDaemonChild should be false when DEFENSECLAW_DAEMON is empty")
	}
}

func TestVerifyProcessCurrentPID(t *testing.T) {
	d := New(t.TempDir())
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot determine executable: %v", err)
	}

	info := pidInfo{
		PID:        os.Getpid(),
		Executable: exe,
		StartTime:  time.Now().Unix(),
	}

	if !d.verifyProcess(info) {
		t.Error("verifyProcess should return true for current process")
	}
}

func TestVerifyProcessWrongExecutable(t *testing.T) {
	d := New(t.TempDir())

	info := pidInfo{
		PID:        os.Getpid(),
		Executable: "/nonexistent/binary/path",
		StartTime:  time.Now().Unix(),
	}

	switch runtime.GOOS {
	case "linux", "darwin":
		if runtime.GOOS == "darwin" {
			if _, err := processExecutableDarwin(os.Getpid()); err != nil {
				t.Skipf("darwin process inspection unavailable in this environment: %v", err)
			}
		}
		if d.verifyProcess(info) {
			t.Error("verifyProcess should return false for wrong executable")
		}
	default:
		t.Skipf("test not applicable on %s", runtime.GOOS)
	}
}

func TestVerifyProcessDarwinUsesPS(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only test")
	}

	d := New(t.TempDir())
	exe, _ := os.Executable()
	if _, err := processExecutableDarwin(os.Getpid()); err != nil {
		t.Skipf("darwin process inspection unavailable in this environment: %v", err)
	}

	info := pidInfo{
		PID:        os.Getpid(),
		Executable: exe,
		StartTime:  time.Now().Unix(),
	}

	if !d.verifyProcessDarwin(info) {
		t.Error("verifyProcessDarwin should return true for current process")
	}
}

func TestVerifyProcessDarwinRejectsBadPID(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only test")
	}

	d := New(t.TempDir())
	info := pidInfo{
		PID:        999999999,
		Executable: "/usr/bin/defenseclaw",
		StartTime:  time.Now().Unix(),
	}

	if d.verifyProcessDarwin(info) {
		t.Error("verifyProcessDarwin should return false for non-existent PID")
	}
}

func TestWritePIDInfoUsesRestrictedPerms(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)
	_ = d.writePIDInfo(99999, "/usr/bin/test")

	info, err := os.Stat(d.pidFile)
	if err != nil {
		t.Fatalf("stat pidFile: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("pidFile perms = %04o, want 0600", mode)
	}
}

func TestDataDirAndLogFilePerms(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "nested", "data")
	d := New(dataDir)

	if err := os.MkdirAll(d.dataDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	info, err := os.Stat(d.dataDir)
	if err != nil {
		t.Fatalf("stat dataDir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("dataDir perms = %04o, want 0700", perm)
	}

	logPath := d.LogFile()
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("create logFile: %v", err)
	}
	f.Close()

	logInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat logFile: %v", err)
	}
	if perm := logInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("logFile perms = %04o, want 0600", perm)
	}
}

func TestStopReturnsErrNotRunningOnMissingPID(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	err := d.Stop(time.Second)
	if err != ErrNotRunning {
		t.Errorf("Stop with no PID file: got %v, want ErrNotRunning", err)
	}
}

// TestStripTokenArgs is the regression for DeepSec finding "daemon
// start propagates gateway token on the child process command line".
// Daemon.Start now scrubs --token / --token=<value> from the argv
// before exec'ing the long-lived child so the secret never reaches
// the daemon process command line where any local user could read it
// via ps(1) / /proc/<pid>/cmdline.
func TestStripTokenArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "two_arg_double_dash",
			in:   []string{"--host", "127.0.0.1", "--token", "s3cret", "--port", "4000"},
			want: []string{"--host", "127.0.0.1", "--port", "4000"},
		},
		{
			name: "two_arg_single_dash",
			in:   []string{"-token", "s3cret", "--port", "4000"},
			want: []string{"--port", "4000"},
		},
		{
			name: "equals_form_double_dash",
			in:   []string{"--token=s3cret", "--host", "127.0.0.1"},
			want: []string{"--host", "127.0.0.1"},
		},
		{
			name: "equals_form_single_dash",
			in:   []string{"-token=s3cret", "--host", "127.0.0.1"},
			want: []string{"--host", "127.0.0.1"},
		},
		{
			name: "case_insensitive",
			in:   []string{"--TOKEN", "s3cret", "--port", "4000"},
			want: []string{"--port", "4000"},
		},
		{
			name: "no_token_passthrough",
			in:   []string{"--host", "127.0.0.1", "--port", "4000"},
			want: []string{"--host", "127.0.0.1", "--port", "4000"},
		},
		{
			name: "empty",
			in:   nil,
			want: nil,
		},
		{
			name: "trailing_bare_token",
			in:   []string{"--host", "127.0.0.1", "--token"},
			want: []string{"--host", "127.0.0.1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripTokenArgs(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("stripTokenArgs(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("stripTokenArgs(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
			// Belt-and-suspenders: assert the secret literal does
			// not survive in any returned element.
			for _, a := range got {
				if a == "s3cret" || a == "--token=s3cret" || a == "-token=s3cret" {
					t.Fatalf("token leaked through scrub: %q", a)
				}
			}
		})
	}
}

// TestDaemonEnvMatchesDataDir is the regression for DeepSec finding
// "killStaleProcesses can terminate unrelated processes". Before
// signalling a candidate stale daemon, killStaleProcesses verifies the
// process's /proc/<pid>/environ contains BOTH DEFENSECLAW_DAEMON=1 AND
// DEFENSECLAW_DATA_DIR=<this daemon's data dir>. This test covers the
// pure parser; the full kill path is exercised by the integration tests
// since /proc is Linux-only.
func TestDaemonEnvMatchesDataDir(t *testing.T) {
	mkenv := func(pairs ...string) []byte {
		var b []byte
		for _, p := range pairs {
			b = append(b, []byte(p)...)
			b = append(b, 0)
		}
		return b
	}

	cases := []struct {
		name    string
		environ []byte
		dataDir string
		want    bool
	}{
		{
			name: "matching_data_dir_and_marker",
			environ: mkenv(
				"PATH=/usr/bin",
				"DEFENSECLAW_DAEMON=1",
				"DEFENSECLAW_DATA_DIR=/home/op/.defenseclaw",
			),
			dataDir: "/home/op/.defenseclaw",
			want:    true,
		},
		{
			name: "different_profile_must_not_match",
			environ: mkenv(
				"DEFENSECLAW_DAEMON=1",
				"DEFENSECLAW_DATA_DIR=/home/op/.dc-profile-2",
			),
			dataDir: "/home/op/.defenseclaw",
			want:    false,
		},
		{
			name: "missing_daemon_marker",
			environ: mkenv(
				"DEFENSECLAW_DATA_DIR=/home/op/.defenseclaw",
			),
			dataDir: "/home/op/.defenseclaw",
			want:    false,
		},
		{
			name: "missing_data_dir_marker",
			environ: mkenv(
				"DEFENSECLAW_DAEMON=1",
			),
			dataDir: "/home/op/.defenseclaw",
			want:    false,
		},
		{
			name:    "empty_environ",
			environ: nil,
			dataDir: "/home/op/.defenseclaw",
			want:    false,
		},
		{
			name: "empty_data_dir_argument_must_never_match",
			environ: mkenv(
				"DEFENSECLAW_DAEMON=1",
				"DEFENSECLAW_DATA_DIR=",
			),
			dataDir: "",
			want:    false,
		},
		{
			name: "substring_attack_does_not_match",
			environ: mkenv(
				"DEFENSECLAW_DAEMON=1",
				"DEFENSECLAW_DATA_DIR=/home/op/.defenseclaw-other",
			),
			dataDir: "/home/op/.defenseclaw",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := daemonEnvMatchesDataDir(tc.environ, tc.dataDir); got != tc.want {
				t.Fatalf("daemonEnvMatchesDataDir() = %v, want %v", got, tc.want)
			}
		})
	}
}
