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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestWriteAndReadPIDInfo(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	now := time.Now().Unix()
	err := d.writePIDInfo(12345, "/usr/bin/defenseclaw-gateway", "")
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
	_ = d.writePIDInfo(42, "/tmp/test-bin", "")

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

func TestChildEnvUsesDotenvGatewayTokenOverStaleParent(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)
	dotenvPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(dotenvPath, []byte("DEFENSECLAW_GATEWAY_TOKEN=from-dotenv\n"), 0o600); err != nil {
		t.Fatalf("write dotenv: %v", err)
	}

	env := d.childEnv([]string{
		"PATH=/bin",
		"DEFENSECLAW_GATEWAY_TOKEN=stale-parent",
		"OPENCLAW_GATEWAY_TOKEN=legacy-parent",
		EnvDaemon + "=0",
		EnvDataDir + "=/wrong",
	})
	got := envMap(env)

	if got["DEFENSECLAW_GATEWAY_TOKEN"] != "from-dotenv" {
		t.Errorf("DEFENSECLAW_GATEWAY_TOKEN = %q, want dotenv token", got["DEFENSECLAW_GATEWAY_TOKEN"])
	}
	if _, ok := got["OPENCLAW_GATEWAY_TOKEN"]; ok {
		t.Errorf("OPENCLAW_GATEWAY_TOKEN should be stripped when dotenv provides the gateway token")
	}
	if got[EnvDaemon] != "1" {
		t.Errorf("%s = %q, want 1", EnvDaemon, got[EnvDaemon])
	}
	if got[EnvDataDir] != dir {
		t.Errorf("%s = %q, want %q", EnvDataDir, got[EnvDataDir], dir)
	}
}

func TestChildEnvPreservesParentGatewayTokenWhenDotenvMissing(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	env := d.childEnv([]string{
		"DEFENSECLAW_GATEWAY_TOKEN=operator-env",
	})
	got := envMap(env)

	if got["DEFENSECLAW_GATEWAY_TOKEN"] != "operator-env" {
		t.Errorf("DEFENSECLAW_GATEWAY_TOKEN = %q, want parent token", got["DEFENSECLAW_GATEWAY_TOKEN"])
	}
}

func TestChildEnvUsesLegacyDotenvGatewayTokenOverStaleParent(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)
	dotenvPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(dotenvPath, []byte("OPENCLAW_GATEWAY_TOKEN='legacy-dotenv'\n"), 0o600); err != nil {
		t.Fatalf("write dotenv: %v", err)
	}

	env := d.childEnv([]string{
		"OPENCLAW_GATEWAY_TOKEN=legacy-parent",
	})
	got := envMap(env)

	if got["OPENCLAW_GATEWAY_TOKEN"] != "legacy-dotenv" {
		t.Errorf("OPENCLAW_GATEWAY_TOKEN = %q, want legacy dotenv token", got["OPENCLAW_GATEWAY_TOKEN"])
	}
}

func envMap(env []string) map[string]string {
	out := map[string]string{}
	for _, kv := range env {
		key, value, ok := strings.Cut(kv, "=")
		if ok {
			out[key] = value
		}
	}
	return out
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

func TestHasManagedProcessIdentityRejectsLegacyPIDRecord(t *testing.T) {
	d := New(t.TempDir())
	if err := os.WriteFile(d.pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if d.HasManagedProcessIdentity(os.Getpid()) {
		t.Fatal("legacy PID record must not prove managed startup identity")
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
	case "linux", "darwin", "windows":
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
	// Capture the live start identity so verifyStartIdentity passes —
	// otherwise the chain F-3399 hardening (PID-reuse detection) would
	// reject the current process for not having a recorded identity.
	ident, _ := processStartIdentity(os.Getpid())

	info := pidInfo{
		PID:           os.Getpid(),
		Executable:    exe,
		StartTime:     time.Now().Unix(),
		StartIdentity: ident,
	}

	if !d.verifyProcess(info) {
		t.Error("verifyProcess should return true for current process")
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

	if d.verifyProcess(info) {
		t.Error("verifyProcess should return false for non-existent PID")
	}
}

// TestVerifyProcessRejectsMismatchedStartIdentity pins the second half of
// avarice chain F-3399 (F-0942). A PID file written for a process that
// later exited and had its PID reused must NOT verify as the original —
// the start-identity tokens differ even when the executable name happens
// to match. We simulate this by recording an identity that intentionally
// disagrees with the current process's live identity.
func TestVerifyProcessRejectsMismatchedStartIdentity(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skipf("test not applicable on %s", runtime.GOOS)
	}
	d := New(t.TempDir())
	exe, _ := os.Executable()
	live, err := processStartIdentity(os.Getpid())
	if err != nil || live == "" {
		t.Skipf("processStartIdentity unavailable: %v", err)
	}
	info := pidInfo{
		PID:           os.Getpid(),
		Executable:    exe,
		StartTime:     time.Now().Unix(),
		StartIdentity: live + "-stale", // simulate PID reuse
	}
	if d.verifyProcess(info) {
		t.Error("verifyProcess must reject a mismatched start identity (PID-reuse case)")
	}
}

func TestWritePIDInfoUsesRestrictedPerms(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)
	_ = d.writePIDInfo(99999, "/usr/bin/test", "")

	testenv.AssertPrivateFile(t, d.pidFile)
}

func TestDataDirAndLogFilePerms(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "nested", "data")
	d := New(dataDir)

	if err := safefile.ProtectDirectory(d.dataDir); err != nil {
		t.Fatalf("ProtectDirectory: %v", err)
	}
	testenv.AssertPrivateDirectory(t, d.dataDir)

	logPath := d.LogFile()
	f, err := d.openLogFileForChild()
	if err != nil {
		t.Fatalf("create logFile: %v", err)
	}
	f.Close()

	testenv.AssertPrivateFile(t, logPath)
}

func TestOpenLogFileForChildRejectsSymlink(t *testing.T) {
	d := New(t.TempDir())
	outside := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, d.logFile); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	f, err := d.openLogFileForChild()
	if f != nil {
		_ = f.Close()
	}
	if err == nil {
		t.Fatal("openLogFileForChild accepted a symlink")
	}
	data, readErr := os.ReadFile(outside)
	if readErr != nil || string(data) != "unchanged" {
		t.Fatalf("outside log changed: data=%q err=%v", data, readErr)
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
