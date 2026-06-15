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

package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestValidatePluginOwner_SameUID pins the happy path: a plugin owned
// by the running process's UID passes the owner check.
func TestValidatePluginOwner_SameUID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin owner check is unix-only")
	}
	dir := t.TempDir()
	soPath := filepath.Join(dir, "plugin.so")
	if err := os.WriteFile(soPath, []byte("not-a-real-so"), 0o644); err != nil {
		t.Fatalf("seed plugin file: %v", err)
	}
	if err := validatePluginOwner(soPath); err != nil {
		t.Errorf("validatePluginOwner on self-owned file: %v", err)
	}
}

// TestValidatePluginOwner_DifferentUID injects a fake getuid that
// returns a different UID than the file's actual owner, simulating
// the threat model: a hostile user dropping a plugin in a directory
// readable by the daemon. The check must reject.
func TestValidatePluginOwner_DifferentUID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin owner check is unix-only")
	}
	dir := t.TempDir()
	soPath := filepath.Join(dir, "plugin.so")
	if err := os.WriteFile(soPath, []byte("not-a-real-so"), 0o644); err != nil {
		t.Fatalf("seed plugin file: %v", err)
	}

	original := pluginGetUID
	t.Cleanup(func() { pluginGetUID = original })
	// File is owned by the test runner's UID; pretend the daemon is
	// running under UID 0 so the owner does NOT match.
	pluginGetUID = func() int { return 0 }

	if pluginGetUID() == os.Getuid() {
		t.Skip("test runner is root; can't simulate UID mismatch this way")
	}

	err := validatePluginOwner(soPath)
	if err == nil {
		t.Fatal("expected validatePluginOwner to reject UID mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "owner uid") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestEmitPluginRejection_DefaultsToLog confirms the loader has a
// non-panicking fallback when no audit emitter is wired (plain test
// harness / `go run` smoke usage). The previous behavior used
// log.Printf directly; now the emitPluginRejection helper centralizes
// the fallback.
func TestEmitPluginRejection_DefaultsToLog(t *testing.T) {
	original := pluginAuditEmitter
	t.Cleanup(func() { pluginAuditEmitter = original })
	pluginAuditEmitter = nil
	// Should not panic.
	emitPluginRejection("PLUGIN_HASH_MISMATCH", "test message", "/tmp/x.so", errors.New("boom"))
}

// TestSetPluginAuditEmitter_RoutesRejections asserts that when the
// emitter is wired, a synthetic rejection lands in the registered
// callback rather than the log fallback.
func TestSetPluginAuditEmitter_RoutesRejections(t *testing.T) {
	original := pluginAuditEmitter
	t.Cleanup(func() { pluginAuditEmitter = original })

	type captured struct {
		code, msg, soPath string
		cause             error
	}
	var got captured
	SetPluginAuditEmitter(func(ctx context.Context, code, msg, soPath string, cause error) {
		got = captured{code: code, msg: msg, soPath: soPath, cause: cause}
	})
	emitPluginRejection("PLUGIN_OWNER_MISMATCH", "uid 0 != 1000", "/tmp/x.so", errors.New("uid drift"))

	if got.code != "PLUGIN_OWNER_MISMATCH" {
		t.Errorf("code = %q", got.code)
	}
	if !strings.Contains(got.msg, "uid 0") {
		t.Errorf("msg = %q", got.msg)
	}
	if got.soPath != "/tmp/x.so" {
		t.Errorf("soPath = %q", got.soPath)
	}
	if got.cause == nil || got.cause.Error() != "uid drift" {
		t.Errorf("cause = %v", got.cause)
	}
}
