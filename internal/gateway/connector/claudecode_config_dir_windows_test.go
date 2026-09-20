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

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEnsureClaudeCodeConfigDirWindowsProtectsCreatedDirectory(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "new-claude-config")
	if err := ensureClaudeCodeConfigDir(configDir); err != nil {
		t.Fatalf("ensureClaudeCodeConfigDir: %v", err)
	}
	if err := hookAPIValidateDirectory(configDir); err != nil {
		t.Fatalf("created configuration directory is not trusted: %v", err)
	}
}

func TestEnsureClaudeCodeConfigDirWindowsRejectsUntrustedExistingDirectory(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "existing-claude-config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("create configuration directory: %v", err)
	}
	setHookAPITokenWindowsUntrustedDACL(t, configDir, windows.GENERIC_WRITE)

	err := ensureClaudeCodeConfigDir(configDir)
	if err == nil || !strings.Contains(err.Error(), "untrusted Windows principal") {
		t.Fatalf("ensureClaudeCodeConfigDir error = %v, want untrusted-principal rejection", err)
	}
	if err := hookAPIValidateDirectoryElement(configDir); err == nil ||
		!strings.Contains(err.Error(), "untrusted Windows principal") {
		t.Fatalf("existing operator ACL was unexpectedly rewritten: %v", err)
	}
}
