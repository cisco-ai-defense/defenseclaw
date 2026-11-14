//go:build !windows

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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The OpenClaw trusted-path rule as setup applies it: a user-owned binary
// in a folder only its owner can write passes; a group-writable binary or
// folder does not (OpenClaw would block every install).
func TestOpenClawInstallPolicyPathTrusted(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(bin, "defenseclaw-gateway")
	if err := os.WriteFile(command, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := openClawInstallPolicyPathTrusted(command, ""); err != nil {
		t.Skipf("the test folder itself fails the rule (%v); the checks below need a trusted temp folder", err)
	}
	if err := os.Chmod(command, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := openClawInstallPolicyPathTrusted(command, ""); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("a group-writable command passed: %v", err)
	}
	if err := os.Chmod(command, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := openClawInstallPolicyPathTrusted(command, ""); err == nil {
		t.Fatal("a group-writable parent folder passed")
	}
	if err := os.Chmod(bin, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := openClawInstallPolicyPathTrusted(command, ""); err != nil {
		t.Fatalf("a sticky world-writable parent is accepted by OpenClaw: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(command, link); err != nil {
		t.Fatal(err)
	}
	if err := openClawInstallPolicyPathTrusted(link, ""); err == nil {
		t.Fatal("a symlinked command passed")
	}
	if err := openClawInstallPolicyPathTrusted(command, "no-such-account-dc-test"); err == nil {
		t.Fatal("an unknown OpenClaw account passed")
	}
}
