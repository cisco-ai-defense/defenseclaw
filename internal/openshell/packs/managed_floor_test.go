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

package packs

import (
	"strings"
	"testing"
)

// GAP-0473: on a managed computer, which runs every sandbox on a copy, a
// profile pack that mounts the project is looser than the default pack in
// workspace.mode; the same pack in copy mode is accepted.
func TestManagedProfilePackMountIsLooser(t *testing.T) {
	trustAllPacks(t)
	dir := t.TempDir()
	mount := writePack(t, dir, "eng-mount", "version: 1\nname: eng-mount\nextends: balanced\napprovals: {mode: manual}\nworkspace: {mode: mount}\n")
	copied := writePack(t, dir, "eng-copy", "version: 1\nname: eng-copy\nextends: balanced\napprovals: {mode: manual}\nworkspace: {mode: copy}\n")
	cfg := managedTestConfig(nil)
	if err := ProfilePackCheck(cfg, "", mount, ""); err == nil || !strings.Contains(err.Error(), "looser than the default pack balanced in workspace.mode") {
		t.Fatalf("mount pack: %v", err)
	}
	if err := ProfilePackCheck(cfg, "", copied, ""); err != nil {
		t.Fatalf("copy pack: %v", err)
	}
	if err := ProfilePackCheck(testConfig(nil), "", mount, ""); err != nil {
		t.Fatalf("OSS mount pack: %v", err)
	}
}

// trustAllPacks lets managed loads take the test's own pack files as the
// administrator's.
func trustAllPacks(t *testing.T) {
	t.Helper()
	previous := validateTrustedFile
	validateTrustedFile = func(string, string) error { return nil }
	t.Cleanup(func() { validateTrustedFile = previous })
}
