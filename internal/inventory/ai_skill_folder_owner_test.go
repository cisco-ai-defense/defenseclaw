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

package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A skill folder outside every home is managed only when an administrator
// owns it; a folder a user made there is reported as the user's.
func TestSkillOutsideHomesIsManagedOnlyWhenAdminOwned(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("runs as root: every folder it makes is root's")
	}
	home, outside := t.TempDir(), t.TempDir()
	dir := filepath.Join(outside, "skills", "pdf")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: pdf\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	facts := svc.skillFacts(dir, false)
	if facts == nil || facts.Scope != SkillScopeUser || facts.Location != "" {
		t.Fatalf("user-made folder outside the homes: %+v", facts)
	}
	admin := "/"
	if runtime.GOOS == "windows" {
		admin = os.Getenv("SystemRoot")
	}
	if !skillFolderManagedNow(admin) || skillFolderManagedNow(dir) {
		t.Fatalf("admin-owned %s = %v, user folder = %v", admin, skillFolderManagedNow(admin), skillFolderManagedNow(dir))
	}
}
