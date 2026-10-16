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

package watcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-1192: an admission retry is forgotten only when the asset is gone. A
// folder the watcher may not reach for now keeps its issue and retry.
func TestAdmissionRetryKeepsAnIssueWhoseFolderIsOnlyUnreachable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reaches every folder")
	}
	dataDir, root := t.TempDir(), t.TempDir()
	locked := filepath.Join(root, "locked")
	skill := filepath.Join(locked, "skill-a")
	gone := filepath.Join(root, "skill-gone")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	s := newAdmissionState(dataDir, func(p string) string { return p })
	for _, path := range []string{skill, gone} {
		s.setIssue(AdmissionIssue{Type: string(InstallSkill), Name: filepath.Base(path), Path: path, Kind: AdmissionUnscanned})
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	later := time.Now().Add(admissionRetryLast)
	if due := s.dueIssues(later, AdmissionUnscanned); len(due) != 0 {
		t.Fatalf("due = %+v, want none: one folder is gone, the other unreachable", due)
	}
	issues, err := ReadAdmissionIssues(dataDir)
	if err != nil || len(issues) != 1 || issues[0].Path != skill {
		t.Fatalf("issues = %+v (err %v), want only the unreachable skill kept", issues, err)
	}
	if err := os.Chmod(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	due := s.dueIssues(later.Add(2*admissionRetryLast), AdmissionUnscanned)
	if len(due) != 1 || due[0].Path != skill {
		t.Fatalf("due once reachable = %+v, want the skill", due)
	}
}
