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
	"time"
)

// GAP-1816: a full scan read every skill folder again in every mode. An
// unchanged folder now keeps its hash, and a changed one is read again.
func TestGAP1816UnchangedSkillFolderIsNotReadAgain(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".agents", "skills", "pdf")
	writeSkillFiles(t, dir, map[string]string{
		"SKILL.md":       "---\nname: pdf\ndescription: Fill PDF forms\n---\n",
		"scripts/run.py": "print('a')\n",
	})
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	svc.skillClock = skillClockAfterTheWrites

	first := *svc.skillFacts(dir, false)
	if first.ContentStatus != SkillContentOK || svc.skillBytesRead == 0 {
		t.Fatalf("first scan: %+v, %d bytes read", first, svc.skillBytesRead)
	}
	svc.resetSkillFacts()
	second := *svc.skillFacts(dir, false)
	if second != first {
		t.Fatalf("unchanged folder: %+v, want %+v", second, first)
	}
	if svc.skillBytesRead != 0 {
		t.Fatalf("an unchanged skill folder was read again: %d bytes", svc.skillBytesRead)
	}

	// A write of the same size, with the write time set back, is still seen
	// outside Windows (the inode change time moves).
	run := filepath.Join(dir, "scripts", "run.py")
	info, err := os.Stat(run)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		time.Sleep(10 * time.Millisecond)
		if err := os.WriteFile(run, []byte("print('b')\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(run, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
		svc.resetSkillFacts()
		third := *svc.skillFacts(dir, false)
		if third.ContentHash == first.ContentHash || svc.skillBytesRead == 0 {
			t.Fatalf("a same-size write kept the old hash: %+v", third)
		}
	}

	// A new file is seen everywhere.
	writeSkillFiles(t, dir, map[string]string{"extra.md": "x"})
	svc.resetSkillFacts()
	fourth := *svc.skillFacts(dir, false)
	if fourth.ContentHash == first.ContentHash || svc.skillBytesRead == 0 {
		t.Fatalf("an added file kept the old hash: %+v", fourth)
	}

	// The manifest stays readable by hash from a cached folder.
	svc.resetSkillFacts()
	cached := *svc.skillFacts(dir, false)
	if cached != fourth || svc.skillBytesRead != 0 {
		t.Fatalf("second read of the edited folder: %+v, %d bytes", cached, svc.skillBytesRead)
	}
	if _, ok := svc.SkillManifest(cached.ManifestHash); !ok {
		t.Fatal("the manifest of a cached folder is not readable by its hash")
	}
}
