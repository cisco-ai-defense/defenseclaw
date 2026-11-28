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
	"testing"
	"time"
)

// GAP-1902: a cached skill folder whose file is overwritten in place with
// the same number of bytes, while the writer still holds its handle open,
// is hashed again by the next scan. The signature knows only a file's size,
// write time and creation time, so it is the file system that must bring the
// write time up to date at the write, not at the close of the handle. On
// Windows this is checked natively (os.Lstat is the file's own record).
func TestGAP1902SameSizeWriteWithOpenHandleIsSeen(t *testing.T) {
	writes := map[string]func(f *os.File) error{
		"write-at": func(f *os.File) error {
			_, err := f.WriteAt([]byte("print('b')\n"), 0)
			return err
		},
		"write-at-then-sync": func(f *os.File) error {
			if _, err := f.WriteAt([]byte("print('b')\n"), 0); err != nil {
				return err
			}
			return f.Sync()
		},
	}
	for name, write := range writes {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, ".agents", "skills", "pdf")
			writeSkillFiles(t, dir, map[string]string{"SKILL.md": "---\nname: pdf\n---\n", "run.py": "print('a')\n"})
			script := filepath.Join(dir, "run.py")
			// An old write time, so that a write that stamps the file shows.
			old := time.Now().Add(-time.Hour)
			if err := os.Chtimes(script, old, old); err != nil {
				t.Fatal(err)
			}
			svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
				Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
			}, nil)
			cleanupPreparedDiscoveryService(t, svc)
			svc.skillClock = skillClockAfterTheWrites
			scan := func() AISkillFacts {
				svc.resetSkillFacts()
				return *svc.skillFacts(dir, false)
			}
			first := scan()
			if first.ContentStatus != SkillContentOK {
				t.Fatalf("first scan: %+v", first)
			}
			if _, kept := svc.skillHashCache[dir]; !kept {
				t.Fatal("the first scan did not keep the folder in the hash cache")
			}
			before, err := os.Lstat(script)
			if err != nil {
				t.Fatal(err)
			}

			f, err := os.OpenFile(script, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			t.Cleanup(func() {
				if !closed {
					_ = f.Close()
				}
			})
			if err := write(f); err != nil {
				t.Fatal(err)
			}
			during, err := os.Lstat(script)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("GAP1902DIAG %s size before=%d during=%d, LastWriteTime before=%s during=%s (moved=%v)",
				name, before.Size(), during.Size(), before.ModTime().UTC().Format(time.RFC3339Nano),
				during.ModTime().UTC().Format(time.RFC3339Nano), !during.ModTime().Equal(before.ModTime()))

			open := scan()
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
			after, err := os.Lstat(script)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("GAP1902DIAG %s LastWriteTime after close=%s (moved since open=%v)", name,
				after.ModTime().UTC().Format(time.RFC3339Nano), !after.ModTime().Equal(during.ModTime()))
			closedFacts := scan()
			if closedFacts.ContentStatus != SkillContentOK || closedFacts.ContentHash == first.ContentHash {
				t.Fatalf("after the close the scan did not see the write: %+v (first %+v)", closedFacts, first)
			}
			// With the writer's handle open the folder is hashed, or (on
			// Windows, where the reader denies write sharing) unreadable and
			// not kept: never the hash from before the write.
			if !during.ModTime().After(before.ModTime()) {
				t.Errorf("the file's write time did not move at the write, with the handle open: %s -> %s", before.ModTime(), during.ModTime())
			}
			if open.ContentHash == first.ContentHash || open.ContentStatus == SkillContentOK && open != closedFacts {
				t.Fatalf("with the write handle open the scan = %+v, after the close %+v (first %+v): the cache served the old hash", open, closedFacts, first)
			}
		})
	}
}
