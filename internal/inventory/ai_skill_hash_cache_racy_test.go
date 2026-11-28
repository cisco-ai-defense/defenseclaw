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

// skillClockAfterTheWrites is a clock an hour past the writes of a test's
// fixture, so a folder written just before the scan is not racily clean and
// its hash is kept (skillHashCacheRacyWindow).
func skillClockAfterTheWrites() time.Time { return time.Now().Add(time.Hour) }

// GAP-1891: an entry stamped within one timestamp tick of the hash read is
// "racily clean" (git's term): a same-size write after the read could carry
// the same stamp, leave the signature as it was, and keep the old hash for a
// day. Such a folder is not kept; once the stamps are older than the window
// it is.
func TestGAP1891RacyFolderIsNotKept(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".agents", "skills", "pdf")
	writeSkillFiles(t, dir, map[string]string{
		"SKILL.md":       "---\nname: pdf\n---\n",
		"scripts/run.py": "print('a')\n",
	})
	// Fix every entry's write time; the clock is then set relative to it.
	stamp := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for _, rel := range []string{"", "SKILL.md", "scripts", filepath.Join("scripts", "run.py")} {
		if err := os.Chtimes(filepath.Join(dir, rel), stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)

	// The change time of an entry (outside Windows) is the real time of the
	// writes above, so the clock is set from the newest stamp the signature
	// reports, not from the fixed write time.
	_, newest, ok := skillFolderSignature(dir)
	if !ok {
		t.Fatal("skillFolderSignature: not signed")
	}
	scan := func(readAt time.Time) bool {
		svc.skillHashCache = nil
		svc.skillClock = func() time.Time { return readAt }
		svc.resetSkillFacts()
		if got := svc.skillFacts(dir, false); got.ContentStatus != SkillContentOK {
			t.Fatalf("scan: %+v", got)
		}
		_, kept := svc.skillHashCache[dir]
		return kept
	}
	for _, offset := range []time.Duration{-time.Hour, 0, time.Millisecond, skillHashCacheRacyWindow} {
		if scan(newest.Add(offset)) {
			t.Errorf("a folder whose newest stamp is %v before the read was kept in the cache", offset)
		}
	}
	if !scan(newest.Add(skillHashCacheRacyWindow + time.Millisecond)) {
		t.Error("a folder whose newest stamp is just over a window older than the read was not kept")
	}
	if !scan(newest.Add(time.Hour)) {
		t.Error("a folder whose newest stamp is an hour older than the read was not kept")
	}

	// A kept entry is used; a racy one is read again by the next scan.
	svc.skillHashCache = nil
	svc.skillClock = func() time.Time { return newest.Add(time.Millisecond) }
	svc.resetSkillFacts()
	svc.skillFacts(dir, false)
	svc.resetSkillFacts()
	svc.skillBytesRead = 0
	svc.skillFacts(dir, false)
	if svc.skillBytesRead == 0 {
		t.Error("a racily clean folder was not read again by the next scan")
	}
}
