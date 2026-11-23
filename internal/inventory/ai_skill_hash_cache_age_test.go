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
	"path/filepath"
	"testing"
)

// Every skill folder is read again once its cached hash is a day old, so a
// write whose metadata was put back is found within a day.
func TestSkillHashCacheAgesOut(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".agents", "skills", "pdf")
	writeSkillFiles(t, dir, map[string]string{"SKILL.md": "---\nname: pdf\n---\n"})
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	svc.skillClock = skillClockAfterTheWrites

	first := *svc.skillFacts(dir, false)
	// Every folder is read again once its cached hash is a day old.
	svc.skillFactsMu.Lock()
	entry := svc.skillHashCache[dir]
	entry.hashedAt = entry.hashedAt.Add(-skillHashCacheMaxAge)
	svc.skillHashCache[dir] = entry
	svc.skillFactsMu.Unlock()
	svc.resetSkillFacts()
	if got := *svc.skillFacts(dir, false); got != first || svc.skillBytesRead == 0 {
		t.Fatalf("a day-old hash was not read again: %+v, %d bytes", got, svc.skillBytesRead)
	}

	// A scan cut short by the scan budget is not kept.
	svc.skillHashCache = nil
	svc.resetSkillFacts()
	svc.skillBytesRead = maxSkillScanBytes - 1
	if got := svc.skillFacts(dir, false); got.ContentStatus != SkillContentTooLarge {
		t.Fatalf("over the scan budget: %+v", got)
	}
	if _, kept := svc.skillHashCache[dir]; kept {
		t.Fatal("a folder cut short by the scan budget was kept in the cache")
	}
}

// A managed scan on Windows, where a user can write every file time back,
// reads every folder each time; elsewhere it uses the cache.
func TestSkillHashCacheManagedWindowsReadsEveryScan(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".agents", "skills", "pdf")
	writeSkillFiles(t, dir, map[string]string{"SKILL.md": "---\nname: pdf\n---\n"})
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	svc.skillClock = skillClockAfterTheWrites
	svc.opts.ManagedEnterprise = true
	svc.skillFacts(dir, false)
	svc.resetSkillFacts()
	svc.skillFacts(dir, false)
	if read := svc.skillBytesRead != 0; read == skillChangeStampTamperEvident {
		t.Fatalf("managed scan read again = %v, want %v", read, !skillChangeStampTamperEvident)
	}
}
