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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// GAP-1242: discovery replaces agent_discovery.json atomically (write a temp
// file, rename it over the cache) while the gateway reads it. On Windows the
// read opened the file without sharing delete, so the rename failed with
// access denied and the CLI dropped that scan; the Windows-native run saw it
// as a flaky "rename agent_discovery.json.tmp: Access is denied". Every
// rename over the cache succeeds while it is being read, and every read
// sees a whole version, or none, never a torn one. The rename is the one
// discovery makes (replaceLikeDiscovery): on Windows a MoveFileExW (os.Rename)
// is refused while any handle has the cache open, whatever it shares, so no
// reader could let that one through. (On other platforms a rename never waits
// for readers; the test passes there either way.)
func TestCachedAgentVersionReadsDoNotBlockAReplaceOfTheCache(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "agent_discovery.json")
	write := func(i int) error {
		tmp := filepath.Join(dir, "agent_discovery.json.tmp")
		body := fmt.Sprintf(`{"agents":{"openclaw":{"installed":true,"version":"2026.11.%d","binary_path":"x"}}}`, i)
		if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
			return err
		}
		return replaceLikeDiscovery(tmp, cache)
	}
	if err := write(0); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var reads, torn atomic.Int32
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				v := LoadCachedAgentVersion(dir, "openclaw")
				reads.Add(1)
				if v != "" && NormalizeAgentVersion("openclaw", v) == "" {
					torn.Add(1)
				}
			}
		}()
	}
	var failed []error
	for i := 1; i <= 400; i++ {
		if err := write(i); err != nil {
			failed = append(failed, err)
		}
	}
	stop.Store(true)
	wg.Wait()
	// A scanner that opens the file without sharing delete (Defender, the
	// indexer) can fail a rename now and then; the reads of the cache made
	// nearly every one fail.
	if len(failed) > 5 {
		t.Fatalf("%d of 400 replaces of the cache failed while it was read (%d reads); first: %v", len(failed), reads.Load(), failed[0])
	}
	if torn.Load() > 0 {
		t.Fatalf("%d reads saw a version that does not parse", torn.Load())
	}
	if reads.Load() == 0 {
		t.Fatal("the cache was never read")
	}
}
