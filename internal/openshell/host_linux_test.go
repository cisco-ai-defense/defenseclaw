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

//go:build linux

package openshell

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMemTotal(t *testing.T) {
	for in, want := range map[string]uint64{
		"MemTotal:       32612345 kB\nMemFree:  1 kB\n": 32612345 << 10,
		"MemFree: 1 kB\n":     0,
		"MemTotal: lots kB\n": 0,
		"MemTotal:\n":         0,
		"":                    0,
	} {
		if got := memTotal([]byte(in)); got != want {
			t.Errorf("memTotal(%q) = %d, want %d", in, got, want)
		}
	}
	if hostMemory() == 0 {
		t.Error("hostMemory() = 0 on a Linux host")
	}
}

// A MicroVM's overlay is a sparse file: its disk use is what the host
// allocated, not its size.
func TestAllocatedBytesOfASparseFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "overlay.ext4")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(4 << 30); err != nil {
		t.Skipf("no sparse files here: %v", err)
	}
	_ = f.Close()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := allocatedBytes(info); got >= 1<<20 {
		t.Fatalf("allocatedBytes = %d for a 4 GiB hole", got)
	}
}
