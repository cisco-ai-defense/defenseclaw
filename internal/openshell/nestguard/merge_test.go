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

//go:build linux || darwin

package nestguard

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// One `git init` showed as two quarantines and two warnings: the guard
// renamed .git while git was still writing it, git recreated it, and that
// was quarantined again. Both entries are renamed, but a .git that comes
// back in the same folder within MergeWindow is part of the same
// detection; one that comes back later is a new one.
func TestRequarantineWithinTheWindowMerges(t *testing.T) {
	root := realTemp(t)
	var mu sync.Mutex
	now := fixedNow()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	var merged collector
	g, detected := guard(t, Options{Root: root, OnMerge: merged.add, Now: clock})
	mkdir(t, filepath.Join(root, "vendor", "tool", ".git", "objects"))
	g.sweep(".")
	// git init writes on into the .git it recreates.
	advance(time.Second)
	mkdir(t, filepath.Join(root, "vendor", "tool", ".git", "refs", "heads"))
	g.sweep(".")

	got := detected.list()
	if len(got) != 1 || got[0].Dir != "vendor/tool" || len(got[0].Also) != 0 {
		t.Fatalf("detections = %+v, want one", got)
	}
	m := merged.list()
	if len(m) != 1 || m[0].Quarantined != got[0].Quarantined || len(m[0].Also) != 1 ||
		!strings.HasPrefix(m[0].Also[0], "vendor/tool/"+QuarantinePrefix) || m[0].Also[0] == got[0].Quarantined {
		t.Fatalf("merged = %+v", m)
	}
	for _, name := range append([]string{m[0].Quarantined}, m[0].Also...) {
		present(t, filepath.Join(root, filepath.FromSlash(name)))
	}
	gone(t, filepath.Join(root, "vendor", "tool", ".git"))
	if all := g.Detections(); len(all) != 1 || len(all[0].Also) != 1 {
		t.Fatalf("Detections = %+v", all)
	}
	// Later, it is another repository.
	advance(MergeWindow + time.Second)
	mkdir(t, filepath.Join(root, "vendor", "tool", ".git"))
	if g.sweep("."); len(detected.list()) != 2 {
		t.Fatalf("detections after the window = %+v", detected.list())
	}
}
