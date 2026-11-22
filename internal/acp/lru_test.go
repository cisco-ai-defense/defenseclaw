// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"fmt"
	"testing"
)

func TestLRUMapDropsTheLeastRecentlyUsedEntry(t *testing.T) {
	m := newLRUMap[string](3)
	for i := 0; i < 3; i++ {
		m.put(fmt.Sprint("k", i), fmt.Sprint("v", i))
	}
	if _, ok := m.get("k0"); !ok { // k0 is now the most recently used
		t.Fatal("k0 missing")
	}
	m.put("k3", "v3") // evicts k1, the least recently used
	if m.len() != 3 {
		t.Fatalf("len = %d", m.len())
	}
	if m.has("k1") {
		t.Fatal("the least recently used entry was kept")
	}
	for _, key := range []string{"k0", "k2", "k3"} {
		if !m.has(key) {
			t.Fatalf("%s was dropped", key)
		}
	}
	m.put("k2", "again") // an update keeps the size
	if value, _ := m.get("k2"); value != "again" || m.len() != 3 {
		t.Fatalf("k2 = %q, len %d", value, m.len())
	}
}
