// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0945: uninstall removes the answer cache only when its bytes are exactly
// what this writer produces, so the bytes are pinned here and in
// cli/tests/test_uninstall_moved_hermes_records.py (the same literal).
func TestTheAnswerStoreWritesTheBytesTheUninstallCheckExpects(t *testing.T) {
	t.Setenv("HOME", testenv.PrivateTempDir(t))
	dir := testenv.PrivateTempDir(t)
	store := newHermesAnswerStore(dir)
	first, second := strings.Repeat("a", 64), strings.Repeat("b", 64)
	store.answers[second] = hermesStoredAnswer{
		Entrypoints: []string{"a<b>&\u2028\x01\b\f\n\r\t\"\\\x7f\u00e9\U0001f600"},
		Seen:        9223372036854775807,
	}
	store.answers[first] = hermesStoredAnswer{Entrypoints: []string{}, Seen: 7}

	store.mu.Lock()
	err := store.writeLocked()
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(dir, hermesStoreFileName))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"answers":{"` + first + `":{"entrypoints":[],"seen":7},"` + second + `":{"entrypoints":["a` +
		`\u003cb\u003e\u0026\u2028\u0001\b\f\n\r\t\"\\` + "\x7f\u00e9\U0001f600" + `"],"seen":9223372036854775807}}}`
	if string(got) != want {
		t.Fatalf("the cache bytes changed, and the uninstall check in cmd_uninstall.py must change with them:\n got %q\nwant %q", got, want)
	}
}
