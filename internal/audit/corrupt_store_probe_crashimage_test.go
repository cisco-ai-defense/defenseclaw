// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-2:GAP-0575: the read-only integrity probe now runs before the
// first writable open on every gateway start. A healthy store that a crash
// left with a populated WAL and a missing, empty, short, zeroed or unrelated
// wal-index (-shm) must still open with its WAL-only rows: it is not corrupt,
// so it is never archived and the start prints no warning.
func TestOpenDaemonStoreHealthyCrashImageSHMStates(t *testing.T) {
	states := []struct {
		name  string
		shm   func(t *testing.T, shm string)
		walOK bool // the WAL-only marker is expected after the start
	}{
		{"valid-copy", func(*testing.T, string) {}, true},
		{"missing", func(t *testing.T, shm string) {
			if err := os.Remove(shm); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"empty", func(t *testing.T, shm string) { writeSHM(t, shm, nil) }, true},
		{"short", func(t *testing.T, shm string) { writeSHM(t, shm, bytes.Repeat([]byte{0x5a}, 100)) }, true},
		{"zeroed", func(t *testing.T, shm string) { writeSHM(t, shm, make([]byte, 32768)) }, true},
		{"garbage", func(t *testing.T, shm string) { writeSHM(t, shm, bytes.Repeat([]byte{0xa5}, 32768)) }, true},
	}
	for _, state := range states {
		t.Run(state.name, func(t *testing.T) {
			path := corruptWALFixture(t, "none")
			state.shm(t, path+"-shm")
			var warning bytes.Buffer
			store, err := OpenDaemonStore(path, &warning)
			if err != nil {
				t.Fatalf("OpenDaemonStore with a %s wal-index: %v", state.name, err)
			}
			defer store.Close()
			var markers, base int
			if err := store.db.QueryRow(`SELECT count(*) FROM audit_events WHERE id = 'wal-only-marker'`).Scan(&markers); err != nil {
				t.Fatal(err)
			}
			if err := store.db.QueryRow(`SELECT count(*) FROM audit_events WHERE id LIKE 'base-%'`).Scan(&base); err != nil {
				t.Fatal(err)
			}
			if markers != 1 || base != 400 {
				t.Fatalf("rows after the start: marker=%d base=%d; want 1 and 400", markers, base)
			}
			if found := MovedCorruptStores(path); len(found) != 0 {
				t.Fatalf("a healthy store was archived: %+v", found)
			}
			if strings.Contains(warning.String(), "WARNING") {
				t.Fatalf("start warning for a healthy store: %q", warning.String())
			}
			if archives, _ := filepath.Glob(path + ".corrupt-*"); len(archives) != 0 {
				t.Fatalf("archive files left: %v", archives)
			}
		})
	}
}

func writeSHM(t *testing.T, shm string, body []byte) {
	t.Helper()
	if err := os.WriteFile(shm, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
