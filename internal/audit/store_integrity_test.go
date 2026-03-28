// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

func TestStore_IntegrityBaselineUpsert(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "a.db")
	s, err := NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	root := filepath.Join(tmp, "skill-root")
	if err := s.UpsertIntegrityBaseline("skill", "my-skill", root, "deadbeef", `{"file_count":3}`); err != nil {
		t.Fatal(err)
	}
	b, err := s.GetIntegrityBaseline("skill", "my-skill")
	if err != nil {
		t.Fatal(err)
	}
	if b == nil || b.Fingerprint != "deadbeef" || b.RootPath != root {
		t.Fatalf("baseline: %+v", b)
	}

	if err := s.UpsertIntegrityBaseline("skill", "my-skill", root, "cafebabe", `{}`); err != nil {
		t.Fatal(err)
	}
	b2, err := s.GetIntegrityBaseline("skill", "my-skill")
	if err != nil {
		t.Fatal(err)
	}
	if b2.Fingerprint != "cafebabe" {
		t.Fatalf("fingerprint not updated: %q", b2.Fingerprint)
	}

	list, err := s.ListIntegrityBaselines()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list len %d", len(list))
	}
}
