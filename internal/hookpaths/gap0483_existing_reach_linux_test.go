// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGAP0483ExistingLeavesShareParentReach(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	cache := filepath.Join(home, ".defenseclaw", "cache")
	for _, dir := range []string{project, cache} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const leaves = 2000
	for i := 0; i < leaves; i++ {
		if err := os.WriteFile(filepath.Join(project, fmt.Sprintf("leaf%d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldRead := readPath
	var leafReads atomic.Int64
	readPath = func(name string, kind pathReadKind) pathReadResult {
		if strings.HasPrefix(name, project+string(filepath.Separator)+"leaf") {
			leafReads.Add(1)
		}
		return oldRead(name, kind)
	}
	t.Cleanup(func() { readPath = oldRead })
	memo := NewTargetMemo()
	for i := 0; i < leaves; i++ {
		path := filepath.Join(project, fmt.Sprintf("leaf%d", i))
		if got := ProtectedReach(path, home, memo); got != GradeNone {
			t.Fatalf("ordinary leaf %d = %s", i, got)
		}
	}
	if got := leafReads.Load(); got != leaves {
		t.Fatalf("%d leaves needed %d file reads, want one per leaf", leaves, got)
	}
	protected := filepath.Join(cache, "entry")
	if err := os.WriteFile(protected, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(project, "alias")
	if err := os.Link(protected, alias); err != nil {
		t.Fatal(err)
	}
	if got := ProtectedReach(alias, home, NewTargetMemo()); got != GradeNamed {
		t.Fatalf("protected alias = %s, want Named", got)
	}
	ordinaryAlias := filepath.Join(project, "ordinary-alias")
	if err := os.Link(filepath.Join(project, "leaf0"), ordinaryAlias); err != nil {
		t.Fatal(err)
	}
	if got := ProtectedReach(ordinaryAlias, home, NewTargetMemo()); got != GradeNone {
		t.Fatalf("ordinary alias = %s, want None", got)
	}
}
