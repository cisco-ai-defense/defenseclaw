// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestCopyModeWorksWithoutAWritableSharedStateDir (substrate-1:GAP-0087): an
// actor image where /sandbox/.dc cannot be made (here a file is in its way)
// still starts a copy and pulls it back: the launcher keeps each copy's
// state in its own directory beside the project, not in the fixed
// /sandbox/.dc.
func TestCopyModeWorksWithoutAWritableSharedStateDir(t *testing.T) {
	if runtimeUnsupported() {
		t.Skip("copy mode is Linux and macOS only")
	}
	o := newOperator(t)
	o.initRepo()
	a := newActor(t)
	sb := sandboxFS{Client: a.client(), dir: t.TempDir()}
	blocked := sb.local("/sandbox/.dc")
	if err := os.MkdirAll(filepath.Dir(blocked), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blocked, []byte("not a directory\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := Start(ctx, StartOptions{Transport: sb, Project: o.project, Name: "c1", DataDir: o.data, Home: o.home}); err != nil {
		t.Fatalf("Start with no usable /sandbox/.dc: %v", err)
	}
	write(t, sb.local(remoteProject), "src/new.go", "package main\n\nfunc New() {}\n", 0o644)
	if _, err := Pull(ctx, PullOptions{Exec: sb, DataDir: o.data, Name: "c1"}); err != nil {
		t.Fatalf("Pull with no usable /sandbox/.dc: %v", err)
	}
	if fi, err := os.Lstat(blocked); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("/sandbox/.dc was touched: %v %v", fi, err)
	}
}
