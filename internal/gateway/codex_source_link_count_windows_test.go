// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCodexSourceFileHasSingleLinkWindows(t *testing.T) {
	directory := t.TempDir()
	unique := filepath.Join(directory, "unique.txt")
	if err := os.WriteFile(unique, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	uniqueInfo, err := os.Lstat(unique)
	if err != nil {
		t.Fatal(err)
	}
	if !codexSingleLinkRegularFile(unique, uniqueInfo) {
		t.Fatal("unique Windows source file was not accepted")
	}

	alias := filepath.Join(directory, "alias.txt")
	if err := os.Link(unique, alias); err != nil {
		t.Fatal(err)
	}
	linkedInfo, err := os.Lstat(unique)
	if err != nil {
		t.Fatal(err)
	}
	if codexSingleLinkRegularFile(unique, linkedInfo) {
		t.Fatal("hard-linked Windows source file was accepted")
	}
}
