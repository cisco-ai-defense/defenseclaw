// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisebundle

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// An anchor file this account may list but not read is anchor_insecure, and
// the refusal says why: errors.Is(err, fs.ErrPermission).
func TestUnreadableAnchorsRefusalWrapsThePermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 0000 file")
	}
	path := filepath.Join(t.TempDir(), AnchorsName)
	if err := os.WriteFile(path, []byte("{}"), 0o000); err != nil {
		t.Fatal(err)
	}
	_, err := LoadAnchors(path, nil)
	if CodeOf(err) != CodeAnchorInsecure || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("LoadAnchors = %v (code %q, permission %v)", err, CodeOf(err), errors.Is(err, fs.ErrPermission))
	}
	if _, err := LoadAnchors(filepath.Join(t.TempDir(), AnchorsName), nil); errors.Is(err, fs.ErrPermission) || CodeOf(err) != CodeAnchorMissing {
		t.Fatalf("missing anchors = %v", err)
	}
}
