// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestManifestHomes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("manifest homes are a unix standalone input; the Windows helper is given no home dirs")
	}
	restore := validateManifestTrust
	validateManifestTrust = func(string) error { return nil }
	defer func() { validateManifestTrust = restore }()

	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yaml")
	if homes, digest, err := manifestHomes(path); err != nil || homes != nil || digest != "" {
		t.Fatalf("missing manifest: %v %v %q", homes, err, digest)
	}
	body := `version: 1
targets:
  - user: alice
    user_home: /home/alice
    connector: codex
  - user: alice
    user_home: /home/alice/
    connector: claudecode
  - user: bob
    user_home: /home/bob
    connector: codex
    enabled: false
  - user: carol
    user_home: relative/path
    connector: codex
`
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	homes, digest, err := manifestHomes(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(homes, []string{"/home/alice"}) || len(digest) != 64 {
		t.Fatalf("homes %v digest %q", homes, digest)
	}

	validateManifestTrust = func(string) error { return errors.New("untrusted") }
	if _, _, err := manifestHomes(path); err == nil {
		t.Fatal("untrusted manifest accepted")
	}
	validateManifestTrust = func(string) error { return nil }

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := watchManifest(context.Background(), path, digest, 10*time.Millisecond, logger)
	if err := os.WriteFile(path, []byte(body+"  - user: dave\n    user_home: /home/dave\n    connector: codex\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("manifest change did not end the helper context")
	}
}
