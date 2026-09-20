// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func mustLoadRulePack(t testing.TB, dir string) *guardrail.RulePack {
	t.Helper()
	rp, err := guardrail.LoadRulePack(dir)
	if err != nil {
		t.Fatalf("LoadRulePack(%q): %v", dir, err)
	}
	return rp
}

func invalidRulePackDir(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	writeRulePackFixtureFile(t, dir, "suppressions.yaml", "version: [\n")
	return dir
}

func writeRulePackFixtureFile(t testing.TB, root, relative, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create rule-pack fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write rule-pack fixture %q: %v", relative, err)
	}
}

func installDefaultRulePackForDataDir(t testing.TB, dataDir string) string {
	t.Helper()
	_, helperPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve rule-pack test helper path")
	}
	source := filepath.Join(filepath.Dir(helperPath), "..", "..", "policies", "guardrail", "default")
	destination := filepath.Join(dataDir, "policies", "guardrail", "default")
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatalf("create test rule-pack parent: %v", err)
	}
	if err := os.CopyFS(destination, os.DirFS(source)); err != nil {
		t.Fatalf("copy default test rule pack: %v", err)
	}
	if err := filepath.WalkDir(destination, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		mode := os.FileMode(0o600)
		if entry.IsDir() {
			mode = 0o700
		}
		return os.Chmod(path, mode)
	}); err != nil {
		t.Fatalf("normalize copied rule-pack fixture permissions: %v", err)
	}
	return destination
}

func routerWithDefaultRulePack(t testing.TB) *EventRouter {
	t.Helper()
	router := NewEventRouter(nil, nil, nil, false)
	router.SetRulePack(mustLoadRulePack(t, ""))
	return router
}
