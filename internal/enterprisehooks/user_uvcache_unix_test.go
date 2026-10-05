// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1947: uninstall --purge left the DefenseClaw wheels earlier per-user
// installers put in each account's ~/.cache/uv (about 25 MB per install),
// which the per-user uninstall --all --binaries removes. The purge removes
// DefenseClaw's archives, wheel pointers and editable builds there and keeps
// every other cache entry, and never follows a link out of the cache.
func TestPurgeUserStateRemovesDefenseClawUVCacheEntries(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	cache := filepath.Join(home, ".cache", "uv")
	write := func(rel string) {
		t.Helper()
		path := filepath.Join(cache, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gone := []string{
		"archive-v0/AAA/defenseclaw/__init__.py",
		"archive-v0/AAA/defenseclaw-1.0.0.dist-info/METADATA",
		"archive-v0/BBB/__editable__.defenseclaw-0.8.10.pth",
		"archive-v0/BBB/defenseclaw-0.8.10.dist-info/METADATA",
		"wheels-v6/url/1f2e/defenseclaw/1.0.1-py3-none-any.http",
		"wheels-v6/pypi/defenseclaw/1.0.0-py3-none-any.http",
		"sdists-v9/editable/c0ffee/x1/defenseclaw-0.8.10-py3-none-any.whl",
	}
	kept := []string{
		"archive-v0/CCC/requests/__init__.py",
		"archive-v0/CCC/requests-2.32.0.dist-info/METADATA",
		"archive-v0/DDD/defenseclaw-1.0.0.dist-info/METADATA",
		"archive-v0/DDD/other-1.0.dist-info/METADATA",
		"wheels-v6/pypi/requests/2.32.0-py3-none-any.http",
		"sdists-v9/editable/beef/x1/myproject-0.1-py3-none-any.whl",
	}
	for _, rel := range append(append([]string{}, gone...), kept...) {
		write(rel)
	}
	// A linked archive folder outside the cache is never followed.
	outside := filepath.Join(home, "elsewhere")
	if err := os.MkdirAll(filepath.Join(outside, "EEE", "defenseclaw-1.0.0.dist-info"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cache, "archive-v1")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}

	opts := InstallOptions{UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry()}
	summary, err := PurgeUserStateSummary(context.Background(), opts)
	if err != nil {
		t.Fatalf("PurgeUserStateSummary: %v", err)
	}
	if !summary.UVCache || !summary.Data {
		t.Fatalf("summary = %+v, want Data and UVCache", summary)
	}
	for _, rel := range gone {
		if _, err := os.Stat(filepath.Join(cache, filepath.FromSlash(rel))); !os.IsNotExist(err) {
			t.Errorf("%s stayed: %v", rel, err)
		}
	}
	for _, rel := range kept {
		if _, err := os.Stat(filepath.Join(cache, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s must stay: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "EEE")); err != nil {
		t.Errorf("the purge followed a link out of the cache: %v", err)
	}

	// A rerun after ~/.defenseclaw went still cleans the cache, and an
	// account without a uv cache is not an error.
	write("archive-v0/FFF/defenseclaw-1.0.1.dist-info/METADATA")
	summary, err = PurgeUserStateSummary(context.Background(), opts)
	if err != nil || !summary.UVCache || summary.Data {
		t.Fatalf("rerun: summary %+v, err %v", summary, err)
	}
	if err := os.RemoveAll(filepath.Join(home, ".cache")); err != nil {
		t.Fatal(err)
	}
	if summary, err := PurgeUserStateSummary(context.Background(), opts); err != nil || summary.UVCache {
		t.Fatalf("without a uv cache: summary %+v, err %v", summary, err)
	}
}
