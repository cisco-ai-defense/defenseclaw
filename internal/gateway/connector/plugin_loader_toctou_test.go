// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestValidatePluginRootChain_HappyPath confirms a strict-perms tree
// owned by the test runner is accepted.
func TestValidatePluginRootChain_HappyPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ancestry walk is unix-only")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := validatePluginRootChain(dir); err != nil {
		t.Errorf("expected ok, got %v", err)
	}
}

// TestValidatePluginRootChain_WorldWritable refuses a 0o777 leaf.
// This is the canonical foothold the DeepSec report calls out: a
// shared-host attacker swaps directory entries because the parent is
// writable.
func TestValidatePluginRootChain_WorldWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ancestry walk is unix-only")
	}
	root := t.TempDir()
	leaf := filepath.Join(root, "writable")
	if err := os.MkdirAll(leaf, 0o777); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(leaf, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	err := validatePluginRootChain(leaf)
	if err == nil {
		t.Fatal("expected refusal of world-writable leaf, got nil")
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSafeOpenPluginSO_HappyPath: regular file, owned by us, opens.
func TestSafeOpenPluginSO_HappyPath(t *testing.T) {
	dir := t.TempDir()
	soPath := filepath.Join(dir, "plugin.so")
	if err := os.WriteFile(soPath, []byte("not-real-so"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	fd, info, err := safeOpenPluginSO(soPath)
	if err != nil {
		t.Fatalf("safeOpen: %v", err)
	}
	defer fd.Close()
	if info.Size() != int64(len("not-real-so")) {
		t.Errorf("size mismatch: %d", info.Size())
	}
}

// TestSafeOpenPluginSO_SymlinkRefused: a symlink target is rejected
// at Lstat time (the previous loader would have happily resolved it
// and loaded the resolution). This is the primary fix for the
// "Plugin validation is raceable before plugin.Open" finding.
func TestSafeOpenPluginSO_SymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks unreliable on Windows test runners")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.so")
	if err := os.WriteFile(target, []byte("real"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	link := filepath.Join(dir, "plugin.so")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	fd, _, err := safeOpenPluginSO(link)
	if err == nil {
		fd.Close()
		t.Fatal("expected symlink refusal, got nil error")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestCachePluginCopy_WritesImmutableCopy verifies that a successful
// copy produces a 0o600 file in the cache dir keyed by the manifest
// sha256, and that the file contents survive an attempted source
// rewrite afterwards (i.e., we are loading from the cache, not the
// source path).
func TestCachePluginCopy_WritesImmutableCopy(t *testing.T) {
	srcDir := t.TempDir()
	cacheDir := t.TempDir()
	if err := os.Chmod(cacheDir, 0o700); err != nil {
		t.Fatalf("chmod cache: %v", err)
	}

	payload := []byte("plugin-bytes-v1")
	srcPath := filepath.Join(srcDir, "plugin.so")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	sum := sha256.Sum256(payload)
	expected := hex.EncodeToString(sum[:])

	fd, _, err := safeOpenPluginSO(srcPath)
	if err != nil {
		t.Fatalf("safeOpen: %v", err)
	}
	cachePath, err := cachePluginCopy(fd, cacheDir, "test-plugin", expected)
	fd.Close()
	if err != nil {
		t.Fatalf("cache: %v", err)
	}

	// Cache file must live under cacheDir, be regular, and be 0o600.
	if filepath.Dir(cachePath) != cacheDir {
		t.Errorf("cache path %s not under %s", cachePath, cacheDir)
	}
	info, err := os.Lstat(cachePath)
	if err != nil {
		t.Fatalf("lstat cache: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("cache file not regular: %v", info.Mode())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("cache file mode = %04o, want 0600", info.Mode().Perm())
	}

	// Now rewrite the source. The cache copy should NOT change.
	if err := os.WriteFile(srcPath, []byte("attacker-payload"), 0o600); err != nil {
		t.Fatalf("rewrite src: %v", err)
	}
	cached, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if string(cached) != string(payload) {
		t.Errorf("cache contents mutated after source rewrite: got %q, want %q", cached, payload)
	}
}

// TestCachePluginCopy_HashMismatchRefused: an attacker who can rewrite
// the source between manifest publication and load gets caught by the
// hash check during the cache copy. The cache file MUST NOT be
// materialised on mismatch.
func TestCachePluginCopy_HashMismatchRefused(t *testing.T) {
	srcDir := t.TempDir()
	cacheDir := t.TempDir()
	if err := os.Chmod(cacheDir, 0o700); err != nil {
		t.Fatalf("chmod cache: %v", err)
	}

	srcPath := filepath.Join(srcDir, "plugin.so")
	if err := os.WriteFile(srcPath, []byte("real-plugin"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Manifest claims a different hash than the actual contents.
	wrongSum := sha256.Sum256([]byte("not-the-real-bytes"))
	wrongHex := hex.EncodeToString(wrongSum[:])

	fd, _, err := safeOpenPluginSO(srcPath)
	if err != nil {
		t.Fatalf("safeOpen: %v", err)
	}
	_, err = cachePluginCopy(fd, cacheDir, "test-plugin", wrongHex)
	fd.Close()
	if err == nil {
		t.Fatal("expected hash mismatch refusal, got nil")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("unexpected error: %v", err)
	}

	// No file with the bogus name should remain in the cache.
	wrongFinal := filepath.Join(cacheDir, wrongHex+".so")
	if _, statErr := os.Lstat(wrongFinal); statErr == nil {
		t.Errorf("cache file %s should NOT exist after hash mismatch", wrongFinal)
	}
}

// TestEnsurePluginCacheDir_CreatesAndTightens: a fresh override dir
// is created with 0o700 and survives a re-call (idempotent) without
// loosening perms.
func TestEnsurePluginCacheDir_CreatesAndTightens(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix mode bits not meaningful")
	}
	base := t.TempDir()
	original := pluginCacheDirOverride
	t.Cleanup(func() { pluginCacheDirOverride = original })
	pluginCacheDirOverride = base

	first, err := ensurePluginCacheDir()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	info, err := os.Lstat(first)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("perms = %04o, want 0700", info.Mode().Perm())
	}

	// Loosen perms on disk, then call again — should be retightened.
	if err := os.Chmod(first, 0o755); err != nil {
		t.Fatalf("chmod loosen: %v", err)
	}
	second, err := ensurePluginCacheDir()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if second != first {
		t.Errorf("path changed: %s vs %s", first, second)
	}
	info2, err := os.Lstat(first)
	if err != nil {
		t.Fatalf("stat 2: %v", err)
	}
	if info2.Mode().Perm() != 0o700 {
		t.Errorf("perms after re-call = %04o, want 0700", info2.Mode().Perm())
	}
}
