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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"plugin"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// PluginAuditEmitter is the callback contract the gateway wires up so
// the plugin loader can emit audit-pipeline events on rejection without
// the connector package importing gatewaylog (which would create a
// dependency cycle once handlers move into this package per Phase C1).
//
// Implementations forward to gatewaylog.Event{EventType: EventError,
// Subsystem: SubsystemPlugin, Code: ...} via the same writer choke
// point as emitGatewayError. When unset, the loader falls back to
// log.Printf so a built-in run with no audit pipeline still surfaces
// the rejection. Plan B3 / S0.1 invariant: every refusal MUST land in
// the audit log when the pipeline is wired.
type PluginAuditEmitter func(ctx context.Context, code, msg, soPath string, cause error)

var pluginAuditEmitter PluginAuditEmitter

// SetPluginAuditEmitter wires the audit-pipeline emitter callback. The
// gateway calls this exactly once at boot, before any plugin discovery
// runs. Calling with nil restores the log-only fallback (used by
// tests that want to inspect rejections without setting up the full
// audit machinery).
func SetPluginAuditEmitter(e PluginAuditEmitter) {
	pluginAuditEmitter = e
}

// pluginGetUID is overridable for tests. Returns the effective UID of
// the running process. Defined in platform-specific files.

func emitPluginRejection(code, msg, soPath string, cause error) {
	if pluginAuditEmitter != nil {
		pluginAuditEmitter(context.Background(), code, msg, soPath, cause)
		return
	}
	if cause != nil {
		log.Printf("[SECURITY] %s: %s (so=%s): %v", code, msg, soPath, cause)
	} else {
		log.Printf("[SECURITY] %s: %s (so=%s)", code, msg, soPath)
	}
}

// pluginManifest is the structure of plugin.yaml in each connector plugin dir.
type pluginManifest struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
	Entry       string `yaml:"entry"`
	SHA256      string `yaml:"sha256"`
}

// LoadPlugins scans a directory for connector plugin subdirectories, each
// containing a plugin.yaml manifest and a compiled Go .so file. Returns
// all successfully loaded connectors.
//
// Security invariants enforced before plugin.Open (which runs init()):
//   - manifest.SHA256 must be present and match the .so contents read
//     from the open file descriptor (not just the pathname).
//   - the .so real path must resolve inside the plugin directory
//     (no symlink escape).
//   - the .so itself must NOT be a symlink (refused via Lstat). The
//     previous loader resolved symlinks instead of refusing them,
//     which let an unprivileged local user point a writable name
//     at an unrelated trusted .so and confuse the audit log.
//   - the .so must not be group-writable or world-writable.
//   - the .so must be owned by the gateway UID.
//   - every directory ancestor of the plugin root (up to "/") must be
//     owned by the gateway UID or root, and must NOT be group- or
//     world-writable. This blocks the directory-entry race where an
//     unprivileged user with write access on a parent directory swaps
//     the verified .so out for an attacker-controlled one between the
//     hash check and plugin.Open (DeepSec finding "Plugin validation
//     is raceable before plugin.Open executes code").
//   - plugin.Open is invoked on an immutable copy in a DefenseClaw-
//     owned 0o700 cache directory, not on the original path. The
//     cache copy is hashed-on-write from the same file descriptor we
//     verified, and the copied file is re-validated for owner and
//     mode before plugin.Open runs init code. Even if an attacker
//     races the source path between any two checks, the loaded code
//     is the bytes we hashed.
func LoadPlugins(dir string) ([]Connector, error) {
	if dir == "" {
		return nil, nil
	}

	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("resolve plugin dir %s: %w", dir, err)
	}

	if err := validatePluginRootChain(realDir); err != nil {
		emitPluginRejection("PLUGIN_ROOT_UNSAFE",
			fmt.Sprintf("plugin root %s rejected (writable or foreign-owned ancestor)", realDir),
			realDir, err)
		return nil, fmt.Errorf("plugin root %s unsafe: %w", realDir, err)
	}

	entries, err := os.ReadDir(realDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plugin dir %s: %w", realDir, err)
	}

	cacheDir, err := ensurePluginCacheDir()
	if err != nil {
		return nil, fmt.Errorf("ensure plugin cache: %w", err)
	}

	var connectors []Connector
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pluginDir := filepath.Join(realDir, entry.Name())
		manifestPath := filepath.Join(pluginDir, "plugin.yaml")

		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			log.Printf("[connector] skipping %s: no plugin.yaml: %v", entry.Name(), err)
			continue
		}

		var manifest pluginManifest
		if err := yaml.Unmarshal(manifestData, &manifest); err != nil {
			log.Printf("[connector] skipping %s: bad plugin.yaml: %v", entry.Name(), err)
			continue
		}

		if strings.TrimSpace(manifest.SHA256) == "" {
			emitPluginRejection("PLUGIN_MANIFEST_INVALID",
				fmt.Sprintf("plugin %s: plugin.yaml missing required sha256 field", entry.Name()),
				manifestPath, nil)
			continue
		}
		if strings.TrimSpace(manifest.Entry) == "" {
			emitPluginRejection("PLUGIN_MANIFEST_INVALID",
				fmt.Sprintf("plugin %s: plugin.yaml missing required entry field", entry.Name()),
				manifestPath, nil)
			continue
		}

		soPath := filepath.Join(pluginDir, manifest.Entry)

		if err := validatePluginPath(soPath, realDir); err != nil {
			emitPluginRejection("PLUGIN_PATH_REJECTED",
				fmt.Sprintf("plugin %s: path validation failed", manifest.Name), soPath, err)
			continue
		}

		// The plugin subdirectory itself must satisfy the same
		// "owner+mode+ancestor" guarantees as the parent root,
		// otherwise a user with write access in pluginDir can
		// swap entries inside it.
		if err := validatePluginRootChain(pluginDir); err != nil {
			emitPluginRejection("PLUGIN_ROOT_UNSAFE",
				fmt.Sprintf("plugin %s: subdirectory %s unsafe", manifest.Name, pluginDir),
				pluginDir, err)
			continue
		}

		// Open the .so safely (refuses symlinks and inode races
		// between Lstat and Open) and hash the bytes we will
		// actually copy. This binds the hash to the open file
		// descriptor, not just the pathname.
		fd, srcInfo, err := safeOpenPluginSO(soPath)
		if err != nil {
			emitPluginRejection("PLUGIN_PATH_REJECTED",
				fmt.Sprintf("plugin %s: safe open failed", manifest.Name), soPath, err)
			continue
		}

		if err := validatePluginPermissionsFromInfo(soPath, srcInfo); err != nil {
			fd.Close()
			emitPluginRejection("PLUGIN_PERMISSION_DENIED",
				fmt.Sprintf("plugin %s: permission check failed", manifest.Name), soPath, err)
			continue
		}

		if err := validatePluginOwnerFromInfo(soPath, srcInfo); err != nil {
			fd.Close()
			emitPluginRejection("PLUGIN_OWNER_MISMATCH",
				fmt.Sprintf("plugin %s: owner check failed", manifest.Name), soPath, err)
			continue
		}

		cachePath, err := cachePluginCopy(fd, cacheDir, manifest.Name, manifest.SHA256)
		fd.Close()
		if err != nil {
			emitPluginRejection("PLUGIN_HASH_MISMATCH",
				fmt.Sprintf("plugin %s: cache copy failed", manifest.Name), soPath, err)
			continue
		}

		// Re-run owner and mode checks on the cached copy before
		// handing it to plugin.Open. The cache directory is 0o700
		// and owned by us, but we still belt-and-suspenders the
		// individual file in case an operator points the cache
		// path at something they shouldn't.
		if err := validatePluginPermissions(cachePath); err != nil {
			emitPluginRejection("PLUGIN_PERMISSION_DENIED",
				fmt.Sprintf("plugin %s: cached copy permission check failed", manifest.Name),
				cachePath, err)
			continue
		}
		if err := validatePluginOwner(cachePath); err != nil {
			emitPluginRejection("PLUGIN_OWNER_MISMATCH",
				fmt.Sprintf("plugin %s: cached copy owner check failed", manifest.Name),
				cachePath, err)
			continue
		}

		c, err := loadPluginSO(cachePath)
		if err != nil {
			emitPluginRejection("PLUGIN_LOAD_FAILED",
				fmt.Sprintf("plugin %s: load failed", manifest.Name), soPath, err)
			continue
		}

		connectors = append(connectors, c)
		log.Printf("[SECURITY] loaded plugin: %s v%s (sha256=%s)", manifest.Name, manifest.Version, manifest.SHA256[:16]+"...")
	}

	return connectors, nil
}

// validatePluginPath ensures the .so file resolves to a real path inside the
// allowed root directory, blocking symlink escapes and path traversal.
func validatePluginPath(soPath, allowedRoot string) error {
	realPath, err := filepath.EvalSymlinks(soPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", soPath, err)
	}
	realRoot, err := filepath.EvalSymlinks(allowedRoot)
	if err != nil {
		return fmt.Errorf("resolve root %s: %w", allowedRoot, err)
	}
	if !strings.HasPrefix(realPath, realRoot+string(filepath.Separator)) {
		return fmt.Errorf("resolved path %s escapes allowed root %s", realPath, realRoot)
	}
	return nil
}

// validatePluginPermissions refuses .so files that are group-writable or
// world-writable. On Windows this check is skipped (file modes are not
// meaningful).
func validatePluginPermissions(soPath string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Lstat(soPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", soPath, err)
	}
	return validatePluginPermissionsFromInfo(soPath, info)
}

// validatePluginPermissionsFromInfo is the FileInfo-driven variant of
// validatePluginPermissions. The caller already has an authoritative
// FileInfo (typically from an Fstat against an open fd) and we want
// to avoid an extra Lstat that could observe a different inode.
func validatePluginPermissionsFromInfo(soPath string, info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	mode := info.Mode().Perm()
	if mode&0o022 != 0 {
		return fmt.Errorf("%s is group-writable or world-writable (mode %04o)", soPath, mode)
	}
	return nil
}

// validatePluginOwner refuses .so files that are not owned by the
// running process's UID. The previous permission gate covered
// "world-writable" but not "world-readable + owned-by-attacker": a
// hostile user on a shared host could drop a plugin in a directory
// the gateway daemon reads, set mode 0o755, and have it loaded with
// the daemon's privileges. This gate closes that path.
//
// validatePluginOwner and validatePluginOwnerFromInfo are implemented in
// platform-specific files (plugin_owner_unix.go / plugin_owner_windows.go)
// because owner verification relies on the unix-only syscall.Stat_t. The
// FromInfo variant lets the open-then-Fstat TOCTOU path reuse the FileInfo
// it already obtained from the open fd instead of re-stating by path.

// validatePluginRootChain walks dirPath upwards and rejects if any
// ancestor is group-/world-writable or owned by an unexpected UID.
// "Unexpected UID" means anything other than the gateway's own UID
// (pluginGetUID) and root (uid 0). Allowing root is necessary because
// system directories like "/" and "/usr/local" are root-owned and
// expected; an attacker who already has root can substitute anything
// regardless of our checks. Skipping on Windows because the syscall
// metadata is unix-only.
func validatePluginRootChain(dirPath string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(dirPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", dirPath, err)
	}
	gatewayUID := uint32(pluginGetUID())
	cur := filepath.Clean(resolved)
	// Cap iterations defensively in case Dir() loops on something exotic.
	for i := 0; i < 1024; i++ {
		info, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("lstat ancestor %s: %w", cur, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("ancestor %s is not a directory", cur)
		}
		mode := info.Mode().Perm()
		if mode&0o022 != 0 {
			return fmt.Errorf("ancestor %s is group- or world-writable (mode %04o); refuse to load plugins from a directory tree another local user can modify", cur, mode)
		}
		uid, ok := pluginOwnerUID(info)
		if !ok {
			return fmt.Errorf("ancestor %s: could not extract owner UID (non-unix FS?)", cur)
		}
		if uid != gatewayUID && uid != 0 {
			return fmt.Errorf("ancestor %s owner uid=%d is neither the gateway uid=%d nor root", cur, uid, gatewayUID)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		cur = parent
	}
	return fmt.Errorf("ancestor walk for %s exceeded depth limit", resolved)
}

// safeOpenPluginSO opens the plugin .so while refusing symlinks and
// closing the lstat-vs-open inode race.
//
//   - Lstat refuses any non-regular file (symlink, fifo, device, etc.).
//   - We then os.Open the path. On unix os.Open follows symlinks,
//     but since the previous Lstat saw a regular file, an attacker
//     swapping the entry to a symlink between Lstat and Open is
//     caught by the post-open Fstat: the inode and dev numbers from
//     the open file descriptor MUST match what Lstat observed,
//     otherwise the entry was raced and we refuse.
//
// The caller must Close the returned fd. The returned FileInfo comes
// from the open fd (Stat), which is the authoritative one for any
// downstream owner/permission checks.
func safeOpenPluginSO(soPath string) (*os.File, os.FileInfo, error) {
	lstatInfo, err := os.Lstat(soPath)
	if err != nil {
		return nil, nil, fmt.Errorf("lstat %s: %w", soPath, err)
	}
	if !lstatInfo.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file (mode=%s); refuse symlinks/devices/pipes for plugin load targets", soPath, lstatInfo.Mode())
	}

	f, err := os.Open(soPath) //nolint:gosec // path is rooted in validated plugin dir tree.
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", soPath, err)
	}

	fdInfo, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("fstat %s: %w", soPath, err)
	}
	if !fdInfo.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s opened to a non-regular file (mode=%s); refusing", soPath, fdInfo.Mode())
	}

	if runtime.GOOS != "windows" {
		lDev, lIno, lOK := pluginInodeIdentity(lstatInfo)
		fDev, fIno, fOK := pluginInodeIdentity(fdInfo)
		if !lOK || !fOK {
			f.Close()
			return nil, nil, fmt.Errorf("%s: could not compare lstat/fstat inode (non-unix FS?)", soPath)
		}
		if lIno != fIno || lDev != fDev {
			f.Close()
			return nil, nil, fmt.Errorf("%s: inode/dev changed between lstat and open (was %d/%d, now %d/%d); directory entry was raced", soPath, lDev, lIno, fDev, fIno)
		}
	}

	return f, fdInfo, nil
}

// pluginCacheDirOverride is overridable for tests. When non-empty it
// replaces the default os.TempDir() base for ensurePluginCacheDir.
var pluginCacheDirOverride string

// ensurePluginCacheDir creates (idempotently) a 0o700 cache directory
// owned by the gateway UID under TempDir, returning its absolute path.
// The cache holds immutable plugin .so copies that plugin.Open
// dlopen()s instead of the original (raceable) source paths.
func ensurePluginCacheDir() (string, error) {
	base := pluginCacheDirOverride
	if base == "" {
		base = os.TempDir()
	}
	uid := pluginGetUID()
	dir := filepath.Join(base, fmt.Sprintf("defenseclaw-plugin-cache-%s", strconv.Itoa(uid)))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// Tighten perms on existing dir (MkdirAll will not chmod an existing one).
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("chmod %s: %w", dir, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Lstat(dir)
		if err != nil {
			return "", fmt.Errorf("stat cache dir %s: %w", dir, err)
		}
		ownerUID, ok := pluginOwnerUID(info)
		if !ok {
			return "", fmt.Errorf("cache dir %s: could not extract owner UID", dir)
		}
		if ownerUID != uint32(uid) {
			return "", fmt.Errorf("cache dir %s owner uid=%d does not match gateway uid=%d (someone else owns the cache dir; refuse to use)", dir, ownerUID, uid)
		}
	}
	return dir, nil
}

// cachePluginCopy reads the open plugin fd, hashes the contents, and
// atomically materialises an immutable 0o600 cache copy named
// "<sha256>.so" under cacheDir. Returns the absolute path of the
// cached file. The hash MUST match expectedHex from the manifest;
// mismatch returns an error and removes the partial copy.
//
// The atomic-rename pattern (write to "<sha256>.so.tmp.<pid>" then
// rename) means that even if multiple gateway processes race on the
// same plugin we converge on a single immutable file. Plugin .so
// images are typically megabytes; the copy cost is negligible vs the
// security benefit of binding plugin.Open to bytes we hashed.
func cachePluginCopy(srcFD *os.File, cacheDir, manifestName, expectedHex string) (string, error) {
	if _, err := srcFD.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("seek src: %w", err)
	}

	want := strings.ToLower(strings.TrimSpace(expectedHex))
	finalName := fmt.Sprintf("%s.so", want)
	finalPath := filepath.Join(cacheDir, finalName)

	// Fast path: if the cache already holds a file with the expected
	// name, re-verify its hash (cheap insurance against an operator
	// hand-editing the cache) and reuse it.
	if existing, err := os.Open(finalPath); err == nil {
		actual, hashErr := hashReader(existing)
		existing.Close()
		if hashErr == nil && actual == want {
			return finalPath, nil
		}
		// Stale or tampered cache entry — remove and rebuild.
		_ = os.Remove(finalPath)
	}

	tmp, err := os.CreateTemp(cacheDir, fmt.Sprintf("%s.*.so.tmp", sanitizePluginName(manifestName)))
	if err != nil {
		return "", fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return "", fmt.Errorf("chmod tmp: %w", err)
	}

	h := sha256.New()
	tee := io.TeeReader(srcFD, h)
	if _, err := io.Copy(tmp, tee); err != nil {
		return "", fmt.Errorf("copy plugin into cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return "", fmt.Errorf("fsync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close tmp: %w", err)
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, want) {
		return "", fmt.Errorf("sha256 mismatch on cache copy: manifest=%s actual=%s", expectedHex, actual)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", fmt.Errorf("rename %s -> %s: %w", tmpPath, finalPath, err)
	}
	cleanup = false
	return finalPath, nil
}

// sanitizePluginName turns a manifest.Name into a filesystem-safe
// stem for tempfile naming (purely cosmetic; the cache file itself
// is keyed by sha256).
func sanitizePluginName(name string) string {
	if name == "" {
		return "plugin"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "plugin"
	}
	return out
}

// hashReader streams r into sha256 and returns the lowercase hex digest.
func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// validatePluginHash computes the SHA-256 digest of the file and compares it
// against the expected hex string from the manifest.
func validatePluginHash(soPath, expectedHex string) error {
	f, err := os.Open(soPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", soPath, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash %s: %w", soPath, err)
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, strings.TrimSpace(expectedHex)) {
		return fmt.Errorf("sha256 mismatch: manifest=%s actual=%s", expectedHex, actual)
	}
	return nil
}

// loadPluginSO opens a compiled Go shared library and looks up the
// NewConnector symbol.
func loadPluginSO(path string) (Connector, error) {
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open plugin %s: %w", path, err)
	}

	sym, err := p.Lookup("NewConnector")
	if err != nil {
		return nil, fmt.Errorf("lookup NewConnector in %s: %w", path, err)
	}

	newFn, ok := sym.(func() (Connector, error))
	if !ok {
		return nil, fmt.Errorf("NewConnector in %s has wrong signature (want func() (Connector, error))", path)
	}

	return newFn()
}
