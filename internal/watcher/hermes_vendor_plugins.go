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

package watcher

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// Hermes ships plugins in its checkout (hermes-agent/plugins). A shipped
// plugin whose bytes, read in the scan that decides it, match the digest
// DefenseClaw pins for that Hermes release is vendor code the account did not
// install, so it is reported as informational vendor content and not scanned,
// as the digest-pinned Hermes bundled skills are not. Nothing about that
// decision is stored as trust: every scan reads the plugin again, and no
// baseline carries a mark. The baseline written for vendor content is an
// ordinary snapshot with no stored scan; it records which bytes were seen, and
// it vouches for nothing but bytes that still match the digest
// (hermesBaselineOwesAdmission). A plugin that differs from its digest in any
// byte, file or link is scanned as any other, under hermes, and a shipped
// plugin that had such a baseline is admitted, so an edit of vendor bytes is
// refused when HIGH. Change detection for a shipped plugin covers the folders
// the snapshot leaves out (skippedTreeHash), so a later change anywhere the
// scanner can read reaches a scan whatever was admitted before. The manifest
// only grows: an unchanged plugin whose release digest was dropped would be
// scanned again.

const (
	hermesPluginMaxEntries   = 4096
	hermesPluginMaxFileBytes = 8 << 20
	hermesPluginMaxTreeBytes = 64 << 20

	// hermesScannerReadBytes is the largest file the plugin scanner reads
	// from a folder it skips (analyzers.py: forced entrypoints, 2 MiB). A
	// larger file there is known by name and size alone, unless a manifest
	// declares it, which binds it by content whatever its size.
	hermesScannerReadBytes = 2 << 20

	// hermesVendorPluginReason is the admission reason for a shipped plugin
	// whose bytes match their pinned digest.
	hermesVendorPluginReason = "hermes shipped plugin matches its pinned vendor digest"
)

// hermesSkippedTreeMaxBytes bounds the bytes skippedTreeHash reads in one
// call. Past it the tree has no stable hash, so it is never unchanged and is
// scanned in every cycle. A variable so a test can lower it.
var hermesSkippedTreeMaxBytes int64 = 1 << 30

var errHermesPluginUnverified = errors.New("hermes plugin tree cannot be matched to its vendor digest")

// hermesBundledPluginRoot reports the Hermes shipped plugin root: the plugins
// folder of a hermes-agent checkout, or the root HERMES_BUNDLED_PLUGINS names.
func hermesBundledPluginRoot(dir string) bool {
	dir = filepath.Clean(dir)
	if filepath.Base(dir) == "plugins" && filepath.Base(filepath.Dir(dir)) == "hermes-agent" {
		return true
	}
	bundled := strings.TrimSpace(os.Getenv("HERMES_BUNDLED_PLUGINS"))
	return bundled != "" && filepath.Clean(bundled) == dir
}

// hermesShippedPlugin reports the shipped-plugin name (its path under the
// Hermes shipped plugin root) of a plugin directory under a registered Hermes
// shipped root. Secure Client keeps its existing admission and rescan.
func (w *InstallWatcher) hermesShippedPlugin(evt InstallEvent) (string, bool) {
	if evt.Type != InstallPlugin || w.secureClientActive() {
		return "", false
	}
	path := filepath.Clean(evt.Path)
	if info, err := os.Lstat(path); err != nil || !info.IsDir() {
		return "", false
	}
	for _, dir := range w.pluginDirs {
		if !hermesBundledPluginRoot(dir) || w.connectorForPath(dir) != "hermes" {
			continue
		}
		relative, err := filepath.Rel(filepath.Clean(dir), path)
		if err == nil && filepath.IsLocal(relative) {
			return filepath.ToSlash(relative), true
		}
	}
	return "", false
}

// hermesVendorPlugin reads the plugin of evt once and reports whether those
// bytes match the digest pinned for it.
func (w *InstallWatcher) hermesVendorPlugin(evt InstallEvent) bool {
	name, ok := w.hermesShippedPlugin(evt)
	if !ok || hermesPluginVendorDigests[name] == "" {
		return false
	}
	digest, err := hermesPluginTreeDigest(filepath.Clean(evt.Path), w.manifestLoader())
	if err != nil || digest != hermesPluginVendorDigests[name] {
		return false
	}
	return true
}

// rescanHermesVendorPlugin is the rescan side of hermesVendorPlugin: it
// reports the plugin as informational vendor content, once per process, and
// tells the caller to leave it unscanned. It records the snapshot of those
// bytes as the plugin's baseline, with no scan and no mark, when there is
// none for the current scanner fingerprint, so that a later change is an
// admission and not a first sight.
func (w *InstallWatcher) rescanHermesVendorPlugin(evt InstallEvent, snap *TargetSnapshot, baseline *audit.SnapshotRow, fingerprint string) bool {
	if !w.hermesVendorPlugin(evt) {
		return false
	}
	if _, seen := w.hermesVendorNoted.LoadOrStore(evt.Path, struct{}{}); !seen {
		w.logHermesVendorPlugin(evt, string(evt.Type))
	}
	if snap != nil && (baseline == nil || baseline.ScannerFingerprint != fingerprint) {
		scanID := ""
		if baseline != nil {
			scanID = baseline.ScanID
		}
		w.persistSnapshot(evt, snap, scanID, fingerprint)
	}
	return true
}

// hermesBaselineOwesAdmission reports a shipped plugin whose baseline holds no
// scan and whose bytes are not vendor content: the baseline was recorded for
// vendor bytes (or after a failed scan), so changed bytes, and bytes that
// differ from the digest although the snapshot hash is the same, are admitted
// and refused when HIGH, not scanned as a first sight. The decision reads the
// plugin again; nothing stored says it is vendor content.
func (w *InstallWatcher) hermesBaselineOwesAdmission(evt InstallEvent, baseline *audit.SnapshotRow, snap *TargetSnapshot) bool {
	if baseline == nil || baseline.ScanID != "" || snap == nil {
		return false
	}
	if _, shipped := w.hermesShippedPlugin(evt); !shipped {
		return false
	}
	return baseline.ContentHash != snap.ContentHash || !w.hermesVendorPlugin(evt)
}

// logHermesVendorPlugin records the vendor-content verdict of a shipped plugin.
func (w *InstallWatcher) logHermesVendorPlugin(evt InstallEvent, targetType string) {
	_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
		fmt.Sprintf("type=%s reason=%s", targetType, hermesVendorPluginReason))
}

// hermesPluginTreeDigest reads every regular file under path once, through
// one os.Root, and returns the vendor digest of those bytes: the name, size
// and bytes of each file, in lexical walk order. Links, devices, special
// mode bits and oversize trees make the tree unverifiable. Python bytecode
// caches, which Hermes writes beside its plugins at run time, are left out,
// as the plugin scanner leaves them out, except a file a manifest declares as
// an entrypoint (hermesDeclaredFiles), which the scanner reads and which is
// hashed like any other file; a native payload inside a cache makes the tree
// unverifiable, as the scanner reports it.
func hermesPluginTreeDigest(path string, load hermesManifestLoader) (string, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return "", err
	}
	defer root.Close()
	digest := sha256.New()
	declared := &hermesDeclaredSet{root: root, dir: path, load: load}
	entries, total := 0, int64(0)
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		if entries++; entries > hermesPluginMaxEntries {
			return errHermesPluginUnverified
		}
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			return errHermesPluginUnverified
		case entry.IsDir():
			return nil
		case !entry.Type().IsRegular():
			return errHermesPluginUnverified
		}
		if inBytecodeCache(name) {
			// Hermes writes these at run time, so they are not hashed; but
			// the plugin scanner audits them for native payloads, which a
			// digest match must not vouch for, and reads one a manifest
			// declares, which it must bind.
			if hermesNativePayload(name) {
				return errHermesPluginUnverified
			}
			info, err := root.Lstat(name)
			if err != nil {
				return err
			}
			if !declared.declares(info) {
				return nil
			}
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
			return errHermesPluginUnverified
		}
		data, err := io.ReadAll(io.LimitReader(file, hermesPluginMaxFileBytes+1))
		if err != nil {
			return err
		}
		if len(data) > hermesPluginMaxFileBytes || total+int64(len(data)) > hermesPluginMaxTreeBytes {
			return errHermesPluginUnverified
		}
		total += int64(len(data))
		fmt.Fprintf(digest, "%s\x00%d\x00", name, len(data))
		_, _ = digest.Write(data)
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// hermesNativeExtensions are the extensions the plugin scanner reports as a
// native payload hidden in a folder it skips (BINARY_EXTENSIONS in
// plugin_scanner/rules.py; TestHermesNativeExtensionsMatchScanner keeps them
// equal).
var hermesNativeExtensions = map[string]bool{
	".exe": true, ".so": true, ".dylib": true, ".wasm": true, ".dll": true, ".node": true,
}

// hermesNativePayload reports a file the plugin scanner treats as a native
// payload by its name.
func hermesNativePayload(name string) bool {
	base := name[strings.LastIndex(name, "/")+1:]
	dot := strings.LastIndex(base, ".")
	return dot >= 0 && hermesNativeExtensions[strings.ToLower(base[dot:])]
}

// inBytecodeCache reports a file inside a __pycache__ folder.
func inBytecodeCache(name string) bool {
	parts := strings.Split(name, "/")
	return slices.Contains(parts[:len(parts)-1], "__pycache__")
}

// hermesManifestFiles are the manifests the plugin scanner reads for declared
// entrypoints (_MANIFEST_CANDIDATES in plugin_scanner/scanner.py;
// TestHermesManifestFilesMatchScanner keeps them equal).
var hermesManifestFiles = []string{
	"package.json", "manifest.json", "plugin.json", "openclaw.plugin.json",
	".claude-plugin/plugin.json", ".codex-plugin/plugin.json", ".cursor-plugin/plugin.json",
	"plugin.yaml", "plugin.yml",
}

// hermesManifestMaxEntrypoints bounds the entrypoint strings hermesDeclaredFiles
// resolves.
const hermesManifestMaxEntrypoints = 10000

// hermesDeclaredFiles returns the files in root that a plugin manifest names
// as a runtime entrypoint, wherever they are. The plugin scanner reads each
// declared entrypoint whatever folder it is in (resolve_entrypoint_files), so
// a declared file in a bytecode cache is scanner-readable. The manifests are
// read once through root (the open folder dir) and handed, as bytes, to load,
// which is the plugin scanner own reader of them. Every entrypoint of every
// manifest the scanner reads is resolved, so a manifest that is shadowed by
// another still binds its files. An entrypoint is resolved as a path under
// dir, as the scanner does, with links followed and with the name taken both
// as written and with its dot segments folded, so the set is a superset of
// what the scanner opens. every is true when every file counts as declared: a
// manifest exists that cannot be read, or the scanner has no answer for these
// manifest bytes under a strict or managed policy. When it has none under a policy that fails open
// (a per-user default or permissive tier), nothing is declared, so an ordinary
// generated cache file is not rejected for an outage of the reader; the policy
// has warned and audited it. An earlier answer of the scanner for the same
// manifest bytes is applied exactly (hermesManifestPolicy).
func hermesDeclaredFiles(root *os.Root, dir string, load hermesManifestLoader) (declared []fs.FileInfo, every bool) {
	manifests := map[string][]byte{}
	for _, name := range hermesManifestFiles {
		rel := filepath.FromSlash(name)
		info, err := root.Lstat(rel)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			continue
		}
		if err != nil {
			return nil, true
		}
		if !info.Mode().IsRegular() {
			// The scanner reads a manifest only when it is a plain file.
			continue
		}
		file, err := root.Open(rel)
		if err != nil {
			return nil, true
		}
		data, err := io.ReadAll(io.LimitReader(file, hermesPluginMaxFileBytes+1))
		file.Close()
		if err != nil || len(data) > hermesPluginMaxFileBytes {
			return nil, true
		}
		manifests[name] = data
	}
	if len(manifests) == 0 {
		return nil, false
	}
	entrypoints, err := load(manifests)
	if errors.Is(err, errHermesManifestFailOpen) {
		// No answer, now or earlier, for these manifest bytes: what they
		// declare is unknown, and the policy lets ordinary writes continue.
		return nil, false
	}
	if err != nil || len(entrypoints) > hermesManifestMaxEntrypoints {
		return nil, true
	}
	for _, value := range entrypoints {
		value = strings.TrimLeft(strings.TrimSpace(value), "/\\")
		if value == "" || len(value) > 4096 || strings.ContainsRune(value, 0) {
			continue
		}
		written := dir + string(os.PathSeparator) + filepath.FromSlash(value)
		for _, candidate := range []string{written, filepath.Clean(written)} {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				declared = append(declared, info)
			}
		}
	}
	return declared, false
}

// hermesDeclaredSet answers whether a manifest declares a file, reading the
// manifests of one plugin root at most once.
type hermesDeclaredSet struct {
	root   *os.Root
	dir    string
	load   hermesManifestLoader
	loaded bool
	files  []fs.FileInfo
	every  bool
}

// declares reports whether a manifest names the file described by info, or
// may name it because a manifest could not be read (see hermesDeclaredFiles).
func (s *hermesDeclaredSet) declares(info fs.FileInfo) bool {
	if !s.loaded {
		s.files, s.every = hermesDeclaredFiles(s.root, s.dir, s.load)
		s.loaded = true
	}
	return s.every || slices.ContainsFunc(s.files, func(d fs.FileInfo) bool { return os.SameFile(info, d) })
}

// skippedTreeHash describes what SnapshotTarget leaves out of a plugin, as
// one hash (empty when there is nothing): every link, and every file in a
// folder the snapshot skips (.git, node_modules, __pycache__, .venv, venv)
// except a bytecode cache file that has no native extension and that no
// manifest declares (hermesDeclaredFiles), which Hermes writes at run time
// and the plugin scanner ignores. The plugin scanner reports a native file in
// those folders and reads a declared entrypoint there, so a shipped plugin
// folds this hash into its content hash: a change anywhere in the tree
// reaches a scan, whatever was admitted before. Every
// file the scanner can read (up to hermesScannerReadBytes) is hashed, however
// much skipped data precedes it, and so is a declared entrypoint of any size;
// another larger file is described by name and size, since the scanner reads
// none of its bytes. A tree over
// hermesSkippedTreeMaxBytes has no stable hash. An entry that cannot be read
// is recorded as unreadable, so it also differs from a clean read.
func skippedTreeHash(root string, load hermesManifestLoader) string {
	var entries []string
	read := int64(0)
	// declaredEntrypoint reports a bytecode cache file the scanner can read
	// because a manifest declares it; the manifests are read at most once. A
	// plugin folder that cannot be opened has every cache file declared.
	declared := &hermesDeclaredSet{loaded: true, every: true}
	if rootHandle, err := os.OpenRoot(root); err == nil {
		defer rootHandle.Close()
		declared = &hermesDeclaredSet{root: rootHandle, dir: root, load: load}
	}
	declaredEntrypoint := func(file string) bool {
		info, err := os.Lstat(file)
		return err != nil || declared.declares(info)
	}
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil || rel == "." {
			return nil
		}
		name := filepath.ToSlash(rel)
		if walkErr != nil {
			entries = append(entries, "unreadable:"+name)
			return nil
		}
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			target, _ := os.Readlink(path)
			// The resolution is bound as the plugin snapshot binds it
			// (linkResolution), so a retargeted link is a change.
			entries = append(entries, "link:"+name+"->"+target+":resolves:"+linkResolution(path, target))
		case entry.IsDir():
		case entry.Type().IsRegular() && !snapshotSkipsPath(name):
		case inBytecodeCache(name) && !hermesNativePayload(name) && !declaredEntrypoint(path):
		case !entry.Type().IsRegular():
			// A special entry is part of the full-tree plugin snapshot.
			entries = append(entries, "special:"+name+":"+entry.Type().String())
		default:
			info, err := entry.Info()
			if err != nil {
				entries = append(entries, "unreadable:"+name)
				return nil
			}
			detail := fmt.Sprintf("%d", info.Size())
			// A file the scanner reads is hashed: any file up to its read
			// limit, and a declared entrypoint whatever its size, so a
			// same-size edit of a declared file is a change.
			if info.Size() <= hermesScannerReadBytes || declaredEntrypoint(path) {
				if read += info.Size(); read > hermesSkippedTreeMaxBytes {
					entries = append(entries, fmt.Sprintf("unbounded:%d", time.Now().UnixNano()))
					return fs.SkipAll
				}
				if sum, err := hashFile(path); err == nil {
					detail += ":" + sum
				} else {
					detail += ":unreadable"
				}
			}
			entries = append(entries, "file:"+name+":"+detail)
		}
		return nil
	})
	if len(entries) == 0 {
		return ""
	}
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(sum[:])
}

// snapshotSkipsPath reports a file inside a folder SnapshotTarget does not
// hash.
func snapshotSkipsPath(name string) bool {
	parts := strings.Split(name, "/")
	for _, part := range parts[:len(parts)-1] {
		if snapshotSkippedDir(part) {
			return true
		}
	}
	return false
}
