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

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// Hermes ships plugins in its checkout (hermes-agent/plugins). A shipped
// plugin whose bytes, read in the scan that decides it, match the digest
// DefenseClaw pins for that Hermes release is vendor code the account did not
// install, so it is reported as informational vendor content and not scanned,
// as the digest-pinned Hermes bundled skills are not. Nothing about that
// decision is stored: no baseline carries a mark, and every scan reads the
// plugin again. A plugin that differs from its digest in any byte, file or
// link is scanned as any other, under hermes. Change detection for a shipped
// plugin covers the folders the snapshot leaves out (skippedTreeHash), so a
// later change anywhere in the tree reaches a scan whatever was admitted
// before. The manifest only grows: an unchanged plugin whose release digest
// was dropped would be scanned again.

const (
	hermesPluginMaxEntries   = 4096
	hermesPluginMaxFileBytes = 8 << 20
	hermesPluginMaxTreeBytes = 64 << 20

	// hermesVendorPluginReason is the admission reason for a shipped plugin
	// whose bytes match their pinned digest.
	hermesVendorPluginReason = "hermes shipped plugin matches its pinned vendor digest"
)

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
	digest, err := hermesPluginTreeDigest(filepath.Clean(evt.Path))
	if err != nil || digest != hermesPluginVendorDigests[name] {
		return false
	}
	return true
}

// rescanHermesVendorPlugin is the rescan side of hermesVendorPlugin: it
// reports the plugin as informational vendor content, once per process, and
// tells the caller to leave it unscanned.
func (w *InstallWatcher) rescanHermesVendorPlugin(evt InstallEvent) bool {
	if !w.hermesVendorPlugin(evt) {
		return false
	}
	if _, seen := w.hermesVendorNoted.LoadOrStore(evt.Path, struct{}{}); !seen {
		w.logHermesVendorPlugin(evt, string(evt.Type))
	}
	return true
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
// as the plugin scanner leaves them out; a native payload inside one makes
// the tree unverifiable, as the scanner reports it.
func hermesPluginTreeDigest(path string) (string, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return "", err
	}
	defer root.Close()
	digest := sha256.New()
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
			// digest match must not vouch for.
			if hermesNativePayload(name) {
				return errHermesPluginUnverified
			}
			return nil
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

// skippedTreeHash describes what SnapshotTarget leaves out of a plugin, as
// one hash (empty when there is nothing): every link, and every file in a
// folder the snapshot skips (.git, node_modules, __pycache__, .venv, venv)
// except a bytecode cache file without a native extension, which Hermes
// writes at run time and the plugin scanner ignores. The plugin scanner
// reports a native file in those folders, so a shipped plugin folds this hash
// into its content hash: a change anywhere in the tree then reaches a scan,
// whatever was admitted before. Files are hashed up to the tree budget of
// the vendor digest and described by name and size beyond it. An entry that
// cannot be read is recorded as unreadable, so it also differs from a clean
// read.
func skippedTreeHash(root string) string {
	var entries []string
	budget := int64(hermesPluginMaxTreeBytes)
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
			entries = append(entries, "link:"+name+"->"+target)
		case entry.IsDir():
		case !snapshotSkipsPath(name) || inBytecodeCache(name) && !hermesNativePayload(name):
		case !entry.Type().IsRegular():
			entries = append(entries, "special:"+name+":"+entry.Type().String())
		default:
			info, err := entry.Info()
			if err != nil {
				entries = append(entries, "unreadable:"+name)
				return nil
			}
			detail := fmt.Sprintf("%d", info.Size())
			if info.Size() <= budget {
				if sum, err := hashFile(path); err == nil {
					budget -= info.Size()
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
		if snapshotSkipsDir(part) {
			return true
		}
	}
	return false
}
