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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// Hermes ships plugins in its checkout (hermes-agent/plugins). A shipped
// plugin whose bytes match the digest DefenseClaw pins for that Hermes
// release is vendor code the account did not install, so it is not scanned,
// as the digest-pinned Hermes bundled skills are not. The decision is made
// only where a scan would run: in install admission after the block, deny
// and allow decisions, and in the rescan where it would scan. It rests on
// the bytes read once by hermesPluginTreeDigest, and the baseline it records
// is marked with the content hash of those bytes, so a later change is
// admitted as a change to any other plugin is. A plugin that differs from
// its digest in any byte, file or link is scanned as any other, under hermes.
// The manifest only grows: an unchanged plugin whose release digest was
// dropped would be scanned again.

const (
	hermesPluginMaxEntries   = 4096
	hermesPluginMaxFileBytes = 8 << 20
	hermesPluginMaxTreeBytes = 64 << 20

	// hermesVendorPluginReason is the admission reason for a shipped plugin
	// whose bytes match their pinned digest.
	hermesVendorPluginReason = "hermes shipped plugin matches its pinned vendor digest"
	// hermesVendorMark ends the fingerprint of a baseline recorded for a
	// shipped plugin without a scan, followed by the content hash of the
	// bytes that matched the digest.
	hermesVendorMark = "|hermes-vendor:"
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

// hermesVendorPluginContent reads the plugin of evt once and, when it lies
// under a registered Hermes shipped plugin root and those bytes match the
// digest pinned for it, returns their snapshot content hash. Secure Client
// keeps its existing admission and rescan.
func (w *InstallWatcher) hermesVendorPluginContent(evt InstallEvent) (string, bool) {
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
		if err != nil || !filepath.IsLocal(relative) {
			continue
		}
		want := hermesPluginVendorDigests[filepath.ToSlash(relative)]
		if want == "" {
			continue
		}
		digest, content, err := hermesPluginTreeDigest(path)
		if err != nil || digest != want {
			return "", false
		}
		return content, true
	}
	return "", false
}

// rescanHermesVendorPlugin records, in place of a scan, the baseline of a
// shipped plugin whose bytes match their pinned digest and the snapshot
// taken this cycle. It reports false when the plugin needs its scan.
func (w *InstallWatcher) rescanHermesVendorPlugin(evt InstallEvent, snap *TargetSnapshot, baseline *audit.SnapshotRow, fingerprint string) bool {
	content, ok := w.hermesVendorPluginContent(evt)
	if !ok || snap == nil || content != snap.ContentHash {
		return false
	}
	marked := fingerprint + hermesVendorMark + content
	scanID := ""
	if baseline != nil && baseline.ContentHash == content {
		if baseline.ScannerFingerprint == marked {
			return true
		}
		scanID = baseline.ScanID
	}
	w.persistSnapshot(evt, snap, scanID, marked)
	return true
}

// unmarkHermesVendorBaseline returns the baseline without its shipped-plugin
// mark, and whether the plugin owes an admission: a marked baseline never
// had a scan, so content other than the bytes that matched the digest is
// admitted, whatever the scan gating says. The snapshot leaves out folders
// the plugin scanner audits for native payloads, so the plugin must also
// still match its digest, read again, with the same content.
func (w *InstallWatcher) unmarkHermesVendorBaseline(evt InstallEvent, baseline *audit.SnapshotRow, snap *TargetSnapshot) (*audit.SnapshotRow, bool) {
	at := strings.LastIndex(baseline.ScannerFingerprint, hermesVendorMark)
	if at < 0 {
		return baseline, false
	}
	verified := baseline.ScannerFingerprint[at+len(hermesVendorMark):]
	unmarked := *baseline
	unmarked.ScannerFingerprint = baseline.ScannerFingerprint[:at]
	if verified != baseline.ContentHash || snap == nil || snap.ContentHash != verified {
		return &unmarked, true
	}
	content, ok := w.hermesVendorPluginContent(evt)
	return &unmarked, !ok || content != verified
}

// hermesPluginTreeDigest reads every regular file under path once, through
// one os.Root, and returns two hashes of those bytes: the vendor digest (the
// name, size and bytes of each file, in lexical walk order) and the content
// hash SnapshotTarget computes for the same tree. Links, devices, special
// mode bits and oversize trees make the tree unverifiable. Python bytecode
// caches, which Hermes writes beside its plugins at run time, are left out
// of both hashes, as the plugin scanner and the snapshot leave them out; a
// native payload inside one makes the tree unverifiable, as the scanner
// reports it.
func hermesPluginTreeDigest(path string) (string, string, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return "", "", err
	}
	defer root.Close()
	digest := sha256.New()
	var contentEntries []string
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
		if !snapshotSkipsPath(name) {
			sum := sha256.Sum256(data)
			contentEntries = append(contentEntries, filepath.FromSlash(name)+":"+hex.EncodeToString(sum[:]))
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), snapshotContentHash(contentEntries), nil
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
