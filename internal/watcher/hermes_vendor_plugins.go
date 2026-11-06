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
	"strings"
)

// Hermes ships plugins in its checkout (hermes-agent/plugins). A shipped
// plugin whose bytes match the digest DefenseClaw pins for that Hermes
// release is vendor code the account did not install, so the rescan leaves
// it out, as it leaves out the digest-pinned Hermes bundled skills. The
// decision rests only on the bytes read once by hermesPluginTreeDigest: no
// scanner re-opens the tree by name afterwards, so nothing read later can be
// covered by it. A plugin that differs from its digest in any byte, file or
// link is enumerated and scanned as any other plugin, under hermes.

const (
	hermesPluginMaxEntries   = 4096
	hermesPluginMaxFileBytes = 8 << 20
	hermesPluginMaxTreeBytes = 64 << 20
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

// hermesVendorPlugin reports whether the plugin at path, enumerated under
// the registered Hermes plugin root dir, holds exactly the bytes Hermes
// shipped. Secure Client keeps its existing enumeration.
func (w *InstallWatcher) hermesVendorPlugin(dir, path string) bool {
	if w.secureClientActive() || w.connectorForPath(dir) != "hermes" || !hermesBundledPluginRoot(dir) {
		return false
	}
	relative, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	if err != nil || !filepath.IsLocal(relative) {
		return false
	}
	want := hermesPluginVendorDigests[filepath.ToSlash(relative)]
	if want == "" {
		return false
	}
	got, err := hermesPluginTreeDigest(path)
	return err == nil && got == want
}

// hermesPluginTreeDigest hashes the name, size and bytes of every regular
// file under path, opening each through one os.Root and reading it once.
// Walk order is lexical, so the digest is stable. Links, devices, special
// mode bits and oversize trees make the tree unverifiable. Python bytecode
// caches, which Hermes writes beside its plugins at run time, are left out,
// as the plugin scanner leaves them out of a scan.
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
			if entry.Name() == "__pycache__" {
				return fs.SkipDir
			}
			return nil
		case !entry.Type().IsRegular():
			return errHermesPluginUnverified
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
