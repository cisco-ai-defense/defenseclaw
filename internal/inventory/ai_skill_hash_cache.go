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

package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A skill folder that has not changed since the last scan keeps its hash
// without its files being read again (GAP-1816). "Not changed" is the
// metadata of every entry the hash covers: name, type, size, modification
// time and, outside Windows, the inode change time, inode, link count and
// owner, none of which a user can set back after a write. Windows keeps no
// such time a user cannot set, so a managed Windows scan does not use the
// cache (skillChangeStampTamperEvident); an OSS Windows install does, and
// reads every folder again at least once per skillHashCacheMaxAge.
const (
	skillHashCacheMaxAge = 24 * time.Hour
	// maxSkillHashCacheFolders bounds the memory of the cache; a scan that
	// would add more starts it again.
	maxSkillHashCacheFolders = maxSkillManifestFolders
)

// skillHashCacheEntry is what hashSkillFolder found in one folder.
type skillHashCacheEntry struct {
	signature    string
	hashedAt     time.Time
	hash, status string
	front        skillFrontMatter
	manifestHash string
	manifestSize int64
}

// fresh reports whether the entry can stand in for reading the folder now.
func (entry skillHashCacheEntry) fresh(signature string, now time.Time) bool {
	return signature != "" && entry.signature == signature &&
		!now.Before(entry.hashedAt) && now.Sub(entry.hashedAt) < skillHashCacheMaxAge
}

// skillFolderSignature fingerprints the metadata of every entry
// hashSkillFolder would walk below root, without reading a file. It reports
// false wherever hashSkillFolder would not report an ok hash from the walk
// alone (a link or irregular root, too many entries, too deep, a walk error),
// so those folders are always hashed again.
func skillFolderSignature(root string) (string, bool) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return "", false
	}
	digest := sha256.New()
	writeSkillEntrySignature(digest, ".", root, info)
	entries := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if entries++; entries > maxSkillEntries {
			return errSkillTooLarge
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			switch {
			case entry.Name() == ".git":
				return fs.SkipDir
			case strings.Count(rel, "/") >= maxSkillDepth:
				return errSkillTooLarge
			}
		}
		// The entry's own record, not entry.Info(): on Windows that is the
		// parent folder's listing, which NTFS brings up to date lazily (a
		// subfolder keeps the write time it had before its last file was
		// added until the folder is next opened), so an unchanged folder
		// looked changed on the next scan and a changed one could look
		// unchanged. Elsewhere entry.Info() is this same lstat.
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		writeSkillEntrySignature(digest, rel, path, info)
		return nil
	})
	if err != nil {
		return "", false
	}
	return hex.EncodeToString(digest.Sum(nil)), true
}

func writeSkillEntrySignature(w io.Writer, rel, path string, info fs.FileInfo) {
	_, _ = fmt.Fprintf(w, "%q\x00%d\x00%d\x00%d\x00%s\n",
		rel, uint32(info.Mode()), info.Size(), info.ModTime().UnixNano(), skillEntryChangeStamp(path, info))
}
