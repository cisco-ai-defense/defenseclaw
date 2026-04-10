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

package signing

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// HashDirectory computes a deterministic SHA-256 digest over every file in dir.
// Files are sorted by their path relative to dir. Each entry contributes
// "relpath:sha256(content)\n" to the final hash. The signature file itself
// is excluded so that the hash is stable before and after signing.
func HashDirectory(dir string) (string, error) {
	type entry struct {
		rel  string
		hash string
	}

	var entries []entry

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("signing: rel path: %w", err)
		}
		rel = filepath.ToSlash(rel)

		if rel == SignatureFileName {
			return nil
		}

		h, err := hashFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{rel: rel, hash: h})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("signing: walk %s: %w", dir, err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	manifest := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(manifest, "%s:%s\n", e.rel, e.hash)
	}
	return hex.EncodeToString(manifest.Sum(nil)), nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("signing: open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("signing: read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
