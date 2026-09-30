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

package image

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

// contextEpoch is the fixed modification time of every context entry, so
// the tar bytes depend only on names, modes and content.
var contextEpoch = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

// WriteTar streams the build context as a deterministic tar: entries sorted
// by name, parent directories emitted once (root, 0755), file modes and
// in-image owners in the headers, fixed whole-second timestamps and no user
// or group names (the writer picks USTAR, or PAX for large ids). The same
// context always produces the same bytes.
func (c *Context) WriteTar(w io.Writer) error {
	return writeContextTar(w, c.Files)
}

// writeContextTar streams context entries as WriteTar describes.
func writeContextTar(w io.Writer, entryFiles []ContextFile) error {
	files := append([]ContextFile(nil), entryFiles...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	dirs := map[string]bool{}
	for _, f := range files {
		for dir := path.Dir(f.Name); dir != "." && dir != "/"; dir = path.Dir(dir) {
			dirs[dir] = true
		}
	}
	type entry struct {
		name string
		dir  bool
		file ContextFile
	}
	entries := make([]entry, 0, len(files)+len(dirs))
	for dir := range dirs {
		entries = append(entries, entry{name: dir + "/", dir: true})
	}
	for _, f := range files {
		if f.Name == "" || strings.HasPrefix(f.Name, "/") || path.Clean(f.Name) != f.Name || strings.HasPrefix(f.Name, "..") {
			return fmt.Errorf("openshell image: invalid context entry %q", f.Name)
		}
		entries = append(entries, entry{name: f.Name, file: f})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	tw := tar.NewWriter(w)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:    e.name,
			ModTime: contextEpoch,
			Uid:     0,
			Gid:     0,
		}
		if e.dir {
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0o755
		} else {
			hdr.Typeflag = tar.TypeReg
			hdr.Mode = int64(e.file.Mode.Perm())
			hdr.Uid = e.file.UID
			hdr.Gid = e.file.GID
			hdr.Size = int64(len(e.file.Data))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("openshell image: tar header %s: %w", e.name, err)
		}
		if !e.dir {
			if _, err := tw.Write(e.file.Data); err != nil {
				return fmt.Errorf("openshell image: tar body %s: %w", e.name, err)
			}
		}
	}
	return tw.Close()
}

// Tar returns the build context bytes.
func (c *Context) Tar() ([]byte, error) {
	var buf bytes.Buffer
	if err := c.WriteTar(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
