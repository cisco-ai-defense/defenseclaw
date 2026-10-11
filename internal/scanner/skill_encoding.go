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

package scanner

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unicode/utf16"
)

// Bounds on the copy stageUTF16Skill makes.
const (
	utf16StageMaxBytes = 64 << 20
	utf16StageMaxFiles = 2000
)

// DecodeSkillText returns raw as UTF-8 text: a UTF-8 byte order mark is
// dropped and UTF-16 with a byte order mark is decoded. Windows editors save
// SKILL.md that way (Notepad "Unicode", PowerShell 5.1 redirection).
func DecodeSkillText(raw []byte) ([]byte, bool) {
	switch {
	case bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}):
		return raw[3:], true
	case bytes.HasPrefix(raw, []byte{0xFF, 0xFE}), bytes.HasPrefix(raw, []byte{0xFE, 0xFF}):
		little := raw[0] == 0xFF
		body := raw[2:]
		units := make([]uint16, 0, len(body)/2)
		for i := 0; i+1 < len(body); i += 2 {
			if little {
				units = append(units, uint16(body[i])|uint16(body[i+1])<<8)
			} else {
				units = append(units, uint16(body[i])<<8|uint16(body[i+1]))
			}
		}
		return []byte(string(utf16.Decode(units))), true
	}
	return raw, false
}

// stageUTF16Skill returns a copy of the skill folder at target whose SKILL.md
// is re-encoded as UTF-8 when it was saved as UTF-16, and a cleanup. The
// scanner refused such a skill ("skill.md contains null bytes") and the
// watcher quarantined it with the reason only in gateway.log (GAP-0417). The
// copy holds regular files only and is bounded; otherwise, and for any other
// SKILL.md, target is scanned as it is.
func stageUTF16Skill(target string) (string, func(), error) {
	noop := func() {}
	manifest := ""
	for _, name := range []string{"SKILL.md", "skill.md"} {
		if info, err := os.Lstat(filepath.Join(target, name)); err == nil && info.Mode().IsRegular() {
			manifest = name
			break
		}
	}
	if manifest == "" {
		return target, noop, nil
	}
	head := make([]byte, 2)
	f, err := os.Open(filepath.Join(target, manifest))
	if err != nil {
		return target, noop, nil
	}
	n, _ := f.Read(head)
	_ = f.Close()
	if n < 2 || !(head[0] == 0xFF && head[1] == 0xFE || head[0] == 0xFE && head[1] == 0xFF) {
		return target, noop, nil
	}
	dir, err := os.MkdirTemp("", "dc-skill-utf8-")
	if err != nil {
		return "", noop, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	stage := filepath.Join(dir, filepath.Base(target))
	var total int64
	files := 0
	err = filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(target, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(stage, rel)
		if d.IsDir() {
			return os.MkdirAll(dest, 0o700)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		files++
		total += info.Size()
		if files > utf16StageMaxFiles || total > utf16StageMaxBytes {
			return fmt.Errorf("the skill is too large to re-encode")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if rel == manifest {
			data, _ = DecodeSkillText(data)
		}
		return os.WriteFile(dest, data, 0o600)
	})
	if err != nil {
		cleanup()
		return "", noop, fmt.Errorf("scanner: %s is saved as UTF-16 and could not be re-encoded for the scan (%v); save it as UTF-8", manifest, err)
	}
	return stage, cleanup, nil
}
