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

// Bounds on the copy stageSkill makes.
const (
	skillStageMaxBytes = 64 << 20
	skillStageMaxFiles = 2000
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

// stageSkill returns the folder skill-scanner reads for the skill at
// target, the OS metadata files it leaves out and a cleanup. That folder is
// target itself unless the skill needs a scan copy:
//   - a SKILL.md saved as UTF-16 is re-encoded as UTF-8: the scanner refused
//     it ("skill.md contains null bytes") and the watcher quarantined the
//     skill with the reason only in gateway.log (GAP-0417);
//   - OS metadata files that pass their format check (skill_metadata.go) are
//     left out and reported as INFO findings, and a UTF-16 desktop.ini is
//     re-encoded as UTF-8: the scanner scored them as opaque binaries and
//     the watcher quarantined a plain-text skill in action mode (GAP-0106).
//
// The copy holds regular files only and is bounded. A UTF-16 SKILL.md that
// cannot be copied fails the scan; any other skill is then scanned as it
// is, metadata files included.
func stageSkill(target string) (string, []metadataSidecar, func(), error) {
	noop := func() {}
	manifest := ""
	for _, name := range []string{"SKILL.md", "skill.md"} {
		if info, err := os.Lstat(filepath.Join(target, name)); err == nil && info.Mode().IsRegular() {
			manifest = name
			break
		}
	}
	utf16Manifest := manifest != "" && hasUTF16BOM(filepath.Join(target, manifest))
	plan, err := planSkillStage(target)
	if err == nil && !utf16Manifest && len(plan.metadata) == 0 && len(plan.transcode) == 0 {
		return target, nil, noop, nil
	}
	if err == nil {
		var stage string
		var cleanup func()
		stage, cleanup, err = copySkillStage(target, manifest, utf16Manifest, plan)
		if err == nil {
			return stage, plan.metadata, cleanup, nil
		}
	}
	if !utf16Manifest {
		return target, nil, noop, nil
	}
	return "", nil, noop, fmt.Errorf("scanner: %s is saved as UTF-16 and could not be re-encoded for the scan (%v); save it as UTF-8", manifest, err)
}

func hasUTF16BOM(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 2)
	n, _ := f.Read(head)
	return n == 2 && (head[0] == 0xFF && head[1] == 0xFE || head[0] == 0xFE && head[1] == 0xFF)
}

// skillStagePlan is what a scan copy of a skill changes.
type skillStagePlan struct {
	metadata  []metadataSidecar // left out of the copy
	skip      map[string]bool   // rel paths of metadata
	transcode map[string]bool   // rel paths re-encoded as UTF-8
}

// planSkillStage walks the skill once (bounded) and finds its OS metadata
// files; an error means the skill cannot be copied.
func planSkillStage(target string) (skillStagePlan, error) {
	plan := skillStagePlan{skip: map[string]bool{}, transcode: map[string]bool{}}
	var total int64
	files := 0
	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(target, path)
		if err != nil {
			return err
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
		if files > skillStageMaxFiles || total > skillStageMaxBytes {
			return fmt.Errorf("the skill is too large to re-encode")
		}
		kind, transcode := classifySkillFile(target, rel, info.Size())
		switch {
		case kind != "":
			plan.skip[rel] = true
			plan.metadata = append(plan.metadata, metadataSidecar{Rel: filepath.ToSlash(rel), Kind: kind})
		case transcode:
			plan.transcode[rel] = true
		}
		return nil
	})
	return plan, err
}

// copySkillStage writes the scan copy of target that plan describes.
func copySkillStage(target, manifest string, utf16Manifest bool, plan skillStagePlan) (string, func(), error) {
	noop := func() {}
	dir, err := os.MkdirTemp("", "dc-skill-scan-")
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
		if plan.skip[rel] {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		files++
		total += info.Size()
		if files > skillStageMaxFiles || total > skillStageMaxBytes {
			return fmt.Errorf("the skill is too large to re-encode")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if rel == manifest && utf16Manifest || plan.transcode[rel] {
			data, _ = DecodeSkillText(data)
		}
		return os.WriteFile(dest, data, 0o600)
	})
	if err != nil {
		cleanup()
		return "", noop, err
	}
	return stage, cleanup, nil
}
