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

package enforce

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type SkillEnforcer struct {
	quarantineDir string
}

func NewSkillEnforcer(quarantineDir string) *SkillEnforcer {
	return &SkillEnforcer{quarantineDir: quarantineDir}
}

func (e *SkillEnforcer) Quarantine(skillPath string) (string, error) {
	info, err := os.Stat(skillPath)
	if err != nil {
		return "", fmt.Errorf("enforce: skill path %q: %w", skillPath, err)
	}

	name := filepath.Base(skillPath)
	dest := filepath.Join(e.quarantineDir, "skills", name)

	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return "", fmt.Errorf("enforce: create quarantine dir: %w", err)
	}

	if info.IsDir() {
		if err := copyDir(skillPath, dest); err != nil {
			return "", fmt.Errorf("enforce: copy skill to quarantine: %w", err)
		}
		if err := os.RemoveAll(skillPath); err != nil {
			return dest, fmt.Errorf("enforce: remove original skill: %w", err)
		}
	} else {
		if err := copyFile(skillPath, dest); err != nil {
			return "", fmt.Errorf("enforce: copy skill to quarantine: %w", err)
		}
		if err := os.Remove(skillPath); err != nil {
			return dest, fmt.Errorf("enforce: remove original skill: %w", err)
		}
	}

	return dest, nil
}

func (e *SkillEnforcer) Restore(skillName, originalPath string) error {
	base := filepath.Base(skillName)
	src := filepath.Join(e.quarantineDir, "skills", base)
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("enforce: quarantined skill %q not found: %w", base, err)
	}

	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("enforce: stat quarantined skill: %w", err)
	}

	if info.IsDir() {
		if err := copyDir(src, originalPath); err != nil {
			return fmt.Errorf("enforce: restore skill: %w", err)
		}
		return os.RemoveAll(src)
	}

	if err := copyFile(src, originalPath); err != nil {
		return fmt.Errorf("enforce: restore skill: %w", err)
	}
	return os.Remove(src)
}

func (e *SkillEnforcer) IsQuarantined(skillName string) bool {
	base := filepath.Base(skillName)
	path := filepath.Join(e.quarantineDir, "skills", base)
	_, err := os.Stat(path)
	return err == nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(rel, "..") {
			return fmt.Errorf("enforce: path traversal detected: %s", rel)
		}

		target := filepath.Join(dst, rel)

		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		return copyFile(path, target)
	})
}
