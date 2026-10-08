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

package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// codeGuardSkillSignatures are the SkillTreeSignature values of the CodeGuard
// skill trees DefenseClaw ships (skills/codeguard): the current one and those
// of earlier releases, which cli/defenseclaw/codeguard_skill.py also lists.
// TestVerifyFirstPartyTrustsOnlyTheShippedCodeGuard fails when the skill
// changes and this list does not.
var codeGuardSkillSignatures = map[string]bool{
	"8915cd55f76380bb35694d0007f95deeeb1e16c8012d3b09c748a67bef27e698": true, // 1.0.2 and later
	"596b1fd2fbfbf050af7a679d80d6151ad53c16df44a975859a43cf591b8e42d9": true, // 1.0.0, 1.0.1
}

// VerifyFirstParty drops the first-party entries for DefenseClaw's own asset
// names when the asset is not DefenseClaw's own content (GAP-0419). A folder
// in a skills or plugins folder is written by whatever the user installs, so
// the name alone must not switch the scan off: an entry named codeguard for a
// skill matches only a byte-identical copy of the shipped CodeGuard skill,
// and an entry named defenseclaw for a plugin matches nothing here, because
// the watcher recognizes DefenseClaw's own plugin by its bytes before
// admission. Other first-party entries keep their name and location match.
// The Secure Client admission is not passed through this.
func (in *AdmissionInput) VerifyFirstParty() {
	if in == nil || in.Admission == nil || len(in.Admission.FirstPartyAllowList) == 0 {
		return
	}
	kept := make([]CompiledFirstParty, 0, len(in.Admission.FirstPartyAllowList))
	for _, entry := range in.Admission.FirstPartyAllowList {
		if entry.Name == in.TargetName && !ownFirstPartyContent(in.TargetType, entry.Name, in.Path) {
			continue
		}
		kept = append(kept, entry)
	}
	adm := *in.Admission
	adm.FirstPartyAllowList = kept
	in.Admission = &adm
}

// ownFirstPartyContent reports whether a first-party entry may trust the
// asset at path: always for names DefenseClaw does not ship, only for the
// shipped content otherwise.
func ownFirstPartyContent(targetType, name, path string) bool {
	switch {
	case strings.EqualFold(targetType, "skill") && name == "codeguard":
		signature, err := SkillTreeSignature(path)
		return err == nil && codeGuardSkillSignatures[signature]
	case strings.EqualFold(targetType, "plugin") && name == "defenseclaw":
		return false
	}
	return true
}

const (
	maxSkillTreeEntries   = 1024
	maxSkillTreeFileBytes = 4 << 20
	maxSkillTreeBytes     = 16 << 20
)

// SkillTreeSignature is the content signature of the folder at root, the
// one cli/defenseclaw/codeguard_skill.py computes (_dir_signature with
// skip_bytecode): SHA-256 over each file's slash-separated relative path and
// its content with line endings normalized to LF and leading and trailing
// whitespace removed, in path order, leaving out __pycache__ folders and .pyc
// files. A link anywhere in the tree is refused.
func SkillTreeSignature(root string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("policy: %s is not a folder", root)
	}

	// Only a small, byte-identical shipped skill can bypass the scan.
	// Bound directory enumeration and bytes read before the scan timer starts.
	sum := sha256.New()
	entries := 0
	var totalBytes int64
	var walk func(string) error
	walk = func(dir string) error {
		folder, err := os.Open(dir)
		if err != nil {
			return err
		}
		limit := maxSkillTreeEntries - entries
		names, readErr := folder.Readdirnames(limit + 1)
		closeErr := folder.Close()
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(names) > limit {
			return fmt.Errorf("policy: skill tree has too many entries")
		}
		sort.Strings(names)
		for _, name := range names {
			path := filepath.Join(dir, name)
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("policy: %s is a link", path)
			}
			entries++
			if entries > maxSkillTreeEntries {
				return fmt.Errorf("policy: skill tree has too many entries")
			}
			if info.IsDir() && name == "__pycache__" {
				continue
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return fmt.Errorf("policy: %s is not a regular file", path)
			}
			if !info.IsDir() && strings.HasSuffix(name, ".pyc") {
				continue
			}
			if info.IsDir() {
				if err := walk(path); err != nil {
					return err
				}
				continue
			}
			remaining := min(int64(maxSkillTreeFileBytes), int64(maxSkillTreeBytes)-totalBytes)
			if info.Size() > remaining {
				return fmt.Errorf("policy: %s exceeds skill signature size limit", path)
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			data, readErr := io.ReadAll(io.LimitReader(file, remaining+1))
			closeErr := file.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			if int64(len(data)) > remaining {
				return fmt.Errorf("policy: %s exceeds skill signature size limit", path)
			}
			totalBytes += int64(len(data))
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
			data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
			sum.Write([]byte(filepath.ToSlash(rel)))
			sum.Write([]byte{0})
			sum.Write(bytes.Trim(data, " \t\n\r\v\f"))
			sum.Write([]byte{0})
		}
		return nil
	}
	if err := walk(root); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
