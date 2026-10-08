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
	"io/fs"
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
	type entry struct {
		rel     string
		content []byte
	}
	var entries []entry
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("policy: %s is a link", path)
		}
		if d.IsDir() {
			if path != root && d.Name() == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("policy: %s is not a regular file", path)
		}
		if strings.HasSuffix(d.Name(), ".pyc") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
		entries = append(entries, entry{rel: filepath.ToSlash(rel), content: bytes.Trim(data, " \t\n\r\v\f")})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	sum := sha256.New()
	for _, e := range entries {
		sum.Write([]byte(e.rel))
		sum.Write([]byte{0})
		sum.Write(e.content)
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
