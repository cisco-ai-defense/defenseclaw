// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/substrate/skilldigest"
)

// SkillFolderDigest is the content digest the build records for an admitted
// skill folder (internal/substrate/skilldigest): the gateway trusts a folder
// that is still exactly this content without scanning it (GAP-0164).
func SkillFolderDigest(files map[string][]byte) string { return skilldigest.Digest(files) }

// localSkillDigest is SkillFolderDigest over a materialized folder.
func localSkillDigest(dir string) string {
	files := map[string][]byte{}
	tooMany := false
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if len(files) >= skilldigest.MaxFiles {
			tooMany = true
			return filepath.SkipAll
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil || tooMany {
		return ""
	}
	return SkillFolderDigest(files)
}
