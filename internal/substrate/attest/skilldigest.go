// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Skill folder digests (substrate-1 GAP-0164). A template build records, for
// each skill folder its scan admitted, a digest of the folder's content as
// the actor kit attaches it (internal/substrate/kit/skills.go: regular files
// up to SkillDigestMaxDepth folders deep, at most SkillDigestMaxFiles). The
// gateway computes the same digest over the files the kit attaches, so a
// folder that is still exactly what the attested build scanned is trusted
// from the attestation and not scanned again; any other folder is scanned.
const (
	SkillDigestMaxFiles = 64
	SkillDigestMaxDepth = 3
)

// SkillFolderDigest digests a skill folder's files: relative slash path to
// content. It is "" when the folder has no files or more than
// SkillDigestMaxFiles, or a file deeper than SkillDigestMaxDepth folders, so
// such a folder is never trusted by digest.
func SkillFolderDigest(files map[string][]byte) string {
	if len(files) == 0 || len(files) > SkillDigestMaxFiles {
		return ""
	}
	names := make([]string, 0, len(files))
	for n := range files {
		if n == "" || strings.HasPrefix(n, "/") || strings.Contains("/"+n+"/", "/../") || strings.Count(n, "/") > SkillDigestMaxDepth {
			return ""
		}
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	h.Write([]byte("defenseclaw skill folder v1\n"))
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		h.Write([]byte(n + "\x00" + hex.EncodeToString(sum[:]) + "\n"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

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
		if len(files) >= SkillDigestMaxFiles {
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
