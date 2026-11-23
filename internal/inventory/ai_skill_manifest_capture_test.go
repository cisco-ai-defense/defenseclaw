// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSkillAuthorCaptureUsesRootManifestAndWholeFileDigest(t *testing.T) {
	root := t.TempDir()
	body := []byte("\xef\xbb\xbf---\r\nauthor: Example Team\r\n---\r\n" + strings.Repeat("benign runbook line\n", 5000))
	nested := "---\nauthor: Nested Team\n---\n"
	writeSkillFiles(t, root, map[string]string{"skill.md": string(body), "scripts/SKILL.md": nested, "scripts/run.py": "print('example')\n"})
	plainHash, plainStatus, plainRead := hashSkillFolder(root, maxSkillBytes)
	hash, status, retained, read := hashSkillFolderCapture(root, maxSkillBytes, maxSkillManifest)
	if status != SkillContentOK || plainStatus != SkillContentOK || hash != plainHash || read != plainRead ||
		read != int64(len(body)+len(nested)+len("print('example')\n")) || len(retained) != maxSkillManifest || !bytes.Equal(retained, body[:maxSkillManifest]) {
		t.Fatalf("capture changed hash/budget or selected nested bytes: status %q/%q, hash equal %v, read %d/%d, retained %d", status, plainStatus, hash == plainHash, read, plainRead, len(retained))
	}
	if author := parseSkillFrontMatter(retained).author; author != "Example Team" {
		t.Fatalf("author %q", author)
	}
	// A change after the retained prefix must still change the whole folder hash.
	body[len(body)-1] = '!'
	if err := os.WriteFile(filepath.Join(root, "skill.md"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	changed, changedStatus, prefix, changedRead := hashSkillFolderCapture(root, maxSkillBytes, maxSkillManifest)
	if changedStatus != SkillContentOK || changed == hash || changedRead != read || !bytes.Equal(prefix, retained) {
		t.Fatal("tail change was omitted from the full hash or changed the captured prefix/budget")
	}
}

func TestSkillAuthorCaptureHonorsTheRemainingReadBudget(t *testing.T) {
	root := t.TempDir()
	body := "---\nauthor: Example Team\n---\n" + strings.Repeat("bounded fixture\n", 6000)
	writeSkillFiles(t, root, map[string]string{"SKILL.md": body})
	hash, status, retained, read := hashSkillFolderCapture(root, int64(len(body)-1), maxSkillManifest)
	if hash != "" || status != SkillContentTooLarge || retained != nil || read != 0 {
		t.Fatalf("over-budget manifest: hash %q status %q retained %d read %d", hash, status, len(retained), read)
	}
	hash, status, retained, read = hashSkillFolderCapture(root, int64(len(body)), 0)
	if hash == "" || status != SkillContentOK || retained != nil || read != int64(len(body)) {
		t.Fatalf("capture-off hash: hash %q status %q retained %d read %d", hash, status, len(retained), read)
	}
}
