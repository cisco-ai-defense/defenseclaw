// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A folder, a manifest or a file inside a skill folder that is a link onto a
// network share that has not answered is not read, whatever the local
// spelling of its path is: the read follows the link onto the share.
func TestLinkOntoAnUnansweredShareIsNotRead(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	share := filepath.Join(home, "share")
	remote := filepath.Join(share, "skills", "remote")
	local := filepath.Join(home, ".claude", "skills", "local")
	for _, dir := range []string{remote, local} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for dir, name := range map[string]string{remote: "remote-name", local: "local-name"} {
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(share, "extra.md"), []byte("extra"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkedFolder := filepath.Join(home, ".claude", "skills", "linked")
	linkOrSkip(t, remote, linkedFolder)
	linkOrSkip(t, filepath.Join(share, "extra.md"), filepath.Join(local, "extra.md"))
	manifestFolder := filepath.Join(home, ".claude", "skills", "manifest-link")
	if err := os.MkdirAll(manifestFolder, 0o755); err != nil {
		t.Fatal(err)
	}
	linkOrSkip(t, filepath.Join(remote, "SKILL.md"), filepath.Join(manifestFolder, "SKILL.md"))

	read := func() (folder, manifest, viaManifestLink string, content Content, ok bool) {
		content, ok = ReadContent("skill", "local", local)
		return DeclaredSkillName(linkedFolder), DeclaredSkillName(local), DeclaredSkillName(manifestFolder), content, ok
	}
	folder, manifest, viaManifestLink, content, ok := read()
	if folder != "remote-name" || manifest != "local-name" || !ok || len(content.Files) != 2 || content.Truncated {
		t.Fatalf("with every path answering: folder=%q manifest=%q manifest link=%q ok=%t content=%+v", folder, manifest, viaManifestLink, ok, content)
	}

	old := ShareGate
	t.Cleanup(func() { ShareGate = old })
	ShareGate = func(path string) bool {
		return path != share && !strings.HasPrefix(path, share+string(filepath.Separator))
	}
	folder, manifest, viaManifestLink, content, ok = read()
	if folder != "" {
		t.Errorf("declared name through a folder link onto the share = %q, want it unread", folder)
	}
	if viaManifestLink != "" {
		t.Errorf("declared name through a manifest link onto the share = %q, want it unread", viaManifestLink)
	}
	if manifest != "local-name" {
		t.Errorf("declared name of a local folder = %q, want local-name", manifest)
	}
	if !ok || !content.Truncated || len(content.Files) != 1 || content.Files[0].Rel != "SKILL.md" {
		t.Errorf("content of a local folder with a file linked onto the share = %+v ok=%t, want SKILL.md only, marked truncated", content, ok)
	}
	if _, ok := ReadContent("skill", "linked", linkedFolder); ok {
		t.Error("content of a folder linked onto the share was read")
	}
}
