// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGAP0488ArchiveScopeKeepsPositiveEvidence(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{"app", "link.tar.d", "plain.tar.d"} {
		if err := os.MkdirAll(filepath.Join(cwd, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, kind := range map[string]byte{"link.tar": tar.TypeSymlink, "plain.tar": tar.TypeReg} {
		file, err := os.Create(filepath.Join(cwd, name))
		if err != nil {
			t.Fatal(err)
		}
		writer := tar.NewWriter(file)
		header := &tar.Header{Name: "p", Typeflag: kind, Mode: 0o600}
		if kind == tar.TypeSymlink {
			header.Linkname = "../../.ssh/authorized_keys"
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	forms := []struct{ name, command, target string }{
		{"preceding statement", "echo start && tar -xf link.tar -C app && echo k >> app/p", "app/p"},
		{"redirect", "tar -xf link.tar -C app 2>/dev/null && echo k >> app/p", "app/p"},
		{"repeated basename", "tar -xf link.tar -C link.tar.d && echo k >> link.tar.d/p", "link.tar.d/p"},
		{"other preceding statement", "true; tar -xf link.tar -C app; echo k >> app/p", "app/p"},
		{"pipeline", "tar -xf link.tar -C app | cat; echo k >> app/p", "app/p"},
		{"conditional", "if true; then tar -xf link.tar -C app; fi; echo k >> app/p", "app/p"},
		{"output redirect", "tar -xvf link.tar -C app > list.txt && echo k >> app/p", "app/p"},
		{"two archive words", "tar -xf plain.tar --file=link.tar -C app && echo k >> app/p", "app/p"},
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			facts := map[string]string{}
			_ = commandLinksWithFacts(form.command, cwd, home, facts, true)
			if facts[TarLinkFactPrefix+filepath.Join(cwd, "link.tar")] != "1" {
				t.Fatal("client omitted positive archive evidence")
			}
			target := filepath.Join(cwd, form.target)
			if !CommandLinksWithFactsForTier("Bash", form.command, cwd, home, facts, true).OpaqueTargetWithFacts(target, false, nil) {
				t.Fatal("balanced lost known archive scope")
			}
			plain := strings.ReplaceAll(form.command, "link.tar", "plain.tar")
			plainTarget := filepath.Join(cwd, strings.ReplaceAll(form.target, "link.tar", "plain.tar"))
			if CommandLinksWithFactsForTier("Bash", plain, cwd, home, nil, true).OpaqueTargetWithFacts(plainTarget, false, nil) {
				t.Fatal("balanced blocked ordinary archive twin")
			}
		})
	}
	t.Run("bounded archive operands", func(t *testing.T) {
		command := "tar -x -C app " + strings.Repeat("-f plain.tar ", 2) +
			"-f link.tar && echo k >> app/p"
		target := filepath.Join(cwd, "app", "p")
		if !CommandLinksWithFactsForTier("Bash", command, cwd, home, nil, true).OpaqueTargetWithFacts(target, false, nil) {
			t.Fatal("bounded archive read lost its scope")
		}
	})
}
