// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	productDocsURL = regexp.MustCompile(`https://cisco-ai-defense\.github\.io/defenseclaw/docs((?:/[A-Za-z0-9_.-]+)*)/?(?:#([A-Za-z0-9_-]+))?`)
	mdxHeading     = regexp.MustCompile(`(?m)^#{1,6}\s+(.+?)\s*$`)
	slugDrop       = regexp.MustCompile(`[^a-z0-9 _-]`)
)

// Every docs link the product prints (Go and Python sources, install
// scripts) names a page, and an anchor, that docs-site still has. A page
// rename or a removed heading otherwise leaves refusals pointing at a 404.
func TestProductDocsLinksNameExistingPages(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	content := filepath.Join(root, "docs-site", "content", "docs")
	if _, err := os.Stat(content); err != nil {
		t.Skipf("docs-site sources not in this tree: %v", err)
	}
	if !strings.HasSuffix(EnterpriseSettingsReferenceURL, "/docs/enterprise/configuration/") {
		t.Errorf("EnterpriseSettingsReferenceURL = %q, want the enterprise settings page", EnterpriseSettingsReferenceURL)
	}
	skipDirs := map[string]bool{".git": true, "node_modules": true, "docs-site": true, ".venv": true, "vendor": true, "testdata": true, "tests": true}
	checked := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if skipDirs[entry.Name()] || (strings.HasPrefix(entry.Name(), ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		name := entry.Name()
		switch filepath.Ext(name) {
		case ".go", ".py", ".sh", ".ps1":
		default:
			return nil
		}
		if strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "test_") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, match := range productDocsURL.FindAllStringSubmatch(string(data), -1) {
			checked++
			page := docsPage(content, match[1])
			if page == "" {
				t.Errorf("%s: %s names no docs-site page", rel, match[0])
				continue
			}
			if anchor := match[2]; anchor != "" && !pageHasAnchor(t, page, anchor) {
				t.Errorf("%s: %s: %s has no heading #%s", rel, match[0], filepath.Base(page), anchor)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("found no docs links in the product sources; the pattern is stale")
	}
}

func docsPage(content, urlPath string) string {
	base := filepath.Join(content, filepath.FromSlash(strings.Trim(urlPath, "/")))
	for _, candidate := range []string{base + ".mdx", filepath.Join(base, "index.mdx")} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func pageHasAnchor(t *testing.T, page, anchor string) bool {
	t.Helper()
	data, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, heading := range mdxHeading.FindAllStringSubmatch(string(data), -1) {
		text := strings.ToLower(strings.NewReplacer("`", "", "*", "").Replace(heading[1]))
		if strings.ReplaceAll(slugDrop.ReplaceAllString(text, ""), " ", "-") == anchor {
			return true
		}
	}
	return false
}
