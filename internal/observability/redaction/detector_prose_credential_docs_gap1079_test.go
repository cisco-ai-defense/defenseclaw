// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1079: the repository's own documentation is a corpus of real prose
// about passwords, secrets and passphrases (about 55,000 lines, hundreds of
// trigger sentences). The prose recognizer takes none of it.
func TestProsePasswordDocsHaveNoFalsePositivesGAP1079(t *testing.T) {
	t.Parallel()
	lines, triggers := 0, 0
	for _, dir := range []string{"docs", "docs-site"} {
		root := filepath.Join("..", "..", "..", dir)
		if _, err := os.Stat(root); err != nil {
			t.Skipf("no %s directory in this checkout", dir)
		}
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if info.Name() == "node_modules" || info.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".md") && !strings.HasSuffix(path, ".mdx") {
				return nil
			}
			file, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			scanner.Buffer(make([]byte, 1<<20), 1<<20)
			for scanner.Scan() {
				line := scanner.Text()
				lines++
				if proseCredentialRE.MatchString(line) {
					triggers++
				}
				for _, item := range recognizeProseCredentials(line) {
					if item.accepted {
						t.Errorf("%s: prose password recognized in documentation: %q", path, line[item.start:item.end])
					}
				}
			}
			return nil
		})
	}
	t.Logf("documentation lines: %d, trigger sentences: %d", lines, triggers)
}
