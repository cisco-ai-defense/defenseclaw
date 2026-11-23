// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// substrate-1:GAP-0578 (b): the real full-filesystem tests skip unless
// RealFSTestsEnv is 1, and no workflow set it, so CI never ran the only
// guards that fill a real volume. CI's Go Throughput job now runs each of
// them with it set and fails on a skip; every test that calls
// RealSmallFilesystem must be named there.
func TestEveryRealFilesystemTestRunsInCI(t *testing.T) {
	root := filepath.Join("..", "..")
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	ci := string(workflow)
	if !strings.Contains(ci, RealFSTestsEnv+`: "1"`) {
		t.Fatalf("ci.yml never sets %s=1: the real full-filesystem tests only skip in CI", RealFSTestsEnv)
	}
	funcs := regexp.MustCompile(`(?m)^func (Test\w+)\(`)
	var tests []string
	err = filepath.WalkDir(filepath.Join(root, "internal"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(body)
		for _, call := range regexp.MustCompile(`testenv\.RealSmallFilesystem\(`).FindAllStringIndex(text, -1) {
			name := ""
			for _, match := range funcs.FindAllStringSubmatchIndex(text[:call[0]], -1) {
				name = text[match[2]:match[3]]
			}
			if name != "" {
				tests = append(tests, name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) < 2 {
		t.Fatalf("found %d real full-filesystem tests, want at least 2 (%v)", len(tests), tests)
	}
	for _, name := range tests {
		if !strings.Contains(ci, "'^"+name+"$'") || !strings.Contains(ci, "--- PASS: $name") || !strings.Contains(ci, " "+name) {
			t.Errorf("%s calls RealSmallFilesystem but ci.yml does not run it with %s=1 and check that it passed", name, RealFSTestsEnv)
		}
	}
}
