// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestClaudeVersionLoaderDescriptorExecTransition(t *testing.T) {
	for _, rights := range []int{unix.O_WRONLY, unix.O_RDWR} {
		if versionLoaderFlags(rights, unix.FD_CLOEXEC, true) || versionLoaderFlags(rights, 0, false) {
			t.Fatal("writable loader descriptor accepted")
		}
	}
	if !versionLoaderFlags(unix.O_RDONLY, unix.FD_CLOEXEC, true) || !versionLoaderFlags(unix.O_RDONLY, 0, false) || versionLoaderFlags(unix.O_RDONLY, 0, true) || versionLoaderFlags(unix.O_RDONLY, unix.FD_CLOEXEC, false) {
		t.Fatal("loader closed or leaked across the wrong exec stage")
	}
}

func TestClaudeVersionUnreviewedLoaderCannotCreateFixtureLeaf(t *testing.T) {
	for _, variant := range []string{"wrong-bytes", "link", "alias"} {
		t.Run(variant, func(t *testing.T) {
			staging, fixturePath := t.TempDir(), t.TempDir()
			if err := os.Mkdir(filepath.Join(staging, "images"), 0700); err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(staging, "images", "musl-loader")
			if err := os.WriteFile(input, []byte("public inert non-loader bytes"), 0500); err != nil {
				t.Fatal(err)
			}
			if variant == "link" {
				if err := os.Rename(input, input+"-target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(input+"-target", input); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "alias" {
				if err := os.Link(input, input+"-alias"); err != nil {
					t.Fatal(err)
				}
			}
			source, err := openDirectory(staging)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			root, err := openDirectory(fixturePath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			fixture := &fixtureCapabilities{root: root}
			if copyVersionLoader(source, fixture) == nil || fixture.loader != nil {
				t.Fatal("unreviewed input became a held loader")
			}
			entries, err := os.ReadDir(fixturePath)
			if err != nil || len(entries) != 0 {
				t.Fatal("refused input touched the fresh fixture")
			}
		})
	}
}

func TestClaudeVersionWrapperRequiresExactOutputAndCleanup(t *testing.T) {
	makeResult := func() map[string]any {
		child := validWrapperResult()
		child["scope"], child["fixed_suite"], child["artifact_receipt_sha256"] = claudeVersionScope, claudeVersionSuite, claudeVersionReceiptSHA
		child["pending_version_resources"], child["pending_outer_loader_resources"], child["claude_version_output_observed"] = float64(0), float64(0), true
		child["cases"] = []any{map[string]any{"mode": claudeVersionSuite, "passed": true, "prepared": true, "started": true, "claude_version_output_observed": true, "destroyed": true, "native_cleanup_observed": true, "exit_code": float64(0), "output_bytes": float64(22), "stderr_bytes": float64(0), "native_terminal_before_outer_cleanup": true}}
		return child
	}
	if validateWrapperSuiteResult(makeResult(), claudeVersionSuite) != nil {
		t.Fatal("synthetic exact version observation refused")
	}
	for _, key := range []string{"claude_version_output_observed", "output_bytes", "stderr_bytes", "exit_code", "native_cleanup_observed", "destroyed", "native_terminal_before_outer_cleanup"} {
		child := makeResult()
		delete(child["cases"].([]any)[0].(map[string]any), key)
		if validateWrapperSuiteResult(child, claudeVersionSuite) == nil {
			t.Fatalf("missing %s accepted", key)
		}
	}
	child := makeResult()
	child["pending_version_resources"] = float64(1)
	if validateWrapperSuiteResult(child, claudeVersionSuite) == nil || validateWrapperSuiteResult(makeResult(), "baseline") == nil {
		t.Fatal("pending source or relabeled baseline accepted")
	}
}
