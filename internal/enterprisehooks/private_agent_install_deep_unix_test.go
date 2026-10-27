// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1357 (already fixed at the base by the any-depth home walk, GAP-0988):
// an older Claude Code under an arbitrary private npm prefix deep in the home
// is found and listed with its path.
func TestDiscoverUnixPrivateInstallsFindsADeepOpaquePrefix(t *testing.T) {
	home := t.TempDir()
	npmCopy(t, claudePackage(filepath.Join(home, "opaque", "nested"), true), "@anthropic-ai/claude-code", "2.0.77", "cli.js")
	want := filepath.Join("opaque", "nested", "lib", "node_modules", "@anthropic-ai", "claude-code")
	for _, install := range DiscoverUnixPrivateAgentInstalls(context.Background(), home, []string{"claudecode"}) {
		if install.Connector == "claudecode" && strings.HasSuffix(install.Path, want) {
			return
		}
	}
	t.Fatalf("the deep private copy %s was not reported", want)
}
