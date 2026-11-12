// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"runtime"
)

// UseClaudeCodeChainFixtureForTests gives every test of the calling test
// binary the per-user hook guard that Claude Code Setup now requires on
// Windows, in a folder of the test run. A packaged install has
// defenseclaw-hook-guard.exe beside its launcher and publishes the chain under
// the user's profile; a test host has neither, so every test that ran Setup
// for Claude Code (connector, runtime-switch, hook-repair) was refused, and the
// chain would have been written to the real profile.
//
// Each settings file a test names (ClaudeCodeSettingsPathOverride) gets its own
// guard and chain folder, so tests do not share a chain. The fixture guard is
// not run: the probe of its bytes is the one step replaced; everything else
// Setup does with the chain is the shipped code.
//
// Call it from TestMain; the returned function removes the folders. It does
// nothing off Windows, where the chain is not used, and panics unless the
// process is a test binary.
func UseClaudeCodeChainFixtureForTests() func() {
	if flag.Lookup("test.v") == nil {
		panic("connector: UseClaudeCodeChainFixtureForTests is test-only")
	}
	if runtime.GOOS != "windows" {
		return func() {}
	}
	root, err := os.MkdirTemp("", "defenseclaw-claude-chain-")
	if err != nil {
		panic(err)
	}
	folder := func() string {
		sum := sha256.Sum256([]byte(ClaudeCodeSettingsPathOverride))
		dir := filepath.Join(root, hex.EncodeToString(sum[:8]))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			panic(err)
		}
		return dir
	}
	previousDir, previousSource, previousProbe := claudeChainDir, claudeChainSource, claudeChainProbe
	claudeChainDir = func() string { return filepath.Join(folder(), "claude-code-chain") }
	claudeChainSource = func(string) string {
		source := filepath.Join(folder(), windowsHookGuardBinaryName)
		if _, err := os.Lstat(source); err != nil {
			if err := os.WriteFile(source, []byte("MZ fixture hook guard"), 0o600); err != nil {
				panic(err)
			}
		}
		return source
	}
	claudeChainProbe = func(string, string) error { return nil }
	return func() {
		claudeChainDir, claudeChainSource, claudeChainProbe = previousDir, previousSource, previousProbe
		_ = os.RemoveAll(root)
	}
}
