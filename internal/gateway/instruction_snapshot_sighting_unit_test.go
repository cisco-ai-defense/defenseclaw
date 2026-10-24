// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A directory with a recorded directory's file system identity keeps that
// directory's first record; another identity is a directory of its own.
func TestInstructionSnapshotAliasesDirectoryIdentity(t *testing.T) {
	var cache activeAgentContextCache
	key := activeAgentContextKey{connector: "codex", sessionID: "live"}
	cache.beginKey(key)
	cache.setStartupKey(key, map[string]string{"/x/SOUL.md": "1:9"}, []string{"/x"}, map[string]string{"/x": "1:2"})
	if !cache.extendStartupKey(key, map[string]string{"/y/AGENTS.md": "1:5"}, []string{"/y"}, map[string]string{"/y": "1:2"}) {
		t.Fatal("another spelling was not recorded")
	}
	cache.extendStartupKey(key, map[string]string{"/z/AGENTS.md": "1:6"}, []string{"/z"}, map[string]string{"/z": "1:3"})
	got := cache.snapshotKey(key)
	if !got.startupCovers("/y") || got.startupFiles["/y/AGENTS.md"] != "" || got.startupFiles["/y/SOUL.md"] != "1:9" {
		t.Fatalf("another spelling did not keep the first record: %+v", got)
	}
	if got.startupFiles["/z/AGENTS.md"] != "1:6" {
		t.Fatalf("another directory lost its own files: %+v", got)
	}
}

// Every instruction file name the snapshot records, OpenClaw's config file
// included, is read back from the saved record after a gateway restart.
func TestInstructionStartupRecordKeepsEveryInstructionName(t *testing.T) {
	for _, name := range hookpaths.InstructionFileNames {
		t.Run(name, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, "openclaw", "action", "HIGH")
			api.scannerCfg.DataDir = t.TempDir()
			dir, ok := instructionDirectoryKey(t.TempDir())
			if !ok {
				t.Fatal("no directory key")
			}
			file := instructionFileIn(dir, name)
			if runtime.GOOS == "windows" {
				file = instructionFileIn(dir, strings.ToLower(name))
			}
			key := activeAgentContextKey{connector: "openclaw", sessionID: "live"}
			api.activeAgentContext.beginKey(key)
			api.activeAgentContext.setStartupKey(key, map[string]string{file: "1:2"}, []string{dir}, map[string]string{dir: "1:3"})
			api.saveInstructionLoads(key)
			record, ok := readInstructionLoadRecord(instructionLoadRecordPath(api.instructionLoadDir(), key), key)
			if !ok || record.StartupFiles[file] != "1:2" || record.StartupDirIDs[dir] != "1:3" {
				t.Fatalf("saved snapshot with %s was not restored: %+v %v", name, record, ok)
			}
		})
	}
}
