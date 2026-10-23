// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// InstructionFileNames are the agent instruction and identity files that the
// cognitive-file rules (COG-*) protect. Protection follows the file, not one
// spelling of its name (GAP-0869): a symlink, a hard link, a case variant on a
// case-insensitive volume and a Windows short or stream name all write it.
var InstructionFileNames = [...]string{
	"AGENTS.md", "CLAUDE.md", "SOUL.md", "IDENTITY.md",
	"MEMORY.md", "TOOLS.md", "openclaw.json", "gateway.json",
}

// InstructionIdentityKey carries the hook client's file-identity check of a
// call's write targets: the path of the protected instruction file that one
// of them writes under another name. A gateway that cannot read the user's
// files (ProtectHome) judges the call from it.
const InstructionIdentityKey = "\x00instruction-identity"

// InstructionFileName returns the protected name that base spells: exactly,
// or without case when foldCase (Windows, where the file system ignores it).
func InstructionFileName(base string, foldCase bool) (string, bool) {
	for _, name := range InstructionFileNames {
		if base == name || foldCase && strings.EqualFold(base, name) {
			return name, true
		}
	}
	return "", false
}

func instructionNameFold() bool { return runtime.GOOS == "windows" }

// InstructionFiles are the protected instruction files of one call, each
// identified once by its file identity: the instruction names in the places
// agents load them from (instructionDirectories) and the instruction files
// the session loaded (the gateway's load provenance). A symlinked
// instruction file is identified by the file it reaches, so a write to that
// physical file is a write to the instruction file (GAP-0971). Any other
// file is ordinary, however many links it has: a link count proves nothing,
// and pnpm and uv stores hard-link package files.
type InstructionFiles struct {
	cwd, home string
	loaded    []string
	files     []instructionFile
	built     bool
}

type instructionFile struct {
	path string
	info os.FileInfo
}

// NewInstructionFiles returns the instruction files of a call in cwd for the
// user's home. loaded are the paths the session loaded; only those with an
// instruction name count. The files are identified on first use.
func NewInstructionFiles(cwd, home string, loaded []string) *InstructionFiles {
	return &InstructionFiles{cwd: cwd, home: home, loaded: loaded}
}

func (f *InstructionFiles) identify() {
	if f.built {
		return
	}
	f.built = true
	seen := map[string]bool{}
	add := func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			f.files = append(f.files, instructionFile{path: path, info: info})
		}
	}
	for _, path := range f.loaded {
		if _, named := InstructionFileName(filepath.Base(path), instructionNameFold()); named && filepath.IsAbs(path) {
			add(filepath.Clean(path))
		}
	}
	for _, directory := range instructionDirectories(f.cwd, f.home) {
		for _, name := range InstructionFileNames {
			add(filepath.Join(directory, name))
		}
	}
}

// Alias reports the protected instruction file that an existing write target
// is under another name: a symlink or hard link to one of the call's
// instruction files, the physical file a symlinked one reaches, or a case,
// short-name or stream variant of one. Only the call's instruction files
// count: an instruction-named file in no load location that the session did
// not load is ordinary, and so is every other name of it. A missing file,
// one that is not regular and one already spelled as an instruction name
// report nothing: the name rules judge the last.
func (f *InstructionFiles) Alias(path string) string {
	if f == nil || !filepath.IsAbs(path) {
		return ""
	}
	path = filepath.Clean(path)
	real := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		real = resolved
	}
	info, err := os.Stat(real)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	if _, named := InstructionFileName(filepath.Base(real), instructionNameFold()); named && real == path {
		return ""
	}
	f.identify()
	for _, file := range f.files {
		if os.SameFile(info, file.info) {
			return file.path
		}
	}
	return ""
}

// instructionHomeFolders are the home-relative folders agents load global
// instruction files from.
var instructionHomeFolders = []string{
	"", ".claude", ".codex", ".openclaw", filepath.Join(".openclaw", "workspace"),
	".config", filepath.Join(".config", "amp"), filepath.Join(".config", "opencode"),
}

// instructionDirectories are the places agents load instruction files from:
// the working directory and its parents with their .claude folders, the home
// and agent folders, and the agents' configured homes (CLAUDE_CONFIG_DIR,
// CODEX_HOME) of the calling process.
func instructionDirectories(cwd, home string) []string {
	var directories []string
	add := func(directory string) {
		if filepath.IsAbs(directory) && !slices.Contains(directories, directory) {
			directories = append(directories, directory)
		}
	}
	if filepath.IsAbs(cwd) {
		for current, steps := filepath.Clean(cwd), 0; steps < 64; steps++ {
			add(current)
			add(filepath.Join(current, ".claude"))
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
			current = parent
		}
	}
	if filepath.IsAbs(home) {
		for _, sub := range instructionHomeFolders {
			add(filepath.Join(home, sub))
		}
	}
	for _, variable := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME"} {
		if value := os.Getenv(variable); value != "" {
			add(filepath.Clean(value))
		}
	}
	return directories
}
