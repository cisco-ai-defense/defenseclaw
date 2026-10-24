// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
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
// call's write targets: the paths of the protected instruction files that
// they write under other names, every one of them (GAP-1065), separated by
// NUL. A gateway that cannot read the user's files (ProtectHome) judges the
// call from it.
const InstructionIdentityKey = "\x00instruction-identity"

// FileIdentitiesKey carries the file identities (FileIdentity) of a call's
// existing write targets, comma separated. LoadedIdentityPrefix keys the
// identity of the instruction file an InstructionsLoaded event names. The
// hook client reads both as the user, so a gateway that cannot read the
// user's files (ProtectHome) still knows a write under any name to a file
// the session loaded as a write to that file (GAP-1064).
const (
	FileIdentitiesKey    = "\x00file-identities"
	LoadedIdentityPrefix = "\x00loaded-identity:"
)

// maxFileIdentityBytes bounds one FileIdentity value.
const maxFileIdentityBytes = 64

// InstructionIdentities returns the instruction files of a decoded map's
// InstructionIdentityKey.
func InstructionIdentities(targets map[string]string) []string {
	if value := targets[InstructionIdentityKey]; value != "" {
		return strings.Split(value, "\x00")
	}
	return nil
}

// FileIdentities returns the write-target identities of a decoded map's
// FileIdentitiesKey.
func FileIdentities(targets map[string]string) []string {
	if value := targets[FileIdentitiesKey]; value != "" {
		return strings.Split(value, ",")
	}
	return nil
}

// FileIdentity is the identity of the regular file that path reaches,
// following symlinks: its device and inode. It is empty when the file is
// missing or not regular, and on Windows, whose gateway reads the file
// itself and gets no client evidence.
func FileIdentity(path string) string {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return fileIdentity(info)
}

func validFileIdentity(identity string) bool {
	if identity == "" || len(identity) > maxFileIdentityBytes {
		return false
	}
	for _, c := range []byte(identity) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && c != ':' {
			return false
		}
	}
	return true
}

// clientIdentityFact reports a key of the identity evidence above, which is
// for the cognitive-file proof only.
func clientIdentityFact(key string) bool {
	return key == InstructionIdentityKey || key == FileIdentitiesKey ||
		strings.HasPrefix(key, LoadedIdentityPrefix)
}

// instructionLoadEvidence is the client evidence of an InstructionsLoaded
// event: the identity of the instruction file it names.
func instructionLoadEvidence(envelope map[string]json.RawMessage) string {
	var event, path string
	if json.Unmarshal(envelope["hook_event_name"], &event) != nil || event != "InstructionsLoaded" ||
		json.Unmarshal(envelope["file_path"], &path) != nil ||
		!filepath.IsAbs(path) || len(path) > MaxWriteTargetPathBytes {
		return ""
	}
	if _, named := InstructionFileName(filepath.Base(path), instructionNameFold()); !named {
		return ""
	}
	identity := FileIdentity(path)
	if identity == "" {
		return ""
	}
	encoded, err := json.Marshal(map[string]string{LoadedIdentityPrefix + path: identity})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

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
// instruction files (whatever the link is named), the physical file a
// symlinked one reaches, a path through a symlinked or case-variant
// directory, or a case, short-name or stream variant of one. Only the call's
// instruction files count: an instruction-named file in no load location
// that the session did not load is ordinary, and so is every other name of
// it. A missing file, one that is not regular and an instruction file named
// as the call names it report nothing: the name rules judge the last.
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
	f.identify()
	for _, file := range f.files {
		if os.SameFile(info, file.info) {
			if file.path == path || instructionNameFold() && strings.EqualFold(file.path, path) {
				return ""
			}
			return file.path
		}
	}
	return ""
}

// Located returns the spelling of path that names it in the directory of a
// file the session loaded or in a load location (instructionDirectories),
// when path, spelled as an instruction file name, reaches that directory
// through another spelling: a symlinked or case-variant one. It is empty
// for any other path. The file itself need not exist. The gateway checks the
// spelling first (instructionLoadLocation) and judges the returned spelling
// the same way; this is the file-system check for the rest.
func (f *InstructionFiles) Located(path string) string {
	if f == nil || !filepath.IsAbs(path) {
		return ""
	}
	path = filepath.Clean(path)
	name, named := InstructionFileName(filepath.Base(path), instructionNameFold())
	if !named {
		return ""
	}
	directory, err := os.Stat(filepath.Dir(path))
	if err != nil || !directory.IsDir() {
		return ""
	}
	sameDirectory := func(candidate string) bool {
		info, err := os.Stat(candidate)
		return err == nil && os.SameFile(info, directory)
	}
	for _, loaded := range f.loaded {
		if loadedName, named := InstructionFileName(filepath.Base(loaded), instructionNameFold()); named &&
			loadedName == name && filepath.IsAbs(loaded) && sameDirectory(filepath.Dir(filepath.Clean(loaded))) {
			return filepath.Clean(loaded)
		}
	}
	for _, candidate := range instructionDirectories(f.cwd, f.home) {
		if sameDirectory(candidate) {
			return filepath.Join(candidate, name)
		}
	}
	return ""
}

// InstructionHomeFolders are the home-relative folders, slash separated,
// that agents load global instruction files from.
var InstructionHomeFolders = [...]string{
	"", ".claude", ".codex", ".openclaw", ".openclaw/workspace",
	".config", ".config/amp", ".config/opencode",
}

// InstructionHomeVariables name the agents' configured homes, which hold
// their global instruction files.
var InstructionHomeVariables = [...]string{"CLAUDE_CONFIG_DIR", "CODEX_HOME"}

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
		for _, sub := range InstructionHomeFolders {
			add(filepath.Join(home, filepath.FromSlash(sub)))
		}
	}
	for _, variable := range InstructionHomeVariables {
		if value := os.Getenv(variable); value != "" {
			add(filepath.Clean(value))
		}
	}
	return directories
}
