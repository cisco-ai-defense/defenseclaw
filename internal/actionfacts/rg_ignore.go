// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The ignore files ripgrep 14.1 reads in a walk (substrate-1:GAP-0660,
// GAP-0661): .rgignore and .ignore (unless --no-ignore-dot) and, in a git
// repository, .gitignore (unless --no-ignore-vcs), in the folder of each
// entry and every folder above it (the ones above the searched folder
// unless --no-ignore-parent), as the ignore crate's Ignore::matched_ignore
// reads them:
//   - one file: its last line that matches the path decides, an ignore
//     line or a "!" whitelist line (the line grammar is the override
//     glob's, rgOverrideGlob);
//   - one kind of file: the file of the deepest folder that decides;
//   - the kinds: .rgignore before .ignore before .gitignore. A .gitignore
//     counts only when a folder of the chain holds .git (unless
//     --no-require-git), and none above the deepest folder that holds it;
//   - an override glob decides before every ignore file; a whitelisted path
//     is read past the hidden rule (a type may still skip it).
//
// The walk (credentialPathWalk) skips hidden names unless hidden is on, so
// a "!" line that may whitelist a hidden credentials name makes the search
// walk again with hidden on (rgIgnoreReader.mayWhitelistHidden), and every
// file either walk found is then counted only when rg reads it
// (rgIgnoreReader.reads). The two directions are kept apart, so the record
// is never below the base's on any input:
//   - a whitelist only adds a read. A line this model does not read exactly
//     (rgGlobRegexp nil), a file it cannot read (unreadable, over
//     rgIgnoreFileMax bytes) and a folder past rgIgnoreFolderMax whitelist
//     nothing: hidden files stay unread there, as before;
//   - an ignore line removes a read only when the call cannot have changed
//     the ignore files or rg's options before rg runs (rgExclude: every
//     command of the call is a reader in rgExcludeSafePrograms and no
//     redirect writes a file, every word known) and nothing on the path is
//     unsure: an unsure
//     whitelist line, file or folder keeps the file.
// Not modelled (a file they skip still counts, a hidden file they whitelist
// stays unread, as before): .git/info/exclude, the global gitignore
// (core.excludesFile) and an ambient RIPGREP_CONFIG_PATH (an inline one
// already reads every file: rgFilterAll).

// rgIgnoreRead is which ignore files an rg reads.
type rgIgnoreRead struct {
	dot, vcs, parents, requireGit, fold bool
}

func (r rgIgnoreRead) any() bool { return r.dot || r.vcs }

// The ignore file kinds in rg's precedence order.
var rgIgnoreFileNames = [...]string{".rgignore", ".ignore", ".gitignore"}

const (
	// rgIgnoreFileMax is the largest ignore file read (bytes).
	rgIgnoreFileMax = 64 << 10
	// rgIgnoreFolderMax is the most folders one resolve looks into for
	// ignore files, and the most a walk keeps as holding one.
	rgIgnoreFolderMax = 512
)

// rgIgnoreFileName reports an ignore file's name.
func rgIgnoreFileName(name []byte) bool {
	for _, file := range rgIgnoreFileNames {
		if string(name) == file {
			return true
		}
	}
	return false
}

// rgIgnoreLine is one line of an ignore file: a whitelist ("!") or ignore
// glob; re nil is a line this model does not read exactly.
type rgIgnoreLine = rgGlob

// rgIgnoreFile is one ignore file; unsure when it could not be read.
type rgIgnoreFile struct {
	lines  []rgIgnoreLine
	unsure bool
}

// rgIgnoreFolder is the ignore files of one folder and whether it holds .git.
type rgIgnoreFolder struct {
	files  [len(rgIgnoreFileNames)]*rgIgnoreFile
	git    bool
	unsure bool // past rgIgnoreFolderMax: not looked into
}

// The results of an ignore match.
const (
	rgIgnoreNone      = 0
	rgIgnoreWhitelist = 1
	rgIgnoreIgnore    = -1
	// rgIgnoreUnsure: an unsure line or file decides: neither whitelisted
	// nor ignored.
	rgIgnoreUnsure = 2
)

// match is the decision of one file on path, relative to its folder.
func (f *rgIgnoreFile) match(rel string, dir bool) int {
	if f == nil {
		return rgIgnoreNone
	}
	if f.unsure {
		return rgIgnoreUnsure
	}
	for i := len(f.lines) - 1; i >= 0; i-- {
		line := f.lines[i]
		if line.onlyDir && !dir {
			continue
		}
		if line.re == nil {
			if line.exclude {
				// A whitelist line that may match: no decision either way.
				return rgIgnoreUnsure
			}
			continue // an ignore line that may match: never skips a file
		}
		if !line.re.MatchString(rgLatin1(rel)) {
			continue
		}
		if line.exclude {
			return rgIgnoreWhitelist
		}
		return rgIgnoreIgnore
	}
	return rgIgnoreNone
}

// rgIgnoreReader reads the ignore files of one resolve's rg searches, each
// folder once.
type rgIgnoreReader struct {
	folders map[string]*rgIgnoreFolder
	loads   int
}

// folder is the ignore files of dir.
func (r *rgIgnoreReader) folder(dir string, fold bool) *rgIgnoreFolder {
	if r.folders == nil {
		r.folders = make(map[string]*rgIgnoreFolder)
	}
	key := dir
	if fold {
		key = "\x00" + dir
	}
	if f, ok := r.folders[key]; ok {
		return f
	}
	f := &rgIgnoreFolder{}
	if r.loads >= rgIgnoreFolderMax {
		f.unsure = true
		r.folders[key] = f
		return f
	}
	r.loads++
	if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
		f.git = true
	}
	for kind, name := range rgIgnoreFileNames {
		f.files[kind] = readRgIgnoreFile(filepath.Join(dir, name), fold)
	}
	r.folders[key] = f
	return f
}

// readRgIgnoreFile is an ignore file's lines, nil when there is none.
func readRgIgnoreFile(file string, fold bool) *rgIgnoreFile {
	info, err := os.Lstat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return &rgIgnoreFile{unsure: true}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// rg reads the file the link points at.
		if info, err = os.Stat(file); err != nil {
			return nil
		}
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if info.Size() > rgIgnoreFileMax {
		return &rgIgnoreFile{unsure: true}
	}
	handle, err := os.Open(file)
	if err != nil {
		return &rgIgnoreFile{unsure: true}
	}
	defer handle.Close()
	data, err := io.ReadAll(io.LimitReader(handle, rgIgnoreFileMax+1))
	if err != nil || len(data) > rgIgnoreFileMax {
		return &rgIgnoreFile{unsure: true}
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	parsed := &rgIgnoreFile{}
	for _, line := range strings.Split(string(data), "\n") {
		glob, ok := rgOverrideGlob(strings.TrimSuffix(line, "\r"), fold)
		if !ok {
			continue
		}
		parsed.lines = append(parsed.lines, glob)
	}
	return parsed
}

// chain is the folders whose ignore files decide an entry of folder dir in
// a search of root, from dir up: to root, and above it when parents.
func rgIgnoreChain(root, dir string, parents bool) []string {
	var chain []string
	for current := dir; ; {
		chain = append(chain, current)
		up := filepath.Dir(current)
		if current == root && !parents || up == current {
			return chain
		}
		if len(chain) > 4096 {
			return chain
		}
		current = up
	}
}

// match is rg's decision for path (a file, or a folder when dir) under the
// folder a search of root reads, by the ignore files of read: one of
// rgIgnoreNone, rgIgnoreWhitelist, rgIgnoreIgnore or rgIgnoreUnsure.
func (r *rgIgnoreReader) match(read rgIgnoreRead, root, entry string, dir bool) int {
	chain := rgIgnoreChain(root, filepath.Dir(entry), read.parents)
	folders := make([]*rgIgnoreFolder, len(chain))
	anyGit := !read.requireGit
	for i, folder := range chain {
		folders[i] = r.folder(folder, read.fold)
		if folders[i].unsure {
			return rgIgnoreUnsure
		}
		anyGit = anyGit || folders[i].git
	}
	var decided [len(rgIgnoreFileNames)]int
	sawGit := false
	for i, folder := range folders {
		rel, err := filepath.Rel(chain[i], entry)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			return rgIgnoreUnsure
		}
		rel = filepath.ToSlash(rel)
		for kind := range rgIgnoreFileNames {
			switch {
			case decided[kind] != rgIgnoreNone:
			case kind < 2 && !read.dot:
			case kind == 2 && (!read.vcs || !anyGit || sawGit):
			default:
				decided[kind] = folder.files[kind].match(rel, dir)
			}
		}
		sawGit = sawGit || folder.git
	}
	for _, d := range decided {
		if d != rgIgnoreNone {
			return d
		}
	}
	return rgIgnoreNone
}

// reads reports a file found under root (shown as rg names root) that rg
// reads with f, its ignore files read: each folder on the way is entered
// and the file read, an override glob first, then the ignore files, then
// f's types and hidden rule (an ignore whitelist passes the hidden rule).
// exclude says an ignore line may skip it (rgExclude); without it only
// whitelists are read.
func (r *rgIgnoreReader) reads(f *rgFilter, root, shown, file string, exclude bool) bool {
	rel, err := filepath.Rel(root, file)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return true
	}
	segments := strings.Split(filepath.ToSlash(rel), "/")
	current, p := root, shown
	for i, segment := range segments {
		dir := i < len(segments)-1
		current, p = filepath.Join(current, segment), rgJoin(p, segment)
		if override := f.override(p, dir); override != 0 {
			if override < 0 {
				return false
			}
			continue
		}
		decision := r.match(f.ignore, root, current, dir)
		if decision == rgIgnoreIgnore && exclude {
			return false
		}
		whitelisted := decision == rgIgnoreWhitelist
		if dir {
			if !whitelisted && !f.hidden && strings.HasPrefix(segment, ".") {
				return false
			}
			continue
		}
		return f.readsName(segment, whitelisted)
	}
	return true
}

// mayWhitelistHidden reports a whitelist line in an ignore file of folders
// (the folders a walk found one in) or of root and the folders above it
// that may match a hidden credentials name: a line this model does not
// read exactly, or one with a path segment that matches a dot-named first
// segment of a credentials probe. A line such as !.env.example whitelists
// no credentials file and makes no second walk.
func (r *rgIgnoreReader) mayWhitelistHidden(read rgIgnoreRead, root string, folders []string, over bool) bool {
	if over {
		return true
	}
	look := append(rgIgnoreChain(root, root, read.parents), folders...)
	for _, dir := range look {
		folder := r.folder(dir, read.fold)
		if folder.unsure {
			return true
		}
		for kind, file := range folder.files {
			if file == nil || kind < 2 && !read.dot || kind == 2 && !read.vcs {
				continue
			}
			if file.unsure {
				continue // whitelists nothing: hidden files stay unread
			}
			for _, line := range file.lines {
				if line.exclude && rgWhitelistMayNameHidden(line) {
					return true
				}
			}
		}
	}
	return false
}

// rgWhitelistMayNameHidden reports a whitelist line that may match a
// dot-named credentials probe segment anywhere in a path.
func rgWhitelistMayNameHidden(line rgIgnoreLine) bool {
	if line.re == nil {
		return true
	}
	for name := range credentialProbeFirstSegments() {
		if !strings.HasPrefix(name, ".") {
			continue
		}
		for _, p := range []string{name, "a/" + name, name + "/a", "a/" + name + "/a"} {
			if line.re.MatchString(rgLatin1(p)) {
				return true
			}
		}
	}
	return false
}

// rgExcludeSafePrograms are the programs a call may run beside an rg for
// the rg's ignore lines to remove a read (rgExclude): readers and folder
// moves that change no file and no option of the rg.
var rgExcludeSafePrograms = map[string]bool{
	"rg": true, "ripgrep": true, "grep": true, "egrep": true, "fgrep": true,
	"cat": true, "head": true, "tail": true, "wc": true, "sort": true, "uniq": true,
	"cut": true, "tr": true, "less": true, "more": true, "ls": true, "pwd": true,
	"cd": true, "pushd": true, "popd": true, "echo": true, "printf": true,
	"true": true, "false": true, "test": true, "[": true,
}

// rgExclude reports a call whose commands are all in rgExcludeSafePrograms,
// each with every word known, and that redirects no output to a file: the
// ignore files are as the hook reads them when its rg runs.
func rgExclude(commands []CommandFact) bool {
	for _, command := range commands {
		if !rgExcludeSafePrograms[command.Program] || !command.ArgvComplete {
			return false
		}
		for _, argument := range command.Arguments {
			if argument.Expands {
				return false
			}
		}
		for _, redirect := range command.Redirects {
			switch redirect.Access {
			case PathAccessWrite, PathAccessAppend:
				if redirect.Target != "/dev/null" {
					return false
				}
			}
		}
	}
	return true
}
