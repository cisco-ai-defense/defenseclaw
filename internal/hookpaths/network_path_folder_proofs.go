// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// folderProofs are the folders one scope of work (a scan of an evaluation, one
// hook client call) has read and found to be plain directories or missing. A
// read of a name goes through the share walk, which proves every folder on
// the way to it not to lead into a network share, once for each name: about
// 125 us a name on Windows, and a command with thousands of operands, or a
// hook client call that looks for an instruction file by each of its names in
// each folder of the working directory, passed the hook answer budget
// (rel-1-0-9:GAP-0943, GAP-0963). With folderProofs the folder of a name is
// read first, with the walk, once, and what was read of it is kept; the names
// below it are then read with the file system after one bounded read of that
// folder alone (folderStillPlain), a single component and not the whole walk.
//
// A proof is never trusted without that read. A folder that became a link, or
// that is another folder now (it or a folder above it was replaced, possibly
// by a link into a network share that does not answer), is dropped and the
// name is read with the walk, which asks the share. The read is bounded by the
// share answer wait and by what the hook call has left of it, as the read of a
// known folder in the walk is (stillPlain).
//
// Where the share walk is off (networkShareLinkWalk: every host but Windows)
// a read is the plain read and no folder is read first.
//
// A proof holds for its scope only (clear, or a new value), never for a later
// scope or call. Only a folder that is spelled in its clean absolute form, is
// no link, and is not on a share can be a proof; a name below a link or a
// share, a relative name, a name with "..", and any read that failed for
// another reason than a missing name are read with the walk. The zero value is
// empty and ready to use.
type folderProofs struct {
	mu sync.Mutex
	// plain are the folders found to be plain directories, with what the
	// lstat of each returned; missing the folders found to be absent (no
	// name below them exists).
	plain   map[string]os.FileInfo
	missing map[string]struct{}
}

// folderLstat reads a proved folder again for folderStillPlain; tests count
// and hold it.
var folderLstat = os.Lstat

// clear drops every proof.
func (p *folderProofs) clear() {
	p.mu.Lock()
	clear(p.plain)
	clear(p.missing)
	p.mu.Unlock()
}

// forget drops the proof of one folder.
func (p *folderProofs) forget(folder string) {
	p.mu.Lock()
	delete(p.plain, folder)
	p.mu.Unlock()
}

// folderOf is the folder that holds the last name of name, for a name that
// folderProofs can place: absolute, clean, below a folder that is no volume
// root, and not on a share.
func folderOf(name string) (folder string, ok bool) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return "", false
	}
	vol := filepath.VolumeName(name)
	if len(vol) > 0 && os.IsPathSeparator(name[0]) && vol == name[:len(vol)] && len(vol) > 2 {
		return "", false
	}
	folder = filepath.Dir(name)
	if folder == name || len(folder) <= len(vol)+1 || networkShareRootOf(name) != "" {
		return "", false
	}
	return folder, true
}

// standing reports how the folder of name stands in this scope: plain (known
// is what the lstat of the folder returned) or missing (no name below it
// exists). The folder is read with the walk if the scope does not know it yet.
func (p *folderProofs) standing(name string) (folder string, known os.FileInfo, missing bool) {
	folder, ok := folderOf(name)
	if !ok || !networkShareLinkWalk {
		return "", nil, false
	}
	look := func() (os.FileInfo, bool) {
		p.mu.Lock()
		defer p.mu.Unlock()
		_, missing := p.missing[folder]
		return p.plain[folder], missing
	}
	if known, missing = look(); known != nil || missing {
		return folder, known, missing
	}
	_, _ = p.lstat(folder)
	known, missing = look()
	return folder, known, missing
}

// folderStillPlain reads a proved folder again and reports whether it is
// still the folder that was found, as a folder and no link. answered is false
// when the read did not return within the bounded wait; the name is then
// reported unanswered, like a share. A proof that does not hold is dropped.
// The folders above are not walked: one that was replaced makes this folder
// another one.
func (p *folderProofs) folderStillPlain(folder string, known os.FileInfo) (same, answered bool) {
	same, answered = stillPlainRead(folder, known, folderLstat)
	if !same {
		p.forget(folder)
	}
	return same, answered
}

// note records what a completed lstat of name showed: a plain folder, or a
// name that is absent.
func (p *folderProofs) note(name string, info os.FileInfo, err error) {
	switch {
	case err == nil && info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0:
		p.noteDir(name, info)
	case err != nil && os.IsNotExist(err):
		p.noteMissing(name)
	}
}

func (p *folderProofs) noteDir(name string, info os.FileInfo) {
	if _, ok := folderOf(name); !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.plain == nil {
		p.plain = make(map[string]os.FileInfo)
	}
	if len(p.plain) < maxTargetMemoEntries {
		p.plain[name] = info
	}
}

func (p *folderProofs) noteMissing(name string) {
	if _, ok := folderOf(name); !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.missing == nil {
		p.missing = make(map[string]struct{})
	}
	if len(p.missing) < maxTargetMemoEntries {
		p.missing[name] = struct{}{}
	}
}

func missingName(op, name string) error {
	return &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
}

// lstat is pathLstat with the folders of this scope read once.
func (p *folderProofs) lstat(name string) (os.FileInfo, error) {
	folder, known, missing := p.standing(name)
	if missing {
		return nil, missingName("lstat", name)
	}
	if known != nil {
		switch same, answered := p.folderStillPlain(folder, known); {
		case !answered:
			return nil, networkShareError("lstat", name)
		case same:
			info, err := os.Lstat(name)
			p.note(name, info, err)
			return info, err
		}
	}
	info, err := pathLstat(name)
	p.note(name, info, err)
	return info, err
}

// stat is pathStat with the folders of this scope read once. A name below a
// plain folder that is no link and a name that is missing are decided by the
// lstat; a link is read with the walk, which follows it. What stat follows
// proves no folder: only an lstat that finds no link does.
func (p *folderProofs) stat(name string) (os.FileInfo, error) {
	folder, known, missing := p.standing(name)
	if missing {
		return nil, missingName("stat", name)
	}
	if known != nil {
		switch same, answered := p.folderStillPlain(folder, known); {
		case !answered:
			return nil, networkShareError("stat", name)
		case same:
			info, err := os.Lstat(name)
			if err != nil && os.IsNotExist(err) ||
				err == nil && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
				p.note(name, info, err)
				return info, err
			}
		}
	}
	info, err := pathStat(name)
	if err != nil && os.IsNotExist(err) {
		p.noteMissing(name)
	}
	return info, err
}
