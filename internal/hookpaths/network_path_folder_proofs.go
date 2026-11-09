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
// read first, with the walk, once; it is then known to be a plain directory
// (or to be missing), and the names below it are read with the file system
// alone.
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
	// plain are the folders found to be plain directories, missing the
	// folders found to be absent (no name below them exists).
	plain, missing map[string]struct{}
}

// clear drops every proof.
func (p *folderProofs) clear() {
	p.mu.Lock()
	clear(p.plain)
	clear(p.missing)
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

// standing reports how the folder of name stands in this scope: plain (names
// below it are read without the walk) or missing (no name below it exists).
// The folder is read with the walk if the scope does not know it yet.
func (p *folderProofs) standing(name string) (plain, missing bool) {
	folder, ok := folderOf(name)
	if !ok || !networkShareLinkWalk {
		return false, false
	}
	look := func() (plain, missing bool) {
		p.mu.Lock()
		defer p.mu.Unlock()
		_, plain = p.plain[folder]
		_, missing = p.missing[folder]
		return plain, missing
	}
	if plain, missing = look(); plain || missing {
		return plain, missing
	}
	_, _ = p.lstat(folder)
	return look()
}

// note records what a completed read of name showed.
func (p *folderProofs) note(name string, info os.FileInfo, err error) {
	if _, ok := folderOf(name); !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case err == nil && info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0:
		if p.plain == nil {
			p.plain = make(map[string]struct{})
		}
		if len(p.plain) < maxTargetMemoEntries {
			p.plain[name] = struct{}{}
		}
	case err != nil && os.IsNotExist(err):
		if p.missing == nil {
			p.missing = make(map[string]struct{})
		}
		if len(p.missing) < maxTargetMemoEntries {
			p.missing[name] = struct{}{}
		}
	}
}

func missingName(op, name string) error {
	return &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
}

// lstat is pathLstat with the folders of this scope read once.
func (p *folderProofs) lstat(name string) (os.FileInfo, error) {
	plain, missing := p.standing(name)
	var info os.FileInfo
	var err error
	switch {
	case missing:
		return nil, missingName("lstat", name)
	case plain:
		info, err = os.Lstat(name)
	default:
		info, err = pathLstat(name)
	}
	p.note(name, info, err)
	return info, err
}

// stat is pathStat with the folders of this scope read once. A name below a
// plain folder that is no link and a name that is missing are decided by the
// lstat; a link is read with the walk, which follows it.
func (p *folderProofs) stat(name string) (os.FileInfo, error) {
	plain, missing := p.standing(name)
	if missing {
		return nil, missingName("stat", name)
	}
	if plain {
		info, err := os.Lstat(name)
		if err != nil && os.IsNotExist(err) ||
			err == nil && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			p.note(name, info, err)
			return info, err
		}
	}
	info, err := pathStat(name)
	p.note(name, info, err)
	return info, err
}
