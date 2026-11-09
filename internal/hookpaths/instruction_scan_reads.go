// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io/fs"
	"os"
)

// scanReads remembers what one hook call read of each path while it scanned
// the instruction directories, so the scans of one call (the instruction
// files a write target is, and the sighting of the directories the call
// reaches) read a path once. The calls of one hook run follow each other
// within milliseconds, and the memo never outlives the call. A nil *scanReads
// reads every path again.
type scanReads struct {
	stats map[string]scanRead
	// folders are proved once for the call (folderProofs).
	folders folderProofs
}

type scanRead struct {
	info os.FileInfo
	err  error
}

func (r *scanReads) stat(path string) (os.FileInfo, error) {
	if r == nil {
		return pathStat(path)
	}
	if read, kept := r.stats[path]; kept {
		return read.info, read.err
	}
	info, err := r.folders.stat(path)
	if r.stats == nil {
		r.stats = make(map[string]scanRead)
	}
	r.stats[path] = scanRead{info: info, err: err}
	return info, err
}

// absent reports a directory that does not exist. No name below it does
// either, so a scan of the names in it reads nothing.
func (r *scanReads) absent(directory string) bool {
	_, err := r.stat(directory)
	return err != nil && errors.Is(err, fs.ErrNotExist)
}

// fileIdentity is FileIdentity read through the memo.
func (r *scanReads) fileIdentity(path string) string {
	info, err := r.stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return fileIdentityForPath(path, info)
}

// directoryIdentity is DirectoryIdentity read through the memo.
func (r *scanReads) directoryIdentity(path string) string {
	info, err := r.stat(path)
	if err != nil || !info.IsDir() {
		return ""
	}
	return directoryIdentityForPath(path, info)
}
