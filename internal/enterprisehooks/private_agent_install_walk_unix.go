// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// unixPrivateWalkOpenTimeout bounds one directory open of the home walk.
// Tests lower it.
var unixPrivateWalkOpenTimeout = 3 * time.Second

// unixPrivateWalkOpenFile is the open the home walk makes. Tests replace it.
var unixPrivateWalkOpenFile = os.Open

// errPrivateWalkOpenTimedOut is a directory open that did not return within
// unixPrivateWalkOpenTimeout: the walk is then incomplete, never clean.
var errPrivateWalkOpenTimedOut = errors.New("the folder did not open in time")

// unixPrivateWalkOpener is the open of the Unix home walk below home.
//
// A system call that never returns never observes the scan's context. On
// macOS an open() of a folder the privacy controls (TCC) protect, such as
// ~/Desktop, ~/Documents or ~/Downloads, waits for a decision no one can give
// to a background worker, so a managed reinstall timed out every discovery
// worker and left the supported installed Hermes unenrolled (GAP-1413).
// Those folders are not opened: they are treated as the walk treats a
// privacy denial (EPERM), which hides nothing DefenseClaw could inspect
// without Full Disk Access. Any other open that does not return in time (a
// hung network mount, a privacy-protected folder not on the list) makes the
// walk incomplete; its goroutine closes the folder if the open returns later.
func unixPrivateWalkOpener(home string) func(string) (*os.File, error) {
	home = filepath.Clean(home)
	return func(dir string) (*os.File, error) {
		if unixPrivateWalkPrivacyProtected(home, dir) {
			return nil, &os.PathError{Op: "open", Path: dir, Err: syscall.EPERM}
		}
		type opened struct {
			f   *os.File
			err error
		}
		result := make(chan opened, 1)
		abandoned := make(chan struct{})
		go func() {
			f, err := unixPrivateWalkOpenFile(dir)
			select {
			case result <- opened{f, err}:
			case <-abandoned:
				if f != nil {
					_ = f.Close()
				}
			}
		}()
		timer := time.NewTimer(unixPrivateWalkOpenTimeout)
		defer timer.Stop()
		select {
		case r := <-result:
			return r.f, r.err
		case <-timer.C:
			close(abandoned)
			select {
			case r := <-result:
				// It returned as the timer fired.
				return r.f, r.err
			default:
			}
			return nil, fmt.Errorf("open %s: %w", dir, errPrivateWalkOpenTimedOut)
		}
	}
}

// unixPrivateWalkPrivacyProtected reports a folder of home that
// unixPrivacyProtectedHomeFolders names, compared as the case-insensitive
// macOS file system does.
func unixPrivateWalkPrivacyProtected(home, dir string) bool {
	rel, err := filepath.Rel(home, filepath.Clean(dir))
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	for _, protected := range unixPrivacyProtectedHomeFolders {
		if strings.EqualFold(rel, protected) {
			return true
		}
	}
	return false
}
