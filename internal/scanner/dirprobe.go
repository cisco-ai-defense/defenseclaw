// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// errFolderPrivacyProtected names why a folder the OS privacy protection
// guards was not read.
var errFolderPrivacyProtected = errors.New("the folder is protected by macOS privacy protection (TCC): " +
	"grant the app that runs the scan Full Disk Access, or leave the folder out of the scan")

// rawOpenDir opens a folder once, with no EINTR retry (rawOpenDirOnce per OS).
// Tests replace it.
var rawOpenDir = rawOpenDirOnce

// dirProbeRetryWindow is how long an EINTR still counts as a signal that
// interrupted the open (retried) rather than a refusal.
var dirProbeRetryWindow = 2 * time.Second

// probeDirOpen reports a folder the scan must not read. macOS answers open()
// of a folder its privacy protection (TCC) guards with EINTR after about five
// seconds, and the Go runtime retries EINTR without end, so filepath.WalkDir
// never returns (GAP-1529). The probe opens the folder itself and treats an
// EINTR that comes back after dirProbeRetryWindow as that refusal; a quick
// EINTR (a signal) is retried. Any other answer is left to the walk.
func probeDirOpen(dir string) error {
	deadline := time.Now().Add(dirProbeRetryWindow)
	for {
		err := rawOpenDir(dir)
		if !errors.Is(err, syscall.EINTR) {
			return nil
		}
		if time.Now().After(deadline) {
			return &os.PathError{Op: "open", Path: dir, Err: fmt.Errorf("%w (%w)", errFolderPrivacyProtected, syscall.EINTR)}
		}
	}
}
