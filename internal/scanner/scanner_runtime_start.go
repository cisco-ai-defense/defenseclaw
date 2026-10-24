// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"errors"
	"fmt"
	"os"
)

// StandaloneRuntimeStartProblem says why a standalone Windows enterprise
// gateway must not start: its scanner runtime folder exists and fails the
// trust check every scan makes. The gateway service runs that Python tree on
// every scan, so it refuses to start on a tree a standard user could change,
// instead of starting and refusing only once a scan reached it (GAP-0490).
// A missing folder is not refused: nothing in it runs, every scan fails
// closed and the lifecycle installs the runtime after the services start.
// Every other install returns nil.
func StandaloneRuntimeStartProblem() error {
	return scannerRuntimeStartCheck.problem()
}

// runtimeStartCheck is the start check with its platform parts, so the
// decision runs on every platform in tests.
type runtimeStartCheck struct {
	standalone func() bool
	root       func() (string, error)
	lstat      func(string) (os.FileInfo, error)
	trustTree  func(root, label string) error
}

func (c runtimeStartCheck) problem() error {
	if c.standalone == nil || !c.standalone() {
		return nil
	}
	root, err := c.root()
	if err != nil {
		return fmt.Errorf("the gateway does not start: resolve the scanner runtime folder: %w", err)
	}
	if _, err := c.lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("the gateway does not start: read the scanner runtime folder %s: %w", root, err)
	}
	if err := c.trustTree(root, "scanner Python runtime"); err != nil {
		return fmt.Errorf("the gateway does not start on the untrusted scanner runtime %s (%v); "+
			"run the DefenseClaw Setup with /repair, which replaces it", root, err)
	}
	return nil
}
