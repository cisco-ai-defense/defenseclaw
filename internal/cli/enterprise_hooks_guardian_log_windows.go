// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The standalone hook guardian and the hook enumerator append to one service
// log, hook-guardian.log, through handles the services keep open for as long
// as they run. Nothing rotated it, so a failure that repeats on every retry
// (a link at a vendor folder waits for an administrator) made it grow without
// a bound. The lifecycle log has a cap and generations; the guardian log gets
// the same ones, kept by the guardian before each reconcile.
//
// The services keep their handles, so the file cannot be renamed under them
// (their handles do not share delete). The guardian copies the log to
// hook-guardian.log.1, after the older generations moved up, and truncates
// the file in place; both services append at the end of the file, so they
// carry on at the start of the emptied one. A line written between the copy
// and the truncate is lost, which for a diagnostic log is the price of not
// changing how the services open it.

// windowsGuardianServiceLogEnv names the log the service process writes.
const windowsGuardianServiceLogEnv = "DEFENSECLAW_WINDOWS_SERVICE_LOG"

// windowsGuardianLogLimit is the size at which the guardian log rotates:
// the cap of the lifecycle log. Replaceable in tests.
var windowsGuardianLogLimit = int64(windowsEnterpriseLogMaxBytes)

// windowsGuardianLogLastErr keeps a rotation that keeps failing from logging
// the same line before every reconcile.
var windowsGuardianLogLastErr string

func init() {
	previousBefore := enterpriseHookBeforeWatchReconcile
	enterpriseHookBeforeWatchReconcile = func(stderr io.Writer) {
		previousBefore(stderr)
		capWindowsGuardianLog(stderr)
	}
}

// capWindowsGuardianLog rotates the log this process writes once it reaches
// windowsGuardianLogLimit. A process that does not write a service log
// (a one-shot command run by hand) has no variable and rotates nothing.
func capWindowsGuardianLog(stderr io.Writer) {
	// The Secure Client guardian log is not touched.
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	path := strings.TrimSpace(os.Getenv(windowsGuardianServiceLogEnv))
	if path == "" || !filepath.IsAbs(path) {
		return
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < windowsGuardianLogLimit {
		return
	}
	if err := rotateWindowsServiceLog(path); err != nil {
		if message := err.Error(); message != windowsGuardianLogLastErr {
			windowsGuardianLogLastErr = message
			fmt.Fprintf(stderr, "[hook-guardian] could not rotate %s: %v\n", path, err)
		}
		return
	}
	windowsGuardianLogLastErr = ""
	fmt.Fprintf(stderr, "[hook-guardian] rotated %s at %d bytes; the earlier lines are in %s.1\n", path, info.Size(), path)
}

// rotateWindowsServiceLog moves the older generations up, copies path to
// path.1 and empties path in place.
func rotateWindowsServiceLog(path string) error {
	shiftWindowsEnterpriseLogGenerations(path)
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer source.Close()
	target := path + ".1"
	copied, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(copied, source); err != nil {
		_ = copied.Close()
		_ = os.Remove(target)
		return err
	}
	if err := copied.Close(); err != nil {
		_ = os.Remove(target)
		return err
	}
	return os.Truncate(path, 0)
}
