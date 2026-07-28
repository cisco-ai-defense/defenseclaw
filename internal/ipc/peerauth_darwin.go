// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package ipc

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// codesignBinary is the on-disk codesign tool. Every macOS ships it;
// we fail closed if it's missing. Overridable in tests via a
// package-level var so unit tests never invoke the real binary.
var codesignBinary = "/usr/bin/codesign"

// plutilBinary is the on-disk plutil tool used to read
// CFBundleIdentifier from an app's Info.plist. Every macOS ships
// it. Overridable in tests.
var plutilBinary = "/usr/bin/plutil"

// codesignTimeout bounds a single peer-cred codesign lookup. macOS
// codesign is normally sub-100ms but a swap-heavy host can stall
// arbitrarily; a bounded exec keeps the accept loop responsive.
const codesignTimeout = 3 * time.Second

// plutilTimeout bounds a bundle-id lookup. plutil is faster than
// codesign but we keep the same posture just in case. It is a variable only
// so the hermetic command-stub test can tolerate heavily loaded CI hosts;
// production never changes the three-second fail-closed bound.
var plutilTimeout = 3 * time.Second

var (
	// codesign -dv --verbose=4 writes its metadata to STDERR (that's
	// been true since the earliest OS X versions). Match all three
	// keys independently — some ad-hoc-signed binaries have
	// Identifier but not TeamIdentifier, and vice-versa.
	//
	// Executable=... may contain spaces (e.g. an .app bundle path),
	// so we match to end-of-line rather than \S+. TeamIdentifier
	// and Identifier are single tokens.
	executableRe = regexp.MustCompile(`(?m)^Executable=(.+)$`)
	teamIDRe     = regexp.MustCompile(`(?m)^TeamIdentifier=(\S+)$`)
	signingIDRe  = regexp.MustCompile(`(?m)^Identifier=(\S+)$`)
)

func init() {
	readPeerIdentity = func(fd int, id *peerIdentity) error {
		cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			return fmt.Errorf("ipc: peer identity: LOCAL_PEERCRED: %w", err)
		}
		id.UID = cred.Uid
		if cred.Ngroups > 0 {
			id.GID = cred.Groups[0]
		}
		if pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
			id.PID = int32(pid)
		}
		return nil
	}
	readCodesignFn = readCodesignForPID
}

// readCodesignForPID shells out to `codesign -dv --verbose=4 +<pid>`
// and returns TeamID + signing identifier + bundle id + executable
// path for the peer process. macOS accepts a PID via the `+<pid>`
// argument form and resolves the running executable itself, so
// we do not need proc_pidpath or /proc scraping.
//
// Bundle-id lookup walks the executable path upward looking for a
// `.app` ancestor and, when found, invokes
// `plutil -extract CFBundleIdentifier raw <app>/Contents/Info.plist`.
// Non-bundle binaries (CLIs, single-file signed processes) yield
// bundleID="". The caller's allow() rejects such peers when an
// AllowedBundleIDs allowlist is configured.
//
// Empty return on error is intentional: allow() rejects any peer
// with empty required fields when the corresponding allowlist is
// non-empty, so a failing codesign / plutil lookup fails closed.
func readCodesignForPID(pid int32) (teamID, signingID, bundleID, exePath string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), codesignTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, codesignBinary, "-dv", "--verbose=4",
		"+"+strconv.Itoa(int(pid)))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// codesign writes metadata to stderr; stdout is empty. Ignore
	// the exit code — a valid signed process still exits 0, but an
	// ad-hoc-signed one exits non-zero on some macOS versions while
	// still writing the fields we care about. We treat "no matches
	// found" as an empty identity, not an error.
	_ = cmd.Run()

	exePath = firstSubmatch(executableRe, stderr.Bytes())
	teamID = firstSubmatch(teamIDRe, stderr.Bytes())
	signingID = firstSubmatch(signingIDRe, stderr.Bytes())

	// codesign emits "TeamIdentifier=not set" for unsigned or
	// ad-hoc-signed binaries. Collapse that to empty so the
	// allowlist doesn't accidentally match a literal "not" entry.
	if strings.EqualFold(strings.TrimSpace(teamID), "not") {
		teamID = ""
	}
	if exePath != "" {
		bundleID = bundleIDFromExecutable(exePath)
	}
	return teamID, signingID, bundleID, exePath, nil
}

// bundleIDFromExecutable walks exePath upward looking for a `.app`
// bundle. When found, it reads CFBundleIdentifier from that
// bundle's Info.plist via plutil. Returns "" for non-bundle
// executables, missing plists, or plutil failures.
//
// Matches the reference implementation at
// /Users/sanjay23/Downloads/GrpcOverUDS 2/IPC/peerauth/darwin.go
// (function of the same name).
func bundleIDFromExecutable(exePath string) string {
	if exePath == "" {
		return ""
	}
	dir := exePath
	for {
		if strings.HasSuffix(dir, ".app") {
			return readBundleIDFromPlist(filepath.Join(dir, "Contents", "Info.plist"))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root without finding an .app.
			return ""
		}
		dir = parent
	}
}

// readBundleIDFromPlist runs plutil to extract CFBundleIdentifier
// from an Info.plist path. Returns "" on any failure.
func readBundleIDFromPlist(plistPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), plutilTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, plutilBinary,
		"-extract", "CFBundleIdentifier", "raw", plistPath).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// firstSubmatch returns the first capture group of the first match
// of re against b, or "" when there is no match.
func firstSubmatch(re *regexp.Regexp, b []byte) string {
	m := re.FindSubmatch(b)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}
