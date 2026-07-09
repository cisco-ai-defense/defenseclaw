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
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// codesignBinary is the on-disk codesign tool. Every macOS ships it;
// we fail closed if it's missing (the server logs an error and rejects
// all peers). Overridable in tests via a package-level var so unit
// tests never invoke the real binary.
var codesignBinary = "/usr/bin/codesign"

// codesignTimeout bounds a single peer-cred codesign lookup. macOS
// codesign is normally sub-100ms but a swap-heavy host can stall
// arbitrarily; a bounded exec keeps the accept loop responsive.
const codesignTimeout = 3 * time.Second

var (
	// codesign -dv --verbose=4 writes its metadata to STDERR (that's
	// been true since the earliest OS X versions). Match both keys
	// independently — some ad-hoc-signed binaries have Identifier
	// but not TeamIdentifier, and vice-versa.
	teamIDRe    = regexp.MustCompile(`(?m)^TeamIdentifier=(\S+)$`)
	signingIDRe = regexp.MustCompile(`(?m)^Identifier=(\S+)$`)
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
// and returns the TeamIdentifier + signing identifier for the peer
// process. macOS accepts a PID via the `+<pid>` argument form and
// resolves the running executable + reads its signature itself, so
// we do not need proc_pidpath or /proc scraping.
//
// Empty return on error is intentional: the caller (allow() in
// peerauth_unix.go) rejects any peer with empty (TeamID, SigningID)
// when an allowlist is configured, so a failing codesign lookup
// fails closed automatically.
func readCodesignForPID(pid int32) (teamID, signingID string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), codesignTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, codesignBinary, "-dv", "--verbose=4",
		"+"+strconv.Itoa(int(pid)))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// codesign writes metadata to stderr; stdout is empty. Ignore
	// the exit code — a valid signed process still exits 0, but an
	// ad-hoc-signed one exits non-zero on some macOS versions while
	// still writing Identifier. We treat "no matches found" as an
	// empty identity, not an error.
	_ = cmd.Run()

	teamID = firstSubmatch(teamIDRe, stderr.Bytes())
	signingID = firstSubmatch(signingIDRe, stderr.Bytes())

	// codesign emits "TeamIdentifier=not set" for unsigned or
	// ad-hoc-signed binaries. Collapse that to empty so the
	// allowlist doesn't accidentally match a literal "not" entry.
	if strings.EqualFold(strings.TrimSpace(teamID), "not") {
		teamID = ""
	}
	return teamID, signingID, nil
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
