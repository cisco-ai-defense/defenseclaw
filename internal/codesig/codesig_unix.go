// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package codesig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// codesignBinary is macOS's code-signing tool, which every macOS ships.
// Tests replace it with a stub.
var codesignBinary = "/usr/bin/codesign"

// darwinHost says codesign can run here. Tests set it so the macOS path
// runs against a stub on the Linux build host.
var darwinHost = runtime.GOOS == "darwin"

// VerifyTimeout bounds one codesign run. A strict verify of the 270 MB
// Claude Desktop engine took 0.7 s on Apple silicon; the bound leaves room
// for a loaded host, and a run past it fails the check.
var VerifyTimeout = 20 * time.Second

// maxCodesignOutput bounds what a codesign run may print.
const maxCodesignOutput = 16 << 10

// DarwinOptions tune VerifyDarwin.
type DarwinOptions struct {
	// Pin are files whose identity (device, inode, size, mode, modification
	// and change times) must be the same before and after the check: the
	// bundle's main executable and its Info.plist. Each must be a regular
	// file, not a link.
	Pin []string
	// UID and GID: when this process runs as root, codesign runs as that
	// account (GID its passwd primary group) with no supplementary group,
	// so a root caller never reads a user's folder with root's rights or
	// groups. A root caller must name an account other than root.
	UID, GID uint32
}

// geteuid is os.Geteuid; tests replace it.
var geteuid = os.Geteuid

// codesignCredential is the account codesign runs as: nil when this process
// is not root (it already runs as the account), else the account's uid and
// primary gid with every supplementary group dropped (setgroups with an
// empty list), never root's groups.
func codesignCredential(opts DarwinOptions, euid int) *syscall.Credential {
	if euid != 0 {
		return nil
	}
	return &syscall.Credential{Uid: opts.UID, Gid: opts.GID, Groups: []uint32{}, NoSetGroups: false}
}

// VerifyDarwin checks that the code at path (an app bundle or a Mach-O
// file) has a valid signature that satisfies want's requirement, with
// /usr/bin/codesign --verify --strict. It runs nothing from path and is
// bounded by VerifyTimeout. On any other OS it reports that it cannot
// verify.
func VerifyDarwin(ctx context.Context, path string, want Darwin, opts DarwinOptions) Result {
	requirement, err := want.Requirement()
	if err != nil {
		return refused("%v", err)
	}
	return verifyDarwinRequirement(ctx, path, requirement,
		fmt.Sprintf("%s is not signed by Apple Developer ID team %s with identifier %s", path, want.TeamID, want.Identifier), opts)
}

// verifyDarwinRequirement is VerifyDarwin for one requirement; unmet is the
// reason when the code is validly signed but does not satisfy it.
func verifyDarwinRequirement(ctx context.Context, path, requirement, unmet string, opts DarwinOptions) Result {
	if !darwinHost {
		return refused("code signatures are checked only on macOS")
	}
	euid := geteuid()
	if euid == 0 && (opts.UID == 0 || opts.GID == 0) {
		return refused("the signature check of %s runs as the account that owns it, never as root", path)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return refused("%s is not a clean absolute path", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return refused("%s cannot be read: %v", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return refused("%s is a symbolic link", path)
	}
	before, err := pinFiles(opts.Pin)
	if err != nil {
		return refused("%v", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, VerifyTimeout)
	defer cancel()
	// The path is absolute, so codesign never reads it as an option.
	cmd := exec.CommandContext(ctx, codesignBinary, "--verify", "--strict", "-R="+requirement, path)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	output := &cappedBuffer{limit: maxCodesignOutput}
	cmd.Stdout, cmd.Stderr = output, output
	if credential := codesignCredential(opts, euid); credential != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
	}
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return refused("the signature check of %s did not finish within %s", path, VerifyTimeout)
	}
	after, err := pinFiles(opts.Pin)
	if err != nil || !samePins(before, after) {
		return refused("%s changed while its signature was checked", path)
	}
	if runErr == nil {
		return Result{Verified: true}
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) && exitErr.ExitCode() == 3 {
		// codesign exits 3 when the code is validly signed but fails the
		// requirement: another team, identifier or certificate type.
		return refused("%s", unmet)
	}
	detail := boundedText(output.String())
	if detail == "" {
		detail = runErr.Error()
	}
	result := refused("the code signature of %s does not verify: %s", path, detail)
	result.Unsigned = strings.Contains(output.String(), "code object is not signed at all")
	return result
}

// VerifyAuthenticode is available only on Windows.
func VerifyAuthenticode(path string, publishers []string) Result {
	return refused("Authenticode signatures are checked only on Windows")
}

// pin is the identity of one pinned file.
type pin struct {
	dev, ino       uint64
	size           int64
	mode           os.FileMode
	mtime, ctimeNs int64
}

func pinFiles(paths []string) ([]pin, error) {
	out := make([]pin, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("%s cannot be read: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", path)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("%s has no file identity", path)
		}
		out = append(out, pin{dev: uint64(st.Dev), ino: st.Ino, size: info.Size(), mode: info.Mode(),
			mtime: info.ModTime().UnixNano(), ctimeNs: statChangeTime(st)})
	}
	return out, nil
}

func samePins(a, b []pin) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// cappedBuffer keeps at most limit bytes and drops the rest.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := c.limit - c.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			c.buf.Write(p[:remaining])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }
