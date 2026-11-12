//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"context"
	"fmt"
	"io/fs"
	"os/exec"
	"syscall"
	"time"
)

// darwinACLInspectionTimeout bounds one `/bin/ls -lde` run. An Endpoint
// Security client that stalls the exec, or a hung volume, must not block
// config load, a guardian tick or the audit open indefinitely.
const darwinACLInspectionTimeout = 5 * time.Second

// inspectDarwinACL is replaced in tests.
var inspectDarwinACL = func(ctx context.Context, path string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "/bin/ls", "-lde", "--", path)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	return cmd.Output()
}

// readDarwinACL returns the `ls -lde` output for path. A timeout or exec
// failure is transient (a busy Endpoint Security client, a volume waking up),
// so it is retried once before it is reported.
func readDarwinACL(path string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), darwinACLInspectionTimeout)
		output, err := inspectDarwinACL(ctx, path)
		timedOut := ctx.Err() == context.DeadlineExceeded
		cancel()
		if err == nil {
			return output, nil
		}
		if timedOut {
			lastErr = fmt.Errorf("inspect macOS ACL for %s: timed out after %s", path, darwinACLInspectionTimeout)
		} else {
			lastErr = fmt.Errorf("inspect macOS ACL for %s: %w", path, err)
		}
	}
	return nil, lastErr
}

// validateTrustedPathACL rejects effective macOS ACL entries that grant
// write-like authority beyond the POSIX owner/group/mode metadata validated by
// trust_unix.go. macOS keeps those mode bits unchanged when an ACL is added, so
// ignoring the extended entries would misclassify an attacker-writable path as
// administrator-trusted.
//
// For Secure Client the verdict is JudgeDarwinACLOutput: write-class rights
// for a principal other than root, wheel or admin. Read, deny and
// inherit-only entries grant no write on the object itself and are not
// judged. A standalone process (StandaloneTrustScope) keeps the stricter
// validateStrictPathACL rule.
//
// Reading an ACL starts /bin/ls, and the managed gateway checks every element
// of its identity spool path on every hook call, so a burst of parallel tool
// calls spent its time starting ls processes (GAP-1822). A path whose ACL was
// read and found clean is therefore not read again while its inode metadata
// is unchanged: an ACL change, like any metadata change, sets the inode
// change time, and a replaced path has another inode. A failed or timed-out
// read is never cached.
func validateTrustedPathACL(path string) error {
	if StandaloneTrustScope() {
		return validateStrictPathACL(path)
	}
	return darwinACLVerdicts.check(path, darwinACLStatKey, darwinACLInspect)
}

// validateStrictPathACL rejects any allow entry with a write-capable right,
// whatever principal it names and whether or not it is inherit-only. It is
// the rule of ValidatePathACL and of the standalone trust walks.
func validateStrictPathACL(path string) error {
	return darwinStrictACLVerdicts.check(path, darwinACLStatKey, darwinStrictACLInspect)
}

// darwinACLVerdicts and darwinStrictACLVerdicts hold the clean ACL verdicts
// of the process under each rule.
var darwinACLVerdicts, darwinStrictACLVerdicts aclVerdictCache

// darwinACLInspect and darwinStrictACLInspect read and judge the ACL of path
// (variables for tests).
var (
	darwinACLInspect       = judgeDarwinPathACL
	darwinStrictACLInspect = judgeDarwinPathACLStrict
)

// darwinACLStatKey is the inode metadata a clean ACL verdict of path stays
// valid for.
func darwinACLStatKey(path string) (aclVerdictKey, error) {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return aclVerdictKey{}, err
	}
	return aclVerdictKey{
		path:  path,
		dev:   uint64(st.Dev),
		ino:   st.Ino,
		ctime: st.Ctimespec.Nano(),
		mode:  uint32(st.Mode),
		uid:   st.Uid,
		gid:   st.Gid,
	}, nil
}

func judgeDarwinPathACL(path string) error {
	output, err := readDarwinACL(path)
	if err != nil {
		return err
	}
	return JudgeDarwinACLOutput(path, output)
}

func judgeDarwinPathACLStrict(path string) error {
	output, err := readDarwinACL(path)
	if err != nil {
		return err
	}
	return JudgeDarwinACLOutputStrict(path, output)
}

// validateAccountPathACL is ValidatePathACLForAccount on macOS.
func validateAccountPathACL(path string, _ int, account string) error {
	output, err := readDarwinACL(path)
	if err != nil {
		return err
	}
	return JudgeDarwinACLOutputForAccount(path, output, account)
}

// modeWithoutACLMask: a macOS ACL never changes the mode bits, so they stand.
func modeWithoutACLMask(_ string, mode fs.FileMode) fs.FileMode { return mode }
