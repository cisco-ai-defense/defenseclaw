//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtimeowner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"time"
)

const (
	getentTimeout     = 5 * time.Second
	getentOutputLimit = 8 << 10
)

// getentPaths are the root-owned getent binaries, in order of preference.
var getentPaths = []string{"/usr/bin/getent", "/bin/getent"}

// lookupAccount resolves name for the sudo-invoker check. The release gateway
// is a static binary, so os/user reads /etc/passwd only and never asks NSS:
// an account that SSSD, LDAP or winbind provides (an Active Directory account
// on a joined host) was "unknown", and a root start for it was refused after
// it had already written its first files (GAP-0714). When os/user does not
// know the name, NSS is asked through the root-owned getent, the same account
// database the rest of the product reads (unixidentity.NSSResolver).
func lookupAccount(name string) (*user.User, error) {
	account, err := user.Lookup(name)
	if err == nil {
		return account, nil
	}
	var unknown user.UnknownUserError
	if !errors.As(err, &unknown) {
		return nil, err
	}
	if found, ok := getentAccount(name, runGetent); ok {
		return found, nil
	}
	return nil, err
}

// getentAccount asks NSS for name through run, which returns getent's exit
// code and bounded stdout. Only a complete passwd entry counts; the caller
// compares its uid and gid with SUDO_UID and SUDO_GID.
func getentAccount(name string, run func(args ...string) (int, []byte, error)) (*user.User, bool) {
	if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, ":\n\r\x00") {
		return nil, false
	}
	code, out, err := run("passwd", "--", name)
	if err != nil || code != 0 {
		return nil, false
	}
	line := strings.TrimRight(string(out), "\r\n")
	fields := strings.Split(line, ":")
	if strings.Contains(line, "\n") || len(fields) != 7 || fields[0] == "" || fields[2] == "" || fields[3] == "" {
		return nil, false
	}
	return &user.User{Username: fields[0], Uid: fields[2], Gid: fields[3], Name: fields[4], HomeDir: fields[5]}, true
}

// runGetent runs the first root-owned getent that nobody else can write, with
// a fixed environment and a timeout. An exit code is the answer, not an error.
func runGetent(args ...string) (int, []byte, error) {
	path := ""
	for _, candidate := range getentPaths {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0 {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid == 0 {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		return 0, nil, errors.New("runtimeowner: no trusted getent binary")
	}
	ctx, cancel := context.WithTimeout(context.Background(), getentTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "LANG=C"}
	cmd.Dir = "/"
	var stdout bytes.Buffer
	cmd.Stdout = &limitWriter{buf: &stdout, limit: getentOutputLimit}
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	return 0, stdout.Bytes(), nil
}

// limitWriter refuses output past limit, so a broken directory backend cannot
// grow this process without bound.
type limitWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.limit {
		return 0, errors.New("runtimeowner: getent output exceeds limit")
	}
	return w.buf.Write(p)
}
