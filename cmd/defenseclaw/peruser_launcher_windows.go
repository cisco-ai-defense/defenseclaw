// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func runWindowsPerUserCLI() (bool, int) {
	executable, err := os.Executable()
	if err != nil || !perUserLauncherPath(executable) {
		return false, 0
	}
	stateFile, err := os.Open(filepath.Join(filepath.Dir(executable), "defenseclaw-hook-state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return false, 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: read per-user launcher state: %v\n", err)
		return true, 1
	}
	defer stateFile.Close()
	stateData, err := io.ReadAll(io.LimitReader(stateFile, (128<<10)+1))
	if err != nil || len(stateData) > 128<<10 {
		fmt.Fprintln(os.Stderr, "defenseclaw: per-user launcher state cannot be read; rerun the Windows installer")
		return true, 1
	}
	target, matched, err := perUserLauncherTarget(executable, stateData, os.Getenv("DEFENSECLAW_HOME"), windowsPerUserRootIsReparse)
	if !matched {
		return false, 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: %v\n", err)
		return true, 1
	}
	command := exec.Command(target, os.Args[1:]...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return true, exit.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "defenseclaw: start per-user CLI: %v\n", err)
		return true, 1
	}
	return true, 0
}

func windowsPerUserRootIsReparse(root string) (bool, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true, nil
	}
	attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && attributes.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}
