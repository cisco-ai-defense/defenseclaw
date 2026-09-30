// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func findPortHolder(port int) (PortHolder, error) {
	return findProcPortHolder("/proc", port)
}

// findProcPortHolder reads the kernel's TCP tables for a LISTEN socket on
// port, then finds the process that owns that socket among the processes
// whose descriptors this account may read.
func findProcPortHolder(procRoot string, port int) (PortHolder, error) {
	holder := PortHolder{UID: -1}
	inodes := map[string]struct{}{}
	for _, table := range []string{"tcp", "tcp6"} {
		file, err := os.Open(filepath.Join(procRoot, "net", table))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Scan() // header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			_, portHex, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			if value, err := strconv.ParseUint(portHex, 16, 16); err != nil || int(value) != port {
				continue
			}
			if uid, err := strconv.Atoi(fields[7]); err == nil && holder.UID < 0 {
				holder.UID = uid
			}
			inodes["socket:["+fields[9]+"]"] = struct{}{}
		}
		_ = file.Close()
	}
	if len(inodes) == 0 {
		return holder, ErrNoListener
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return holder, nil
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(procRoot, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if _, ok := inodes[target]; ok {
				holder.PID = pid
				if comm, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "comm")); err == nil {
					holder.Command = strings.TrimSpace(string(comm))
				}
				return holder, nil
			}
		}
	}
	return holder, nil
}
