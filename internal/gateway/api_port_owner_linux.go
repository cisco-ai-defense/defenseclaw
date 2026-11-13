// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// procNetRoot is the /proc the port owner reader uses; replaceable in tests.
var procNetRoot = "/proc"

// procNetMaxBytes bounds one /proc/net table read.
const procNetMaxBytes = 32 << 20

// apiPortHolderUID reads /proc/net/tcp and /proc/net/tcp6 for the account
// that listens on the port of addr (S1 DESIGN 17.1). found is false when
// no listener blocks the address (the holder exited, or it is in another
// network namespace).
func apiPortHolderUID(addr string, self int) (uid int, found bool, err error) {
	ip, port, ok := apiBindIP(addr)
	if !ok {
		return 0, false, fmt.Errorf("api address %q", addr)
	}
	var all []procNetListener
	var readErr error
	for _, name := range []string{"tcp", "tcp6"} {
		data, err := readProcNet(filepath.Join(procNetRoot, "net", name))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) && readErr == nil {
				readErr = err
			}
			continue
		}
		all = append(all, parseProcNetTCP(data)...)
	}
	uid, found = apiPortHolder(all, ip, port, self)
	if !found && readErr != nil {
		return 0, false, readErr
	}
	return uid, found, nil
}

func readProcNet(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, procNetMaxBytes))
}
