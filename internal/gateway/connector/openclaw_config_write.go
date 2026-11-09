// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"sync"
)

// openClawLastWrite is the SHA-256 of the bytes this process last passed to its
// own write of openclaw.json. It lives in this process only: the CLI that
// started the gateway asks for it over the gateway's authenticated status, so a
// failed setup knows what its own registration wrote without trusting a file
// anyone else could copy (GAP-0973).
var openClawLastWrite struct {
	mu  sync.Mutex
	sum string
}

// writeOpenClawConfig writes openclaw.json and remembers the digest of data, the
// slice handed to the write, never a read-back of the file.
func writeOpenClawConfig(path string, data []byte, perm os.FileMode) error {
	if err := atomicWriteFile(path, data, perm); err != nil {
		return err
	}
	openClawLastWrite.mu.Lock()
	openClawLastWrite.sum = sha256Hex(data)
	openClawLastWrite.mu.Unlock()
	return nil
}

// LastOpenClawConfigWrite is the hex SHA-256 of the bytes this process last
// wrote to openclaw.json, and false while it has written none.
func LastOpenClawConfigWrite() (string, bool) {
	openClawLastWrite.mu.Lock()
	defer openClawLastWrite.mu.Unlock()
	return openClawLastWrite.sum, openClawLastWrite.sum != ""
}
