// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package vault

import (
	"sync"
	"time"
)

const lockWait = 5 * time.Second

// Sandboxes do not run on Windows, so only the CLI writes the vault there;
// one process-wide lock is enough.
var windowsLock sync.Mutex

func lockDir(string, time.Duration) (func(), error) {
	windowsLock.Lock()
	return windowsLock.Unlock, nil
}
