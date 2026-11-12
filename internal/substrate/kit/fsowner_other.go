// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package kit

import (
	"errors"
	"os"
)

// The actor kit runs only in Linux actors; other platforms build the package
// for tooling and tests and refuse to load a configuration.
func rootOwned(string) error { return errors.New("actor kit config: only Linux actors are supported") }

func fileOwner(os.FileInfo) (uid, gid int, nlink uint64) { return -1, -1, 0 }
