// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package managed

import "os"

// mkdirServiceRuntimeDir creates a missing service runtime directory.
func mkdirServiceRuntimeDir(path string) error { return os.Mkdir(path, 0o700) }
