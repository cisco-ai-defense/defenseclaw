// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package winpath

import "os"

// OpenReadShared is os.Open: POSIX opens never block a rename or replace.
func OpenReadShared(path string) (*os.File, error) { return os.Open(path) }
