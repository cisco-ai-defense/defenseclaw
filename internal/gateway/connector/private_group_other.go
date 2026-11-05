// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package connector

import "os"

// ownerPrivateGroup is Linux-only (see private_group_linux.go): macOS
// accounts share the staff group, so group write stays refused there.
func ownerPrivateGroup(string, os.FileInfo) bool { return false }
