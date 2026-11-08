// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package connector

import "os"

// Group write on non-Linux Unix remains untrusted for connector directories.
func ownerPrivateGroup(string, os.FileInfo) bool { return false }

// Group write on non-Linux Unix remains untrusted for the managed setter too.
func ownerPrivateGroupStrictAfterACL(string, os.FileInfo) bool { return false }
