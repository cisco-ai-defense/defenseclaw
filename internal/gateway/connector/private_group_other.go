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

// The local-sources proof is false off Linux as well.
func ownerPrivateGroupLocalSources(string, os.FileInfo) bool { return false }

// Without a proof of a private group nothing consults the PAM stack here; if
// asked, the module counts as loaded.
func pamGroupLoaded() bool { return true }
