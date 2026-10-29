// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

// actionProcessOwnsHome is false on Windows: the walk keeps a directory it
// cannot list as unproved.
func actionProcessOwnsHome(string) bool { return false }
