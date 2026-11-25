// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

// gap0674WindowsForms: only a Windows host has the Windows spellings of a
// folder.
func gap0674WindowsForms(*testing.T, string) []gap0674FolderForm { return nil }
