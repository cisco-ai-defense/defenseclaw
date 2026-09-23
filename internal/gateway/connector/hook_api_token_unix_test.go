// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "testing"

func TestHookAPITrustedOwnerRejectsUnrelatedUID(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")
	t.Setenv("SUDO_USER", "")
	if hookAPITrustedOwner(^uint32(0)) {
		t.Fatal("hook API trusted an unrelated UID")
	}
}
