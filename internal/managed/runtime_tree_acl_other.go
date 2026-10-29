// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !windows

package managed

// runtimeTreeHasNoACL: the per-entry ACL check is one system call here.
func runtimeTreeHasNoACL(string) bool { return false }
