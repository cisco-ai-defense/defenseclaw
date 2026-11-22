// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package watcher

// ownedByAnotherAccount is false on Windows: the folder ACL decides whether
// the watcher may create a root, and a root it cannot create is watched once
// it exists (GAP-1251).
func ownedByAnotherAccount(string) bool { return false }
