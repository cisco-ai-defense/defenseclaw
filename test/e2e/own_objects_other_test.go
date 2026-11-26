// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package e2e

// ownNewObjectsAsTokenUser is a no-op off Windows: new files belong to the
// user already.
func ownNewObjectsAsTokenUser() {}
