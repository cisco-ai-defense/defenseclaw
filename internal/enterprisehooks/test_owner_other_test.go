// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

// ownTestObjectsAsTokenUser changes nothing off Windows: a new file is owned
// by the process's own user.
func ownTestObjectsAsTokenUser() error { return nil }
