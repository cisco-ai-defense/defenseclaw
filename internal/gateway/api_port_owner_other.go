// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package gateway

// apiPortHolderOf names no holder on macOS: it has no /proc and its socket
// table does not name another account's listener to this account (S1
// DESIGN 17.1; doctor warns on a shared Mac instead).
func apiPortHolderOf(string) (apiPortHolderInfo, error) { return apiPortHolderInfo{}, nil }
