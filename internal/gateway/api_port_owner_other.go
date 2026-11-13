// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package gateway

// apiPortHolderUID is Linux-only (S1 DESIGN 17.1): Windows reports another
// account through its bind error (isAPIPortHeldByAnotherAccount), and macOS
// has no /proc (doctor warns on a shared Mac instead).
func apiPortHolderUID(string, int) (int, bool, error) { return 0, false, nil }
