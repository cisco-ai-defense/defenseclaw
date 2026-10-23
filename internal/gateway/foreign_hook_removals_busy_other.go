// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

// foreignHookRemovalsReadBusy is Windows-only: a rename never leaves the
// ledger unopenable here.
func foreignHookRemovalsReadBusy(error) bool { return false }
