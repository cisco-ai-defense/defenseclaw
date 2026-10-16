//go:build !linux && !darwin && !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

func (r *NSSResolver) platformGroupIDs(account Account) ([]int, error) {
	return r.rawGroupIDs(account)
}
