// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

func validateEnterpriseHookScopedTokenLocation(_, _ string) error {
	return nil
}

func alignEnterpriseHookScopedTokenOwner(_, _ string) error {
	return nil
}
