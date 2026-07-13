// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "fmt"

func validateEnterpriseHookScopedTokenLocation(_, _ string) error {
	return fmt.Errorf("enterprise hook scoped tokens are unsupported on Windows until SID and DACL validation is implemented")
}

func alignEnterpriseHookScopedTokenOwner(_, _ string) error {
	return fmt.Errorf("enterprise hook scoped tokens are unsupported on Windows until target-user impersonation is implemented")
}
