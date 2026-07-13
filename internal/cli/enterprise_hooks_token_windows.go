// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func validateEnterpriseHookScopedTokenLocation(_, _ string) error {
	return fmt.Errorf("enterprise hook scoped tokens are unsupported on Windows until SID and DACL validation is implemented")
}

func alignEnterpriseHookScopedTokenOwner(_, _ string) error {
	return fmt.Errorf("enterprise hook scoped tokens are unsupported on Windows until target-user impersonation is implemented")
}

func validateEnterpriseOTLPTokenLocation(_ string, _ connector.OTLPPathTokenScope) error {
	return fmt.Errorf("enterprise OTLP scoped tokens are unsupported on Windows until SID and DACL validation is implemented")
}

func alignEnterpriseOTLPTokenOwner(_ string, _ connector.OTLPPathTokenScope) error {
	return fmt.Errorf("enterprise OTLP scoped tokens are unsupported on Windows until target-user impersonation is implemented")
}
