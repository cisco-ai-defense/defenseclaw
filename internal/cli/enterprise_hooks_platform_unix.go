//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/spf13/cobra"
)

var enterpriseHookSIDProfilePath = func(string) (string, error) {
	return "", fmt.Errorf("SID-only targets are supported only on native Windows")
}

func syncEnterpriseHookManagedEnrollments(
	enterprisehooks.Manifest,
	string,
	bool,
) error {
	return nil
}

func verifyEnterpriseHookManagedEnrollments(
	enterprisehooks.Manifest,
	string,
) error {
	return nil
}

func enterpriseHooksNativePlatformPreflight() error { return nil }

func enterpriseHooksNativeMutationIdentityPreflight() error { return nil }

func enterpriseHooksNativePersistentPreRun(cmd *cobra.Command, args []string) error {
	return enterpriseHooksFullRootPersistentPreRun(cmd, args)
}
