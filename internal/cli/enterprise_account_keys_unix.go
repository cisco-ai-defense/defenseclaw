// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// enterpriseAccountKeysEUID is os.Geteuid (replaceable in tests).
var enterpriseAccountKeysEUID = os.Geteuid

// enterpriseAccountKeysManagedInstalled reports whether the managed gateway
// is installed at path, a regular file (replaceable in tests). A per-user
// install has no managed layout, so its refusal must not tell the user to run
// a binary that does not exist (rel-1-0-6:GAP-0417).
var enterpriseAccountKeysManagedInstalled = func(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func runEnterpriseAccountKeys(cmd *cobra.Command) error {
	env, err := newUnixLifecycleEnv(enterpriseunix.CurrentGOOS())
	if err != nil {
		return withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	if enterpriseAccountKeysEUID() != 0 {
		gateway := filepath.Join(env.Layout.BinDir, "defenseclaw-gateway")
		if !enterpriseAccountKeysManagedInstalled(env.P(gateway)) {
			return secretFailed("not_installed", enterprisestatus.UnixExitFailure, fmt.Errorf(
				"account join keys exist only on a managed (enterprise) install of DefenseClaw, and this computer has none (%s is not installed); "+
					"a per-user install has no account join keys to print", gateway))
		}
		return secretFailed("not_root", enterprisestatus.UnixExitFailure, fmt.Errorf("the account join keys require administrator rights; run: sudo %s enterprise account-keys",
			gateway))
	}
	return printEnterpriseAccountKeys(cmd.OutOrStdout(), env.AccountJoinReport())
}
