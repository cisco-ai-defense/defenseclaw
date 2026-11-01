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

func runEnterpriseAccountKeys(cmd *cobra.Command) error {
	env, err := newUnixLifecycleEnv(enterpriseunix.CurrentGOOS())
	if err != nil {
		return withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	if enterpriseAccountKeysEUID() != 0 {
		return secretFailed("not_root", enterprisestatus.UnixExitFailure, fmt.Errorf("the account join keys require administrator rights; run: sudo %s enterprise account-keys",
			filepath.Join(env.Layout.BinDir, "defenseclaw-gateway")))
	}
	return printEnterpriseAccountKeys(cmd.OutOrStdout(), env.AccountJoinReport())
}
