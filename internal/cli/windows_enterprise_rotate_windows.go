// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// errWindowsCredentialRotationUnavailable explains why `enterprise windows
// rotate-credentials` refuses. On Linux and macOS the lifecycle rotates the
// per-user credential key as one transaction with the hook guardian: the
// gateway accepts the old and the new key while the guardian moves every
// user, and the new key takes effect only after every user is verified on
// it. The Windows lifecycle runs as an installer transaction, and its
// guardian renders a user's credentials into their runtime bundle only
// while that user's session is available, so it has no participant that
// can move every user before a new key takes effect. Replacing the key
// there would refuse users' hooks until each one signed in again.
var errWindowsCredentialRotationUnavailable = errors.New(
	"rotate-credentials is not available for Windows managed deployments yet: the Windows lifecycle cannot move " +
		"every user to a new per-user credential key before the key takes effect, because its hook guardian " +
		"renders a user's credentials only while that user is signed in. Nothing was changed.")

func newWindowsRotateCredentialsCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "rotate-credentials",
		Short:              "Not available on Windows (see the enterprise operations guide)",
		SilenceUsage:       true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Flag parsing is off so any other argument gets the refusal;
			// a request for help still gets the help.
			for _, arg := range args {
				if arg == "-h" || arg == "--help" {
					return cmd.Help()
				}
			}
			return withExitCode(errWindowsCredentialRotationUnavailable, enterprisestatus.WindowsExitInvalidArgs)
		},
	}
}

func init() {
	enterpriseWindowsCmd.AddCommand(newWindowsRotateCredentialsCommand())
}
