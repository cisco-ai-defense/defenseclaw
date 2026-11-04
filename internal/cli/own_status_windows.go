// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/spf13/cobra"

// newLauncherStatusCommand is nil: Windows has no launcher.
func newLauncherStatusCommand() *cobra.Command { return nil }
