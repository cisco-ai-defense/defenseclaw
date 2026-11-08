// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

// newUnixOpenCodePortClearCommand: the guardian keeps no OpenCode port record
// on Windows yet (pod g053w); the action is not offered there.
func newUnixOpenCodePortClearCommand(string) *cobra.Command {
	return &cobra.Command{
		Use:    "opencode-port-clear <port>",
		Hidden: true,
		RunE: func(*cobra.Command, []string) error {
			return errors.New("opencode-port-clear is not available on this platform")
		},
	}
}

// newUnixOpenCodePortUnknownClearCommand: no OpenCode port record on Windows
// yet; the action is not offered there.
func newUnixOpenCodePortUnknownClearCommand(string) *cobra.Command {
	return &cobra.Command{
		Use:    "opencode-port-unknown-clear <uid>",
		Hidden: true,
		RunE: func(*cobra.Command, []string) error {
			return errors.New("opencode-port-unknown-clear is not available on this platform")
		},
	}
}
