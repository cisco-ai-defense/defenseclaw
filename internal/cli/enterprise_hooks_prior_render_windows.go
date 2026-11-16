// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/enterprisehooks"

func init() {
	// The guardian's read-only second verify of a signed-out account's
	// Copilot row accepts the Local hook files of releases up to 1.0.6
	// (GAP-0980).
	enterprisehooks.SetWindowsCopilotVSCodeUserPriorRender(func(home string) error {
		return windowsCopilotVSCodeUserAccepting(home, true, false, true)
	})
}
