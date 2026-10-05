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

import "github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"

// copilotCLIMachinePolicyInForce reports whether DefenseClaw's own entries
// are present in the standalone deployment's Copilot policy.d drop-in; a
// read, trust or parse error is not in force (GAP-1779).
func copilotCLIMachinePolicyInForce() bool {
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return false
	}
	opts := enterprisepolicy.LayoutOptions(layout, programFiles, programData)
	present, err := enterprisepolicy.MachinePolicyPresent(opts, enterprisepolicy.ConnectorCopilot)
	return err == nil && present
}
