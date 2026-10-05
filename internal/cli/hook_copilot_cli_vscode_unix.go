// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import "github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"

// copilotCLIMachinePolicyInForce reports whether DefenseClaw's own Copilot
// entries are present in the standalone machine policy; a read or parse
// error is not in force.
func copilotCLIMachinePolicyInForce() bool {
	opts, ok := standaloneMachinePolicyOptions(standaloneHookGOOS)
	if !ok {
		return false
	}
	present, err := enterprisepolicy.MachinePolicyPresent(opts, enterprisepolicy.ConnectorCopilot)
	return err == nil && present
}
