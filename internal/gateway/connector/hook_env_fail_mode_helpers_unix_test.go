// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "slices"

// writePerUserHooksForTestFailMode renders a connector's per-user hooks as
// WriteHookScriptsForConnectorObject does, installed open when the run's
// environment asks for DEFENSECLAW_FAIL_MODE=open. A per-user hook no longer
// takes an open mode from its environment, so a test of the fail-open path
// installs it open the way guardrail fail-mode open does.
func writePerUserHooksForTestFailMode(hookDir, apiAddr, token string, c Connector, extraEnv []string) error {
	if !slices.Contains(extraEnv, "DEFENSECLAW_FAIL_MODE=open") {
		return WriteHookScriptsForConnectorObject(hookDir, apiAddr, token, c)
	}
	opts := SetupOpts{APIAddr: apiAddr, APIToken: token}
	var extras []string
	if owner, ok := c.(HookScriptOwner); ok {
		extras = owner.HookScriptNames(opts)
	}
	return writeHookScriptsCommonWithOptions(hookDir, apiAddr, token, "open", extras, false, c.Name(), !IsProxyConnector(c.Name()))
}
