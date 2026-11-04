// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// hookGetenv reads the hook's environment (replaceable in tests).
var hookGetenv = os.Getenv

// applyCoworkContext tags a claudecode hook call that runs for Claude Cowork
// (hookexec.CoworkHeader): the engine set CLAUDE_CODE_IS_COWORK=1, and the
// agent process that runs the hook is Claude Desktop's bundled Claude Code
// build (its executable lives in Claude Desktop's data folder or app
// bundle). The process lookup runs only when the flag is set, so other
// calls pay nothing. A call whose engine cannot be named is not tagged. The
// tag is attribution for the audit; the user identity still comes from the
// operating system. Secure Client hooks keep the request of main.
func applyCoworkContext(opts *hookexec.Options) {
	if opts == nil || opts.SecureClient || !strings.EqualFold(strings.TrimSpace(opts.Connector), "claudecode") {
		return
	}
	cowork, ok := hookexec.CoworkSessionFromEnv(hookGetenv)
	if !ok {
		return
	}
	if connector.ClassifyAgentSurface("claudecode", hookAgentExecutable(), nil) != connector.HostSurfaceDesktop {
		return
	}
	opts.Cowork = &cowork
}
