// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The connector registry's shell tools and pre-tool events, as
// TestGAP0545EveryRegisteredShellToolGetsTheKitsProofs reads them.

func gap0545StructuredActionEvents(name string) []string {
	return connector.StructuredActionEvents(name)
}

func gap0545ShellTools(name string) []string { return connector.ShellTools(name) }

func gap0545ShellCommandKey(name, tool string) string { return connector.ShellCommandKey(name, tool) }

func gap0545FileToolPathKeys() []string { return actionfacts.FileToolPathKeys() }
