//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// attestedClaudeKit is what the signed statement of a Claude Code template
// built by this kit says: the connector, the pinned agent version and the
// hook contract the kit installs.
func attestedClaudeKit() SubstrateTemplateKit {
	return SubstrateTemplateKit{Connector: "claudecode", AgentVersion: kit.AgentVersion("claudecode", ""),
		HookContract: "claudecode-hooks-v2", KitVersion: "stk", Digest: "sha256:" + "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"}
}

// chartTemplateActions are the create path's actions over the Control API
// with the template's attested kit.
func chartTemplateActions(c ateapi.Client, k SubstrateTemplateKit) *SubstrateATEActions {
	return &SubstrateATEActions{Client: c, Ensure: func(context.Context, string, string) error { return nil },
		TemplateKit: func(context.Context, *ateapi.ActorTemplate) (SubstrateTemplateKit, error) { return k, nil }}
}
