// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// agentHostAuditExtra is the hook audit field for the agent host tag.
const agentHostAuditExtra = "agent_host"

type agentHostContextKey struct{}

// withAgentHost keeps the agent host tag a managed standalone hook sends
// (hookexec.AgentHostHeader: the process that started the agent, such as
// Devin Desktop for Devin Local) for the request's hook audit. Any local
// process can set the header, so it is attribution only and never reaches a
// policy decision.
func withAgentHost(ctx context.Context, header http.Header) context.Context {
	host := hookexec.AgentHostHeaderValue(header.Get(hookexec.AgentHostHeader))
	if host == "" {
		return ctx
	}
	return context.WithValue(ctx, agentHostContextKey{}, host)
}

func agentHostExtra(ctx context.Context) map[string]string {
	host, _ := ctx.Value(agentHostContextKey{}).(string)
	if host == "" {
		return nil
	}
	return map[string]string{agentHostAuditExtra: host}
}
