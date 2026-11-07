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
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// persistAuditEvent requires the canonical logger; direct Store writes are not
// an ordinary target-runtime capability.
func persistAuditEvent(logger *audit.Logger, event audit.Event) error {
	if logger == nil {
		return errors.New("gateway: canonical audit logger unavailable")
	}
	return logger.LogEvent(event)
}

func persistAuditEventCtx(ctx context.Context, logger *audit.Logger, event audit.Event) error {
	if logger == nil {
		return errors.New("gateway: canonical audit logger unavailable")
	}
	return logger.LogEventCtx(ctx, event)
}

// bodyIdentityStructuredKeys are the structured facts the gateway sets from the
// verified caller and the verified agent identity of a request. A posted
// event is only a claim, so it never supplies them.
var bodyIdentityStructuredKeys = []string{
	auditUserIDKey, auditUserIDKindKey, auditUserNameKey,
	"defenseclaw.agent.identity.id", "defenseclaw.agent.depth",
}

// dropBodyAssignedIdentity removes the identity the gateway assigns from a
// posted audit event: the agent identity and instance, the sidecar instance and
// the verified caller facts. The agent instance (ais-) is the key by which
// alerts --show borrows a hook or inspect row (GAP-0647), so a row written
// through POST /audit/event must not be able to carry the instance of another request
// and change the Agent shown for an earlier finding.
func dropBodyAssignedIdentity(event *audit.Event) {
	event.AgentID, event.AgentInstanceID, event.SidecarInstanceID = "", "", ""
	for _, key := range bodyIdentityStructuredKeys {
		delete(event.Structured, key)
	}
}
