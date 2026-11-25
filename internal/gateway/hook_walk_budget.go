// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

type hookWalkBudgetKey struct{}

// withHookWalkBudget gives every dispatch under ctx one wait for walk slots:
// the wait of the hook request. A request judged as several top-level
// dispatches (the calls of a Copilot toolCalls envelope, the members of an
// artifact, the readings of a sandboxed or Codex shell command) answers in
// the one round trip the hook client waits for, so their waits cannot add up
// past it, as withHookJudgeBudget does for the judge (substrate-1:GAP-1083,
// RV-0674S F1). A ctx that already has one keeps it. The dispatch makes its
// own wait only for a call that comes with none (an ACP frame, a direct
// evaluation).
func withHookWalkBudget(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if hookWalkBudgetFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, hookWalkBudgetKey{}, actionfacts.NewCredentialWalkBudget(ctx))
}

// hookWalkBudgetFrom is the wait of the hook request ctx belongs to, nil if
// it has none.
func hookWalkBudgetFrom(ctx context.Context) *actionfacts.CredentialWalkBudget {
	if ctx == nil {
		return nil
	}
	budget, _ := ctx.Value(hookWalkBudgetKey{}).(*actionfacts.CredentialWalkBudget)
	return budget
}
