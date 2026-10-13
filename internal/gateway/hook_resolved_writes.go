// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "context"

type resolvedWritesContextKey struct{}

func resolvedWritesFromContext(ctx context.Context) map[string]string {
	targets, _ := ctx.Value(resolvedWritesContextKey{}).(map[string]string)
	return targets
}
