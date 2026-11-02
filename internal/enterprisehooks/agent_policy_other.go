//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func platformPrepareAgentPolicy(context.Context, string, string, string, int, int, *connector.SetupOpts) {
}
