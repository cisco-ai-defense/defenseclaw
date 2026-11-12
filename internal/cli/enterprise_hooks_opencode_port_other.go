//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func enterpriseHookStandaloneOpenCodePorts(context.Context, enterprisehooks.Manifest) (map[string]int, error) {
	return nil, nil
}
