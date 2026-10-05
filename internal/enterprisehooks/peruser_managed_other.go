// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import "github.com/defenseclaw/defenseclaw/internal/gateway/connector"

// RegisterWindowsStandalonePerUserConnectors only applies to native Windows.
func RegisterWindowsStandalonePerUserConnectors(*connector.Registry) {}
