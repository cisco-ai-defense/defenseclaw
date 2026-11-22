//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
)

// startEnterpriseHookPeerBroker is Windows only: Linux and macOS read the
// loopback peer uid in the gateway itself.
func startEnterpriseHookPeerBroker(context.Context, io.Writer) {}
