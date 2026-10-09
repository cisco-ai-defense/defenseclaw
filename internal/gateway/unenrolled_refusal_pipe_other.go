// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "context"

// serveUnenrolledRefusals is Windows only: the Unix standalone gateway
// refuses and audits an unenrolled caller on its hook socket.
func (a *APIServer) serveUnenrolledRefusals(context.Context) {}
