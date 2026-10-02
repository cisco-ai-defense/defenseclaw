//go:build !linux && !darwin

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
	"net"
	"net/http"
)

// heldAPIPortRetriedWithoutHookSocket: a Windows standalone gateway has no
// hook socket, so its loopback TCP API is the only hook transport. When
// another process holds the port past the first bind's budget, Run keeps
// retrying the bind and reports the API as failed instead of returning: the
// sidecar keeps running after the API goroutine exits, so returning left the
// service Running without a hook API until an administrator restarted it
// again. Replaceable in tests.
var heldAPIPortRetriedWithoutHookSocket = true

// newManagedHookSocketServer: the standalone hook socket is unix-only.
// Windows hooks keep the loopback TCP transport with the SCM service-PID
// peer check.
func (a *APIServer) newManagedHookSocketServer(context.Context, func(http.Handler) http.Handler) (*http.Server, net.Listener, error) {
	return nil, nil, nil
}
