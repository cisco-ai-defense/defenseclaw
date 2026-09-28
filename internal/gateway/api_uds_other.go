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

// newManagedHookSocketServer: the standalone hook socket is unix-only.
// Windows hooks keep the loopback TCP transport with the SCM service-PID
// peer check.
func (a *APIServer) newManagedHookSocketServer(context.Context, func(http.Handler) http.Handler) (*http.Server, net.Listener, error) {
	return nil, nil, nil
}
