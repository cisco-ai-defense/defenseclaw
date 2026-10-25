// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || windows

package hookexec

import "errors"

// A just-connected client can precede the accepted server row in the OS
// socket table. Only this absence is retried by per-user peer verification.
var errConnectedSocketNotFound = errors.New("connected gateway server socket was not found")
