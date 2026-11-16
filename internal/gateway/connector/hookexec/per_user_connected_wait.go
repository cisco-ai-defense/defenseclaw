// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package hookexec

import "time"

// perUserConnectedWait is how long a per-user hook waits for its gateway to
// accept a connection and so show whose socket it is.
var perUserConnectedWait = 3 * time.Second
