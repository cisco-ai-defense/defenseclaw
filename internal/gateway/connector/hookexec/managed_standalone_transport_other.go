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

package hookexec

import (
	"fmt"
	"net/http"
	"time"
)

// managedStandaloneHTTPClient: the unix standalone transport does not exist
// here (Windows uses the SCM service-PID check), so selecting it fails
// closed.
func managedStandaloneHTTPClient(time.Duration, string, int) (*http.Client, error) {
	return nil, fmt.Errorf("%w: standalone unix hook transport is unavailable on this platform", errManagedGatewayPeerUnverified)
}
