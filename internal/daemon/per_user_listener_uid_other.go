// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package daemon

import "errors"

func gatewayProcessUID(int) (int, error) {
	return -1, errors.New("process UID is unavailable")
}
