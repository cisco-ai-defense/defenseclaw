// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package daemon

func findPortHolder(host string, port int) (PortHolder, error) {
	if pid, err := listenerOwnerPID(host, port); err == nil {
		return PortHolder{PID: pid, UID: -1}, nil
	} else {
		return PortHolder{UID: -1}, err
	}
}
