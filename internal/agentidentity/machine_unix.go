// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin

package agentidentity

import (
	"errors"
	"os"
	"strings"
)

// readPlatformMachineID reads the systemd machine id, falling back to the
// D-Bus copy older distributions keep.
func readPlatformMachineID() (string, error) {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(raw)); id != "" {
			return id, nil
		}
	}
	return "", errors.New("agentidentity: no machine id")
}
