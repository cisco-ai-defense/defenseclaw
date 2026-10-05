// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package agentidentity

import (
	"os"
	"strings"
	"sync"
)

var hostMachine struct {
	once     sync.Once
	hash     string
	verified bool
}

// HostMachineHash returns MachineHash of this host's machine id, read once
// per process. verified is true when the id came from the platform's machine
// id (/etc/machine-id, MachineGuid, IOPlatformUUID). Where none is readable
// the hostname stands in and verified is false. The device key is never
// used: it is a credential, and it rotates.
func HostMachineHash() (hash string, verified bool) {
	hostMachine.once.Do(func() {
		if raw, err := readPlatformMachineID(); err == nil && strings.TrimSpace(raw) != "" {
			hostMachine.hash, hostMachine.verified = MachineHash(raw), true
			return
		}
		if name, err := os.Hostname(); err == nil && strings.TrimSpace(name) != "" {
			hostMachine.hash = MachineHash("hostname:" + name)
		}
	})
	return hostMachine.hash, hostMachine.verified
}
