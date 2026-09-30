// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"fmt"
	"os/user"
	"strconv"
)

// PortHolder is a best-effort description of the process listening on a
// local TCP port. PID is 0 and UID is -1 when the platform does not reveal
// them (for example a process of another account).
type PortHolder struct {
	PID     int
	UID     int
	Command string
}

// FindPortHolder describes the process that listens on the local TCP port.
// It returns ErrNoListener when no listener was found and
// ErrListenerInspectionUnavailable when the platform cannot tell.
func FindPortHolder(port int) (PortHolder, error) {
	if port < 1 || port > 65535 {
		return PortHolder{PID: 0, UID: -1}, fmt.Errorf("%w: invalid port %d", ErrListenerInspectionUnavailable, port)
	}
	return findPortHolder(port)
}

// String names the holder for an operator: "PID 123 (defenseclaw-gateway)",
// "PID 123 of another account (uid 1001, alice)" or "a process of another
// account (uid 1001, alice)".
func (holder PortHolder) String(ownUID int) string {
	account := ""
	if holder.UID >= 0 && holder.UID != ownUID {
		account = "uid " + strconv.Itoa(holder.UID)
		if found, err := user.LookupId(strconv.Itoa(holder.UID)); err == nil && found.Username != "" {
			account += ", " + found.Username
		}
	}
	switch {
	case holder.PID > 0 && account != "":
		return fmt.Sprintf("PID %d of another account (%s)", holder.PID, account)
	case holder.PID > 0 && holder.Command != "":
		return fmt.Sprintf("PID %d (%s)", holder.PID, holder.Command)
	case holder.PID > 0:
		return fmt.Sprintf("PID %d", holder.PID)
	case account != "":
		return fmt.Sprintf("a process of another account (%s)", account)
	default:
		return "another process"
	}
}
