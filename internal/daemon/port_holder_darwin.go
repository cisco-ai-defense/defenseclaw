// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// findPortHolder asks the system lsof for the LISTEN socket on port. lsof
// sees this account's processes; another account's listener is reported as
// unavailable.
func findPortHolder(port int) (PortHolder, error) {
	holder := PortHolder{UID: -1}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(
		ctx, "/usr/sbin/lsof", "-nP", "-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fpcu",
	).Output()
	if err != nil && len(output) == 0 {
		// lsof exits 1 when it lists nothing.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return holder, ErrNoListener
		}
		return holder, ErrListenerInspectionUnavailable
	}
	for _, line := range strings.Split(string(output), "\n") {
		if len(line) < 2 {
			continue
		}
		value := line[1:]
		switch line[0] {
		case 'p':
			if holder.PID > 0 {
				return holder, nil
			}
			holder.PID, _ = strconv.Atoi(value)
		case 'c':
			holder.Command = value
		case 'u':
			holder.UID, _ = strconv.Atoi(value)
		}
	}
	if holder.PID <= 0 {
		return holder, ErrNoListener
	}
	return holder, nil
}
