//go:build linux

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
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// standaloneGatewayUnit is the systemd unit of the standalone gateway
// (packaging/systemd/defenseclaw-gateway.service).
const standaloneGatewayUnit = "defenseclaw-gateway.service"

var standaloneGatewayServiceProbe = systemdGatewayServiceState

// systemdGatewayServiceState reads the gateway unit's state with a fixed
// systemctl path. Its answer can only end a wait early, as fail closed;
// it never lets a request through.
func systemdGatewayServiceState(ctx context.Context) (gatewayServiceState, error) {
	var state gatewayServiceState
	systemctl := ""
	for _, candidate := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			systemctl = candidate
			break
		}
	}
	if systemctl == "" {
		return state, errors.New("systemctl not found")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemctl, "show", "--property=ActiveState,SubState,NRestarts", standaloneGatewayUnit)
	cmd.Env = []string{"LC_ALL=C", "SYSTEMD_PAGER=cat"}
	out, err := cmd.Output()
	if err != nil {
		return state, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		switch key {
		case "ActiveState":
			state.Active = value
		case "SubState":
			state.Sub = value
		case "NRestarts":
			state.Restarts, _ = strconv.Atoi(value)
		}
	}
	if state.Active == "" {
		return state, errors.New("systemctl reported no state")
	}
	return state, nil
}
