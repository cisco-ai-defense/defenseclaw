// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var managedScanWindowsLayout = managed.StandaloneWindowsLayout

// managedScanGatewayEndpoint binds the scan commands to the standalone
// managed gateway: its configured API port and the gateway token in its data
// directory, which only an administrator can read.
func managedScanGatewayEndpoint() (string, string, bool, error) {
	if _, present := managedHostWindowsStandalone(); !present {
		return "", "", false, nil
	}
	layout, err := managedScanWindowsLayout()
	if err != nil {
		return "", "", true, err
	}
	base, err := managedWindowsGatewayBase(layout)
	if err != nil {
		return "", "", true, err
	}
	body, err := readWindowsEnterpriseBoundedFile(filepath.Join(layout.DataDir, ".env"), 1<<20)
	if err != nil {
		return "", "", true, errors.New("the managed gateway token is readable only from an elevated Administrator prompt")
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		name, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if ok && strings.TrimSpace(name) == "DEFENSECLAW_GATEWAY_TOKEN" && strings.TrimSpace(value) != "" {
			return base, strings.Trim(strings.TrimSpace(value), `"'`), true, nil
		}
	}
	return "", "", true, errors.New("the managed gateway token is not provisioned")
}

// managedWindowsGatewayBase is the loopback URL of the standalone managed
// gateway's API: the gateway.api_port of the installed config, or the
// layout's default port when the config sets none.
func managedWindowsGatewayBase(layout managed.StandaloneLayout) (string, error) {
	configBody, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, 4<<20)
	if err != nil {
		return "", fmt.Errorf("read installed managed gateway config: %w", err)
	}
	var installed struct {
		Gateway struct {
			APIPort *int `yaml:"api_port"`
		} `yaml:"gateway"`
	}
	if err := yaml.Unmarshal(trimWindowsJSONBOM(configBody), &installed); err != nil {
		return "", fmt.Errorf("parse installed managed gateway config: %w", err)
	}
	host, defaultPort, err := net.SplitHostPort(layout.APIAddr)
	if err != nil {
		return "", fmt.Errorf("invalid managed gateway default API address: %w", err)
	}
	port := 0
	if installed.Gateway.APIPort != nil {
		port = *installed.Gateway.APIPort
		if port < 1 || port > 65535 {
			return "", fmt.Errorf("installed managed gateway config has invalid gateway.api_port %d", port)
		}
	} else {
		port, err = strconv.Atoi(defaultPort)
		if err != nil {
			return "", fmt.Errorf("invalid managed gateway default API port: %w", err)
		}
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port)), nil
}
