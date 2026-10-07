// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedScanGatewayEndpoint binds the scan commands to the standalone
// managed gateway: its fixed API address and the gateway token in its data
// directory, which only an administrator can read.
func managedScanGatewayEndpoint() (string, string, bool, error) {
	if _, present := managedHostWindowsStandalone(); !present {
		return "", "", false, nil
	}
	layout, err := managed.StandaloneWindowsLayout()
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
			return "http://" + layout.APIAddr, strings.Trim(strings.TrimSpace(value), `"'`), true, nil
		}
	}
	return "", "", true, errors.New("the managed gateway token is not provisioned")
}
