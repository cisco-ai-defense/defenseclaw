// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"strings"
)

type brokerOptions struct {
	serviceName        string
	gatewayServiceName string
	pipeName           string
	authKeyPath        string
	cmidLibraryPath    string
	logPath            string
}

func parseBrokerOptions(arguments []string) (brokerOptions, error) {
	var options brokerOptions
	if len(arguments) == 0 || arguments[0] != "service" {
		return options, errors.New("the only supported command is service")
	}
	values := make(map[string]string, 6)
	for index := 1; index < len(arguments); index++ {
		name := arguments[index]
		if !strings.HasPrefix(name, "--") || strings.Contains(name, "=") {
			return options, fmt.Errorf("invalid broker argument %q", name)
		}
		if _, duplicate := values[name]; duplicate {
			return options, fmt.Errorf("duplicate broker option %s", name)
		}
		if index+1 >= len(arguments) || strings.HasPrefix(arguments[index+1], "--") {
			return options, fmt.Errorf("missing value for broker option %s", name)
		}
		value := strings.TrimSpace(arguments[index+1])
		if value == "" {
			return options, fmt.Errorf("empty value for broker option %s", name)
		}
		values[name] = value
		index++
	}
	required := []string{
		"--service-name",
		"--gateway-service-name",
		"--pipe-name",
		"--auth-key",
		"--cmid-library",
		"--log",
	}
	for _, name := range required {
		if values[name] == "" {
			return options, fmt.Errorf("missing required broker option %s", name)
		}
	}
	if len(values) != len(required) {
		for name := range values {
			known := false
			for _, candidate := range required {
				known = known || name == candidate
			}
			if !known {
				return options, fmt.Errorf("unsupported broker option %s", name)
			}
		}
	}
	options = brokerOptions{
		serviceName:        values["--service-name"],
		gatewayServiceName: values["--gateway-service-name"],
		pipeName:           values["--pipe-name"],
		authKeyPath:        values["--auth-key"],
		cmidLibraryPath:    values["--cmid-library"],
		logPath:            values["--log"],
	}
	return options, nil
}
