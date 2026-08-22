// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

// Package cmidbroker contains the deliberately narrow contract between the
// restricted Windows gateway and the LocalSystem CMID broker. It does not know
// about prompts, connectors, AI Defense endpoints, or HTTP.
package cmidbroker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ProtocolVersion = 1

	MaxMessageBytes = 16 << 10
	MaxTokenBytes   = 8 << 10
	MaxErrorBytes   = 512
	AuthKeyBytes    = 32

	PipeEnv           = "DEFENSECLAW_CMID_BROKER_PIPE"
	BrokerServiceEnv  = "DEFENSECLAW_CMID_BROKER_SERVICE_NAME"
	AuthKeyEnv        = "DEFENSECLAW_CMID_BROKER_AUTH_KEY"
	GatewayServiceEnv = "DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME"
)

const defaultOperationTimeout = 15 * time.Second

const (
	OperationToken      = "token"
	OperationRefresh    = "refresh"
	OperationInvalidate = "invalidate"
)

var (
	ErrIncompleteConfiguration = errors.New("cmid broker configuration is incomplete")
	ErrUnsupportedPlatform     = errors.New("cmid broker is unsupported on this platform")
	ErrAuthentication          = errors.New("cmid broker response authentication failed")
	ErrProtocol                = errors.New("cmid broker protocol violation")
	ErrUnavailable             = errors.New("cmid broker unavailable")
)

// Provider is intentionally identical to cloudreg.Provider without importing
// that package. Both the gateway client and the private CMID provider satisfy
// this narrow lifecycle.
type Provider interface {
	Token(context.Context) (string, error)
	Refresh(context.Context) error
	Invalidate()
}

// ClientConfig is installer-owned configuration read by the restricted
// gateway. Values are considered disabled only when every field is absent.
type ClientConfig struct {
	PipeName           string
	BrokerServiceName  string
	AuthKeyPath        string
	GatewayServiceName string
}

// ConfigFromEnvironment implements the all-or-none broker selection rule. A
// partially authored protected service environment must never fall back to
// direct in-process CMID loading.
func ConfigFromEnvironment(lookup func(string) string) (ClientConfig, bool, error) {
	if lookup == nil {
		return ClientConfig{}, false, fmt.Errorf("%w: environment lookup unavailable", ErrIncompleteConfiguration)
	}
	cfg := ClientConfig{
		PipeName:           strings.TrimSpace(lookup(PipeEnv)),
		BrokerServiceName:  strings.TrimSpace(lookup(BrokerServiceEnv)),
		AuthKeyPath:        strings.TrimSpace(lookup(AuthKeyEnv)),
		GatewayServiceName: strings.TrimSpace(lookup(GatewayServiceEnv)),
	}
	present := 0
	for _, value := range []string{
		cfg.PipeName,
		cfg.BrokerServiceName,
		cfg.AuthKeyPath,
		cfg.GatewayServiceName,
	} {
		if value != "" {
			present++
		}
	}
	if present == 0 {
		return ClientConfig{}, false, nil
	}
	if present != 4 {
		return ClientConfig{}, true, ErrIncompleteConfiguration
	}
	return cfg, true, nil
}
