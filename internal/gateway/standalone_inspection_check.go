// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// aiDefenseProbeContent is the one message of the key check: a single
// full stop, so no prompt, file or user text leaves the device.
const aiDefenseProbeContent = "."

// CheckStandaloneAIDefense proves the Cisco AI Defense credential of a
// standalone deployment before the first prompt does (`enterprise secret
// check`). It builds the client the gateway builds (the protected credential
// only, the administrator's egress proxy) and makes one authenticated request
// that carries no content, then returns what /health reports in
// inspection.ai_defense: "ok" (AI Defense answered with the stored key),
// "disabled" (enterprise.inspection.ai_defense is off) or
// "unavailable:<code>". It reads only; it stores and changes nothing. The
// error is set for a config that is not a standalone deployment.
func CheckStandaloneAIDefense(ctx context.Context, cfg *config.Config) (string, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return "", errors.New("not a standalone managed deployment")
	}
	client, err := newStandaloneCiscoInspectClient(cfg)
	switch {
	case errors.Is(err, errStandaloneAIDefenseDisabled):
		return "disabled", nil
	case err != nil:
		return "unavailable:" + aiDefenseUnavailableCode("ai_defense: "+err.Error()), nil
	}
	return probeAIDefense(ctx, client), nil
}

// probeAIDefense sends the key check through client and maps its outcome the
// way the gateway maps the outcome of a real inspection.
func probeAIDefense(ctx context.Context, client *CiscoInspectClient) string {
	var outcome error
	observed := false
	client.bindAvailabilityObserver(func(err error) { outcome, observed = err, true })
	client.Inspect(ctx, []ChatMessage{{Role: "user", Content: aiDefenseProbeContent}})
	switch {
	case outcome != nil:
		return "unavailable:" + aiDefenseUnavailableCode("ai_defense: "+outcome.Error())
	case !observed && ctx.Err() != nil:
		// A request cut short by the caller's deadline reached no answer.
		return "unavailable:unreachable"
	case !observed:
		return "unavailable:error"
	}
	return "ok"
}
