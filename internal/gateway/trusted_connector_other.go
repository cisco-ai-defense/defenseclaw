//go:build !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Windows has no hook socket: a managed Windows hook call is authenticated
// by a per-user credential on the TCP API, which never proves the caller's
// process, so acting_for is never honoured there (1.0.6 limit, documented).
// A configured list is reported as not honoured.
func trustedConnectorPlatformSupported() bool { return false }

func resolveTrustedConnectorEntry(entry config.TrustedConnectorConfig) trustedConnectorEntry {
	return trustedConnectorEntry{
		Name: strings.TrimSpace(entry.Name), AccountSpec: strings.TrimSpace(entry.Account),
		Disabled: trustedConnectorsUnsupportedOS,
	}
}

func resolveActingFor(entry trustedConnectorEntry, _ string, _ time.Time) (actingFor, actingForRefusal) {
	return actingFor{}, actingForRefusal{Code: actingForRefusedUnsupported, Cause: entry.Disabled}
}
