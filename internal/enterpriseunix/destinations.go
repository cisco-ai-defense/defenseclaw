// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// describeDestinations lists, for status, the observability destinations the
// installed config.yaml compiles to with each one's effective redaction
// profiles. `defenseclaw observability plan` is a per-user command a managed
// install does not offer, so this is where an administrator reads which
// profile a destination such as Galileo exports under (GAP-1105). A config
// that does not compile is reported by config_rejected; the list is left out.
func (l *lifecycle) describeDestinations() {
	env, r := l.env, l.result
	if r.Action != ActionStatus {
		return
	}
	path := env.P(env.Layout.ConfigPath)
	raw, err := readBounded(path, maxInputBytes)
	if err != nil {
		return
	}
	summaries, err := config.SummarizeObservabilityV8Destinations(path, raw, env.P(env.Layout.DataDir))
	if err != nil {
		return
	}
	r.Destinations = enterprisestatus.DestinationsFromSummaries(summaries)
}
