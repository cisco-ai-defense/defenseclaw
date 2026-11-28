// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strconv"
	"strings"
	"time"
)

// SubstrateUsageConfig is substrate.usage: model spend and usage of actor
// calls, counted per person and per actor across gateway replicas through
// the leader. Off, replicas push nothing, the leader serves no usage or
// spend method, no loop runs and the usage API answers 501 usage_disabled.
type SubstrateUsageConfig struct {
	// Enabled (nil = true).
	Enabled *bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// SyncInterval is how often a replica sends its spend and usage to the
	// leader (Go duration or integer seconds, 1s to 30s; default 5s). A
	// cluster has no routing.admin.budget_store; this is its interval.
	SyncInterval string `mapstructure:"sync_interval" yaml:"sync_interval,omitempty"`
}

// Defaults and bounds of substrate.usage.sync_interval.
const (
	DefaultSubstrateUsageSyncInterval = 5 * time.Second
	MinSubstrateUsageSyncInterval     = time.Second
	MaxSubstrateUsageSyncInterval     = 30 * time.Second
)

// UsageEnabled reports substrate.usage.enabled (default true).
func (u SubstrateUsageConfig) UsageEnabled() bool {
	return u.Enabled == nil || *u.Enabled
}

// EffectiveSyncInterval returns substrate.usage.sync_interval, or the
// default when it is unset or out of bounds (Validate refuses those).
func (u SubstrateUsageConfig) EffectiveSyncInterval() time.Duration {
	d, err := parseSubstrateUsageInterval(u.SyncInterval)
	if err != nil || d < MinSubstrateUsageSyncInterval || d > MaxSubstrateUsageSyncInterval {
		return DefaultSubstrateUsageSyncInterval
	}
	return d
}

// parseSubstrateUsageInterval reads sync_interval as the schema's duration
// allows it, a Go duration or integer seconds, spaces trimmed (Python keeps
// an integer as its text).
func parseSubstrateUsageInterval(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if n, err := strconv.ParseUint(v, 10, 31); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(v)
}

func (u SubstrateUsageConfig) validate(bad func(key, format string, a ...any)) {
	if strings.TrimSpace(u.SyncInterval) == "" {
		return
	}
	d, err := parseSubstrateUsageInterval(u.SyncInterval)
	if err != nil || d < MinSubstrateUsageSyncInterval || d > MaxSubstrateUsageSyncInterval {
		bad("usage.sync_interval", "%q must be a Go duration or integer seconds from 1s to 30s", u.SyncInterval)
	}
}
