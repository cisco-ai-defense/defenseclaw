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

import "time"

// SubstrateUsageConfig is substrate.usage: model spend and usage of actor
// calls, counted per person and per actor across gateway replicas through
// the leader. Off, replicas push nothing, the leader serves no usage or
// spend method, no loop runs and the usage API answers 501 usage_disabled.
type SubstrateUsageConfig struct {
	// Enabled (nil = true).
	Enabled *bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// SyncInterval is how often a replica sends its spend and usage to the
	// leader (Go duration, 1s to 30s; default 5s). On a cluster it replaces
	// routing.admin.budget_store.sync_interval.
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
	d, err := time.ParseDuration(u.SyncInterval)
	if err != nil || d < MinSubstrateUsageSyncInterval || d > MaxSubstrateUsageSyncInterval {
		return DefaultSubstrateUsageSyncInterval
	}
	return d
}

func (u SubstrateUsageConfig) validate(bad func(key, format string, a ...any)) {
	if u.SyncInterval == "" {
		return
	}
	d, err := time.ParseDuration(u.SyncInterval)
	if err != nil || d < MinSubstrateUsageSyncInterval || d > MaxSubstrateUsageSyncInterval {
		bad("usage.sync_interval", "%q must be a Go duration from 1s to 30s", u.SyncInterval)
	}
}
