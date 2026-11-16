//go:build !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/config"

// machineHookAbsent proves nothing off Unix: the own-status pipe carries no
// per-connector hook proof there, so an excluded account's row is unverified.
var machineHookAbsent = func(string, *config.Config, string) bool { return false }
