// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import "github.com/defenseclaw/defenseclaw/internal/config"

// ManagedHookFailMode is the fail mode the managed hook renderer writes into
// connector's hooks for cfg. It delegates to the hook renderer resolver: on
// Linux and macOS the renderer passes cfg.EffectiveHookFailModeForConnector
// to every hook it writes, so status reports that value and never derives
// one from the raw config.
func ManagedHookFailMode(cfg *config.Config, connector string) string {
	return cfg.EffectiveHookFailModeForConnector(connector)
}
