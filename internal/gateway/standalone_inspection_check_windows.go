// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// CheckStandaloneAIDefenseAs gives an elevated administrator command the
// gateway service's reader identity for the same protected-file checks the
// gateway uses. The key remains in memory and only the probe result is returned.
func CheckStandaloneAIDefenseAs(ctx context.Context, cfg *config.Config, serviceAccount string) (string, error) {
	return checkStandaloneAIDefense(ctx, cfg, func(name, dir string) ([]byte, managed.CredentialSource, error) {
		return managed.ResolveServiceCredentialAs(name, dir, serviceAccount)
	})
}
