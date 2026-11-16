// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/config"

// The repair rollback preflight is part of the Windows lifecycle.
func validateRepairRollbackPolicyInputs(_ *config.Config, _ string) error { return nil }

func repairRollbackCanCreateJSONLInRestampedRuntime(_, _ string) bool { return false }

func resolveRepairRollbackCredential(name, secretsDir string) (string, bool) {
	return config.ResolveObservabilityV8ProtectedCredential(secretsDir, name)
}
