// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The guardian and each managed connector target use the same guarded digest
// memo. These functions are replaceable in guardian tests.
var (
	guardianTargetHookSHA256Hex = connector.ManagedEnterpriseHookBinarySHA256Hex
	guardianCopyHookSHA256Hex   = connector.ManagedProtectedHookCopySHA256Hex
)

type guardianTargetDigestDecision struct {
	damage  string
	refusal string
	missing bool
}

// decideGuardianTargetDigest uses a plain read to reach a verdict when the
// guarded digest refuses an existing target. The structure check reads only
// attributes and runs after a matching plain hash, so a linked copy of the
// recorded bytes is still replaced with a single-link file.
func decideGuardianTargetDigest(
	target, want string,
	guardedHash, plainHash func(string) (string, error),
	structure func(string) (string, error),
) (guardianTargetDigestDecision, error) {
	sum, guardedErr := guardedHash(target)
	if guardedErr == nil {
		if sum != want {
			return guardianTargetDigestDecision{damage: "not the recorded release (hash mismatch: sha256 " + sum + ")"}, nil
		}
		return guardianTargetDigestDecision{}, nil
	}
	decision := guardianTargetDigestDecision{refusal: guardedErr.Error()}
	sum, readErr := plainHash(target)
	if errors.Is(readErr, os.ErrNotExist) {
		decision.damage = fmt.Sprintf("missing (shared digest refused file: %v)", guardedErr)
		decision.missing = true
		return decision, nil
	}
	if readErr != nil {
		return decision, fmt.Errorf("read hook binary %s after shared digest refusal: %w; plain read: %w", target, guardedErr, readErr)
	}
	if sum != want {
		decision.damage = fmt.Sprintf("not the recorded release (hash mismatch: sha256 %s; shared digest refused file: %v)", sum, guardedErr)
		return decision, nil
	}
	structuralDamage, structureErr := structure(target)
	if structureErr != nil {
		return decision, fmt.Errorf("inspect hook binary %s after shared digest refusal: %w; attribute read: %w", target, guardedErr, structureErr)
	}
	if structuralDamage != "" {
		decision.damage = fmt.Sprintf("%s (shared digest refused file: %v)", structuralDamage, guardedErr)
	}
	return decision, nil
}
