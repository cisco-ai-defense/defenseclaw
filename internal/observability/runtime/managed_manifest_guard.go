// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
)

type managedManifestDigestKey struct{}
type managedManifestDigest struct {
	hash, digest string
	part, total  int
	generation   uint64
}

// WithManagedManifestDigest binds a recovery emission to its previously captured
// managed projection. Reload or SinkPolicy drift must never overwrite an
// immutable stored part with a different representation.
func WithManagedManifestDigest(ctx context.Context, hash, digest string, part, total int) context.Context {
	expected, _ := ctx.Value(managedManifestDigestKey{}).(managedManifestDigest)
	expected.hash, expected.digest, expected.part, expected.total = hash, digest, part, total
	return context.WithValue(ctx, managedManifestDigestKey{}, expected)
}

func managedManifestDigestBound(ctx context.Context) bool {
	expected, ok := ctx.Value(managedManifestDigestKey{}).(managedManifestDigest)
	return ok && expected.digest != ""
}

func managedManifestProjectionMatches(ctx context.Context, outcome pipeline.LocalLogOutcome) bool {
	expected, guarded := ctx.Value(managedManifestDigestKey{}).(managedManifestDigest)
	if !guarded || expected.digest == "" {
		return true
	}
	for _, work := range outcome.OptionalWork() {
		if work.Delivery().DestinationName != config.ObservabilityV8ManagedAIDDestinationName {
			continue
		}
		raw, err := work.Projection().Bytes()
		if err != nil {
			return false
		}
		var projected struct {
			Body map[string]json.RawMessage `json:"body"`
		}
		if json.Unmarshal(raw, &projected) != nil {
			return false
		}
		var hash, text string
		var part, total int
		if json.Unmarshal(projected.Body["defenseclaw.inventory.skill.manifest_hash"], &hash) != nil ||
			json.Unmarshal(projected.Body["defenseclaw.inventory.skill.manifest"], &text) != nil ||
			json.Unmarshal(projected.Body["defenseclaw.inventory.skill.manifest_part"], &part) != nil ||
			json.Unmarshal(projected.Body["defenseclaw.inventory.skill.manifest_parts"], &total) != nil {
			return false
		}
		sum := sha256.Sum256([]byte(text))
		return hash == expected.hash && part == expected.part && total == expected.total && "sha256:"+hex.EncodeToString(sum[:]) == expected.digest
	}
	return false
}

// WithManagedManifestGeneration binds even identical projected text to the
// destination/policy graph that authenticated its receipt. Checked under lease.
func WithManagedManifestGeneration(ctx context.Context, generation uint64) context.Context {
	expected, _ := ctx.Value(managedManifestDigestKey{}).(managedManifestDigest)
	expected.generation = generation
	return context.WithValue(ctx, managedManifestDigestKey{}, expected)
}
func managedManifestGenerationMatches(ctx context.Context, generation uint64) bool {
	expected, _ := ctx.Value(managedManifestDigestKey{}).(managedManifestDigest)
	return expected.generation == 0 || expected.generation == generation
}
