// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/managedaid"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

func (s *Sidecar) bindManifestReceipts(ctx context.Context, owner *sidecarOwnedObservabilityV8Runtime, cfg *config.Config, plan *config.ObservabilityV8Plan) {
	if s == nil || owner == nil {
		return
	}
	var reader managedaid.ManifestReceiptReader
	if cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) && cfg.AIDiscovery.IncludeSkillManifests && owner.destinationFactory != nil {
		reader = owner.destinationFactory.ManifestReceiptReader(ctx, plan)
	}
	binding := manifestReceiptRuntimeBinding{}
	if plan != nil {
		if destination, ok := plan.RuntimeDestination(config.ObservabilityV8ManagedAIDDestinationName); ok {
			// Retain only an opaque identity, never the destination address or
			// credentials, in the protected publisher state.
			sum := sha256.Sum256([]byte(destination.Transport.Endpoint))
			binding.destination = "sha256:" + hex.EncodeToString(sum[:])
		}
	}
	if owner.runtime != nil && owner.runtime.Active() != nil {
		binding.generation = owner.runtime.Active().Generation()
		binding.current = func() uint64 {
			if graph := owner.runtime.Active(); graph != nil {
				return graph.Generation()
			}
			return 0
		}
	}
	s.inventoryPublish.SetSkillManifestReceiptReader(reader, binding)
}

func (owner *sidecarOwnedObservabilityV8Runtime) ProjectManagedLogBatch(ctx context.Context, items []observabilityruntime.LogBatchItem) ([]pipeline.LocalLogOutcome, error) {
	if owner == nil || owner.runtime == nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.ProjectManagedLogBatch(ctx, items)
}
