// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package destinations

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/managedaid"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/push"
)

// ManifestReceiptReader uses exactly the generated managed ingest origin and
// its existing trust-aware transport. It adds no operator destination or worker.
func (factory *Factory) ManifestReceiptReader(ctx context.Context, plan *config.ObservabilityV8Plan) managedaid.ManifestReceiptReader {
	if factory == nil || !factory.managedService || factory.managedProvider == nil || plan == nil {
		return nil
	}
	destination, ok := plan.RuntimeDestination(config.ObservabilityV8ManagedAIDDestinationName)
	if !ok || !validManagedAIDDestination(destination) {
		return nil
	}
	client, err := managedaid.NewManifestReceiptClient(ctx, destination.Transport.Endpoint, factory.managedProvider, push.NetworkOptions{Resolver: factory.resolver, Dialer: factory.dialer}, factory.warnings)
	if err != nil {
		return nil
	}
	return client
}
