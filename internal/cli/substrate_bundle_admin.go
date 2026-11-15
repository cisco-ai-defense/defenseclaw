// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/config"
	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/substrate/bundle"
)

// substrateBundleAdapter serves the admin listener's bundle routes from
// the bundle store (the gateway pods hold the same ConfigMap rights and
// anchors mount as the controller).
type substrateBundleAdapter struct{ s *bundle.Store }

func (a substrateBundleAdapter) Apply(ctx context.Context, archive []byte, stage string, atespaces []string) (any, error) {
	return a.s.Apply(ctx, archive, stage, atespaces, bundle.SourceAdmin)
}

func (a substrateBundleAdapter) Rollback(ctx context.Context, stage string) (any, error) {
	return a.s.Rollback(ctx, stage, bundle.SourceAdmin)
}

func (a substrateBundleAdapter) Status(ctx context.Context) (any, error) {
	st, err := a.s.Status(ctx, 50)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// substrateBundleStore is the admin listener's bundle store, nil when
// substrate.bundles is off.
func substrateBundleStore(c *config.Config) (gateway.SubstrateBundles, error) {
	b := c.Substrate.Bundles
	if !b.Enabled {
		return nil, nil
	}
	cms, err := bundle.NewInClusterKube(os.Getenv("POD_NAMESPACE"))
	if err != nil {
		return nil, fmt.Errorf("substrate.bundles: %w", err)
	}
	path := b.EffectiveAnchorsFile()
	return substrateBundleAdapter{&bundle.Store{CM: cms, Base: c, AnchorsFile: path,
		Anchors: func() (*eb.Anchors, error) { return bundle.LoadAnchorsFile(path) }}}, nil
}
