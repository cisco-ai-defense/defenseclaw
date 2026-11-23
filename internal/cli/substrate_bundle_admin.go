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
// substrate.bundles is off. live is config.yaml in force: it decides which
// atespaces a stage may name, as the controller decides (GAP-0494).
func substrateBundleStore(c *config.Config, live func() *config.Config) (gateway.SubstrateBundles, error) {
	b := c.Substrate.Bundles
	if !b.Enabled {
		return nil, nil
	}
	cms, err := bundle.NewInClusterKube(os.Getenv("POD_NAMESPACE"))
	if err != nil {
		return nil, fmt.Errorf("substrate.bundles: %w", err)
	}
	return substrateBundleAdapter{newSubstrateBundleStore(cms, c, live)}, nil
}

// newSubstrateBundleStore is the bundle store of a gateway or controller
// pod: the boot config verifies, the live config (GAP-0494) decides which
// atespaces a stage may name, and the anchors come from the mounted file.
func newSubstrateBundleStore(cms bundle.ConfigMaps, c *config.Config, live func() *config.Config) *bundle.Store {
	path := c.Substrate.Bundles.EffectiveAnchorsFile()
	return &bundle.Store{CM: cms, Base: c, Live: live, AnchorsFile: path, OCIStages: substrateOCIStages(c),
		Anchors: func() (*eb.Anchors, error) { return bundle.LoadAnchorsFile(path) }}
}

// substrateOCIStages is substrate.bundles.oci.stages when oci is on.
func substrateOCIStages(c *config.Config) []bundle.OCIStage {
	o := c.Substrate.Bundles.OCI
	if !o.Enabled {
		return nil
	}
	out := make([]bundle.OCIStage, 0, len(o.Stages))
	for _, st := range o.Stages {
		out = append(out, bundle.OCIStage{Stage: st.Stage, Ref: st.Ref, Atespaces: st.Atespaces})
	}
	return out
}
