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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/substrate/bundle"
	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// defaultBundleAnchorsSecret is the chart's bundles.anchorsSecret.
const defaultBundleAnchorsSecret = "defenseclaw-bundle-anchors"

// bundleAnchorsSecret is the Secret the gateway mounts as its bundle trust
// anchors (the bundle-anchors volume), else the chart default.
func bundleAnchorsSecret(loads []kubeItem) string {
	for _, it := range loads {
		for _, v := range it.Spec.Template.Spec.Volumes {
			if v.Name == "bundle-anchors" && v.Secret != nil && v.Secret.SecretName != "" {
				return v.Secret.SecretName
			}
		}
	}
	return defaultBundleAnchorsSecret
}

// readBundles fills o.Bundles when substrate.bundles is on (GAP-0429,
// GAP-0432): the stages and their active bundles from the bundle state
// ConfigMap, each re-verified, as the controller does on every pass,
// against the trust anchors Secret, both read with kubectl. A stage whose
// bundle no longer verifies is no longer enforced. A bundle that verifies
// but whose policy does not layer over config.yaml as read here, and every
// stage when the anchors Secret cannot be read, is "unchecked".
func readBundles(ctx context.Context, f *substrateClusterFlags, o *fleet.Observed, cfgText, anchorsSecret string) {
	var doc struct {
		Mode      string `yaml:"deployment_mode"`
		Substrate struct {
			Bundles struct {
				Enabled bool `yaml:"enabled"`
			} `yaml:"bundles"`
		} `yaml:"substrate"`
	}
	if cfgText == "" || yaml.Unmarshal([]byte(cfgText), &doc) != nil || !doc.Substrate.Bundles.Enabled {
		return
	}
	b := &fleet.Bundles{Managed: managed.IsManagedEnterprise(doc.Mode), Stages: []fleet.BundleStage{}}
	o.Bundles = b
	raw, err := substrateKubectl(ctx, f, "get", "configmap", bundle.StateConfigMap, "-n", f.namespace, "-o", "json", "--ignore-not-found")
	if err != nil {
		b.Note = "the " + bundle.StateConfigMap + " ConfigMap could not be read: " + firstLineOf(err.Error())
		return
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return // no bundle was ever applied
	}
	var cm struct {
		Data       map[string]string `json:"data"`
		BinaryData map[string][]byte `json:"binaryData"`
	}
	if err := json.Unmarshal(raw, &cm); err != nil {
		b.Note = "the " + bundle.StateConfigMap + " ConfigMap is not readable: " + firstLineOf(err.Error())
		return
	}
	mem := bundle.NewMemoryConfigMaps()
	if err := mem.Create(ctx, &bundle.ConfigMap{Name: bundle.StateConfigMap, Data: cm.Data, BinaryData: cm.BinaryData}); err != nil {
		b.Note = err.Error()
		return
	}
	anchorsNote := ""
	var anchors *eb.Anchors
	var anchorsErr error
	if raw, err := substrateKubectl(ctx, f, "get", "secret", anchorsSecret, "-n", f.namespace, "-o", "json"); err != nil {
		anchorsNote = "the trust anchors Secret " + anchorsSecret + " could not be read: " + firstLineOf(err.Error())
	} else {
		var sec struct {
			Data map[string][]byte `json:"data"`
		}
		if err := json.Unmarshal(raw, &sec); err != nil {
			anchorsNote = "the trust anchors Secret " + anchorsSecret + " is not readable: " + firstLineOf(err.Error())
		} else if a, ok := sec.Data[eb.AnchorsName]; !ok {
			// What the gateway and the controller read: no anchors, so no bundle verifies.
			anchorsErr = &eb.Error{Code: eb.CodeAnchorMissing, Path: eb.AnchorsName, Detail: "the trust anchors Secret " + anchorsSecret + " has no " + eb.AnchorsName}
		} else {
			anchors, anchorsErr = eb.DecodeAnchors(a)
		}
	}
	var base config.Config
	_ = yaml.Unmarshal([]byte(cfgText), &base)
	store := &bundle.Store{CM: mem, Base: &base, Now: func() time.Time { return time.Now().UTC() },
		Anchors: func() (*eb.Anchors, error) {
			if anchorsNote != "" {
				return nil, errors.New(anchorsNote)
			}
			return anchors, anchorsErr
		}}
	st, err := store.Status(ctx, 0)
	if err != nil {
		b.Note = "the bundle state could not be verified: " + firstLineOf(err.Error())
		return
	}
	problems := map[string]bundle.Problem{}
	for _, p := range st.Problems {
		problems[p.Stage] = p
	}
	names := make([]string, 0, len(st.Stages))
	for n := range st.Stages {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := st.Stages[n]
		if s.Active == nil {
			continue
		}
		r := s.Active
		bs := fleet.BundleStage{Stage: n, Atespaces: append([]string{}, s.Atespaces...), BundleID: r.BundleID, Version: r.Version,
			KeyID: r.KeyID, ManifestSHA256: r.ManifestSHA256, AppliedAt: r.AppliedAt.UTC().Format(time.RFC3339), Source: r.Source,
			State: fleet.BundleVerified}
		bs.ReceiptID = fleet.ReceiptID(bs.AppliedAt, bs.Source, bs.Stage, bs.ManifestSHA256)
		if bs.Atespaces == nil {
			bs.Atespaces = []string{}
		}
		p, failed := problems[n]
		switch {
		case anchorsNote != "":
			bs.State, b.Note = fleet.BundleUnchecked, anchorsNote
		case failed && p.Code == string(eb.CodeConfigInvalid):
			// The signature verified; the policy is checked over the
			// gateway's own config.yaml, which this read cannot rebuild.
			bs.State, b.Note = fleet.BundleUnchecked, "the policy of a verified bundle could not be layered over config.yaml as read here"
		case failed:
			bs.State, bs.Problem = fleet.BundleUnverified, p.Code
		}
		b.Stages = append(b.Stages, bs)
	}
}
