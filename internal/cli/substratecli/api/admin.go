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

package api

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// MaxBundleBytes is the largest policy bundle ApplyBundle sends: the
// cluster keeps two per stage in a ConfigMap (bundle.MaxArchiveBytes).
const MaxBundleBytes = 48 << 10

// ErrBundleTooLarge is returned by ApplyBundle for a bundle over MaxBundleBytes.
var ErrBundleTooLarge = errors.New("the bundle is larger than 48 KiB")

// FleetVerifyDocument returns the administrator verify document: the
// cluster checks and one verdict. A person who is not an administrator gets
// a 403, a cluster without the route a 501.
func (c *Client) FleetVerifyDocument(ctx context.Context) (fleet.VerifyDocument, error) {
	var out fleet.VerifyDocument
	return out, c.do(ctx, http.MethodGet, "fleet/verify", nil, nil, &out)
}

// bundleApplyRequest is the body of POST bundle. The admin listener takes
// JSON only (its CSRF gate), so the bundle bytes travel as base64.
type bundleApplyRequest struct {
	Name      string   `json:"name,omitempty"`
	Bundle    []byte   `json:"bundle"`
	Stage     string   `json:"stage,omitempty"`
	Atespaces []string `json:"atespaces,omitempty"`
}

// ApplyBundle sends a signed policy bundle to the cluster, named by name,
// for a stage: the atespaces given, or every atespace without them. An
// empty stage lets the cluster name it (all, or one stage per atespace
// set). The bytes are sent as they are; the cluster verifies them and
// answers with the receipt.
func (c *Client) ApplyBundle(ctx context.Context, name string, data io.Reader, stage string, atespaces []string) (map[string]any, error) {
	raw, err := io.ReadAll(io.LimitReader(data, MaxBundleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxBundleBytes {
		return nil, ErrBundleTooLarge
	}
	var out map[string]any
	return out, c.do(ctx, http.MethodPost, "bundle", nil, bundleApplyRequest{Name: name, Bundle: raw, Stage: stage, Atespaces: atespaces}, &out)
}

// RollbackBundle re-activates a stage's previous bundle and answers with the
// receipt.
func (c *Client) RollbackBundle(ctx context.Context, stage string) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodPost, "bundle/rollback", nil, map[string]string{"stage": stage}, &out)
}

// BundleStatus returns the policy bundles in force.
func (c *Client) BundleStatus(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "bundle/status", nil, nil, &out)
}
