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

package sandboxapi

import (
	"context"
	"net/http"
	"net/url"
)

// PathPolicyPacks lists the packs of the caller's own effective chain on a
// managed host (GET); PathPolicyPacks + "/" + name returns one with its
// content. The routes answer on the per-user daemon socket only.
const PathPolicyPacks = "/api/v1/sandbox/policy/packs"

// ManagedPack is one pack of the caller's effective chain on a managed
// host (`sandbox pack list|show`). It is the JSON of sandboxrelay.PackView;
// the daemon relays the managed gateway's answer unchanged, so a user sees
// only the packs their own policy uses.
type ManagedPack struct {
	Name        string `json:"name"`
	Source      string `json:"source,omitempty"`
	Digest      string `json:"digest"`
	Description string `json:"description,omitempty"`
	Extends     string `json:"extends,omitempty"`
	// Content is the pack's YAML, set by Pack only.
	Content string `json:"content,omitempty"`
}

// ListManagedPacks lists the packs of the caller's effective chain.
func (c *Client) ListManagedPacks(ctx context.Context) ([]ManagedPack, error) {
	var out []ManagedPack
	if err := c.do(ctx, http.MethodGet, PathPolicyPacks, nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetManagedPack returns one pack of the caller's effective chain, with its
// content.
func (c *Client) GetManagedPack(ctx context.Context, name string) (*ManagedPack, error) {
	var out ManagedPack
	if err := c.do(ctx, http.MethodGet, PathPolicyPacks+"/"+url.PathEscape(name), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
