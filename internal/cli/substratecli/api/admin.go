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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// MaxBundleBytes is the largest policy bundle ApplyBundle sends.
const MaxBundleBytes = 32 << 20

// ErrBundleTooLarge is returned by ApplyBundle for a bundle over MaxBundleBytes.
var ErrBundleTooLarge = errors.New("the bundle is larger than 32 MiB")

// FleetVerifyDocument returns the administrator verify document: the
// cluster checks and one verdict. A person who is not an administrator gets
// a 403, a cluster without the route a 501.
func (c *Client) FleetVerifyDocument(ctx context.Context) (fleet.VerifyDocument, error) {
	var out fleet.VerifyDocument
	return out, c.do(ctx, http.MethodGet, "fleet/verify", nil, nil, &out)
}

// ApplyBundle sends a signed policy bundle to the cluster as the request
// body, named by name, optionally limited to some atespaces. The bytes are
// sent as they are; the cluster verifies the signature.
func (c *Client) ApplyBundle(ctx context.Context, name string, data io.Reader, atespaces []string) (map[string]any, error) {
	raw, err := io.ReadAll(io.LimitReader(data, MaxBundleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxBundleBytes {
		return nil, ErrBundleTooLarge
	}
	q := url.Values{}
	if name != "" {
		q.Set("name", name)
	}
	if len(atespaces) > 0 {
		q.Set("atespaces", strings.Join(atespaces, ","))
	}
	var out map[string]any
	return out, c.doRaw(ctx, http.MethodPost, "bundle", q, "application/octet-stream", raw, &out)
}

// BundleStatus returns the policy bundles in force.
func (c *Client) BundleStatus(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "bundle/status", nil, nil, &out)
}

// doRaw is do with a body that is already bytes and its own content type.
func (c *Client) doRaw(ctx context.Context, method, path string, q url.Values, contentType string, body []byte, out any) error {
	u := *c.base
	u.Path = prefix + strings.TrimLeft(path, "/")
	u.RawQuery = q.Encode()
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Content-Type", contentType)
	resp, err := c.hc.Do(req)
	if err != nil {
		return redactErr(err, tok)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return redactErr(err, tok)
	}
	if len(raw) > maxResponse {
		return errors.New("the cluster answer is too large")
	}
	if resp.StatusCode >= 300 {
		e := &Error{Status: resp.StatusCode, Path: path}
		var d struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(raw, &d) == nil {
			e.Reason = d.Reason
		}
		return e
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("the cluster answer is not what this version expects: %w", err)
	}
	return nil
}
