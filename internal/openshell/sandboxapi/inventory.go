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
	"time"
)

// DiscoveryResult is POST /sandboxes/{name}/discover: what the AI discovery
// of a ready sandbox found in it. Every text field is the sandbox's, made
// safe to print.
type DiscoveryResult struct {
	Name       string    `json:"name"`
	ScannedAt  time.Time `json:"scanned_at"`
	DurationMs int64     `json:"duration_ms"`
	// Result is ok, or partial when the scan fell short of reading
	// everything (Problems say where: a bound, records refused).
	Result   string   `json:"result"`
	Problems []string `json:"problems,omitempty"`
	// Entries are the files and folders the sandbox reported, and Files the
	// files the detectors read.
	Entries int               `json:"entries"`
	Files   int               `json:"files"`
	Signals []DiscoverySignal `json:"signals"`
}

// DiscoverySignal is one AI component found in a sandbox.
type DiscoverySignal struct {
	// Category is the signal category (mcp_server, skill, ai_cli, ...),
	// Detector what found it (mcp, skill, binary, process, ...).
	Category string `json:"category"`
	Product  string `json:"product"`
	Vendor   string `json:"vendor,omitempty"`
	Detector string `json:"detector"`
	// Names are what the evidence names: MCP server, skill or file names.
	Names      []string `json:"names,omitempty"`
	Confidence float64  `json:"confidence"`
}

// Discover runs the AI discovery of a ready sandbox now.
func (c *Client) Discover(ctx context.Context, name string) (*DiscoveryResult, error) {
	var out DiscoveryResult
	if err := c.do(ctx, http.MethodPost, sandboxPath(name, "discover"), nil, struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
