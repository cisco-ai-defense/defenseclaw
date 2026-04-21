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

package tui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// fetchHealth calls the gateway REST /health endpoint and returns
// a parsed HealthSnapshot. Returns nil on connection errors.
func fetchHealth(apiPort int) (*HealthSnapshot, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/health", apiPort)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("tui: health fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("tui: health read: %w", err)
	}

	var h HealthSnapshot
	if err := json.Unmarshal(body, &h); err != nil {
		return nil, fmt.Errorf("tui: health parse: %w", err)
	}
	return &h, nil
}
