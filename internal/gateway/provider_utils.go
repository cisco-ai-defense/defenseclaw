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

package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
)

// patchRawBody takes raw JSON bytes and overrides the "model" and "stream"
// fields, preserving every other field the client sent. It also caps
// max_tokens to the model's limit to avoid 400 errors.
func patchRawBody(raw json.RawMessage, model string, stream bool) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("provider: patch raw body: %w", err)
	}
	modelBytes, _ := json.Marshal(model)
	m["model"] = modelBytes
	streamBytes, _ := json.Marshal(stream)
	m["stream"] = streamBytes

	limit := modelMaxTokens(model)
	for _, tokKey := range []string{"max_tokens", "max_completion_tokens"} {
		if maxTokRaw, ok := m[tokKey]; ok {
			var maxTok int
			if json.Unmarshal(maxTokRaw, &maxTok) == nil && limit > 0 && maxTok > limit {
				capBytes, _ := json.Marshal(limit)
				m[tokKey] = capBytes
			}
		}
	}

	return json.Marshal(m)
}

const defaultMaxTokensFallback = 8192

func modelMaxTokens(model string) int {
	switch {
	case strings.HasPrefix(model, "gpt-4o-mini"):
		return 16384
	case strings.HasPrefix(model, "gpt-4o"):
		return 16384
	case strings.HasPrefix(model, "gpt-4-turbo"):
		return 4096
	case strings.HasPrefix(model, "gpt-4"):
		return 8192
	case strings.HasPrefix(model, "o3-mini"):
		return 100000
	case strings.HasPrefix(model, "o3"):
		return 100000
	case strings.HasPrefix(model, "o4-mini"):
		return 100000
	case strings.HasPrefix(model, "claude"):
		return 8192
	default:
		return defaultMaxTokensFallback
	}
}
