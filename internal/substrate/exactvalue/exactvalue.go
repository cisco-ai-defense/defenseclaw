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

// Package exactvalue holds the forms in which an exposed actor_secrets value
// is matched by exact-value DLP. The egress callout (request URLs, headers
// and bodies) and the gateway (/llm prompts) share it, so both look for the
// same spellings.
package exactvalue

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
)

// MinLen keeps short values from matching everywhere: a shorter value has
// no forms.
const MinLen = 8

// Forms returns v as is, JSON-escaped (a prompt or a JSON body carries it
// as a JSON string), base64 in the standard and URL alphabets with and
// without padding, and URL-encoded (query and path escaping), without
// repeats. nil for a value shorter than MinLen.
func Forms(v string) []string {
	if len(v) < MinLen {
		return nil
	}
	b := []byte(v)
	escaped, _ := json.Marshal(v)
	seen := map[string]bool{}
	var out []string
	for _, f := range []string{v, string(escaped[1 : len(escaped)-1]),
		base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b),
		url.QueryEscape(v), url.PathEscape(v)} {
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}
