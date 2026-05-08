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

import "context"

// TokenResolverFunc resolves an API key for a given provider.
// When registered via SetTokenResolver, the gateway calls this function
// instead of reading credentials from environment variables, dotenv files,
// or the X-AI-Auth request header.
//
// Parameters:
//   - ctx: request context
//   - provider: LLM provider name (e.g., "openai", "anthropic")
//
// Returns the API key string or an error if resolution fails.
type TokenResolverFunc func(ctx context.Context, provider string) (string, error)

var tokenResolver TokenResolverFunc

// SetTokenResolver registers an external token resolution function.
// When set, the gateway uses this function to obtain API keys instead of
// local resolution (env vars, dotenv, X-AI-Auth header).
// Pass nil to revert to default behavior.
func SetTokenResolver(fn TokenResolverFunc) {
	tokenResolver = fn
}

var localKeyResolutionDisabled bool

// DisableLocalKeyResolution prevents the gateway from reading API keys
// from environment variables, dotenv files, or the X-AI-Auth request header.
// When disabled, a TokenResolver must be registered or all LLM requests
// will fail with an error.
//
// This is intended for enterprise deployments where credentials are managed
// externally and must never be present in the gateway process.
func DisableLocalKeyResolution() {
	localKeyResolutionDisabled = true
}

// IsLocalKeyResolutionDisabled returns whether local key resolution is disabled.
func IsLocalKeyResolutionDisabled() bool {
	return localKeyResolutionDisabled
}
