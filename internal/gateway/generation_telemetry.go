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

import "github.com/defenseclaw/defenseclaw/internal/observability"

// Decision records carry defenseclaw.policy.effective_digest and
// defenseclaw.policy.generation from the live generation. Both are absent
// before the first generation and under the Secure Client integration,
// whose records stay unchanged.

func livePolicyDigestV8() observability.Optional[string] {
	if g := livePolicyGeneration(); g != nil && g.Digest != "" {
		return observability.Present(g.Digest)
	}
	return observability.Absent[string]()
}

func livePolicyGenerationV8() observability.Optional[int64] {
	if g := livePolicyGeneration(); g != nil && g.N > 0 {
		return observability.Present(int64(g.N))
	}
	return observability.Absent[int64]()
}

func livePolicyGeneration() *Generation {
	g := currentGeneration()
	if g == nil || g.Config == nil || g.Config.SecureClientIntegration() {
		return nil
	}
	return g
}
