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

package audit

import (
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// PolicyStamp returns the live generation's effective policy digest and
// applied generation (absent before the first generation and under the
// Secure Client integration).
type PolicyStamp func() (digest observability.Optional[string], generation observability.Optional[int64])

var policyStamp atomic.Pointer[PolicyStamp]

// SetPolicyStamp binds the stamp that enforcement records (asset
// quarantine) carry as defenseclaw.policy.effective_digest and
// defenseclaw.policy.generation. The gateway calls it once at start; a
// process that never does (the CLI) emits the records without them.
func SetPolicyStamp(stamp PolicyStamp) {
	if stamp == nil {
		policyStamp.Store(nil)
		return
	}
	policyStamp.Store(&stamp)
}

func livePolicyStamp() (observability.Optional[string], observability.Optional[int64]) {
	if stamp := policyStamp.Load(); stamp != nil {
		return (*stamp)()
	}
	return observability.Absent[string](), observability.Absent[int64]()
}
