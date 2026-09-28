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
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// kiroHookSurfaceFromHeaders returns the Kiro hook surface a request names:
// which of the two hook configurations DefenseClaw installs invoked it (see
// connector.KiroBlockEventsForSurface). The native hook binary, which Kiro
// runs on Windows, sends the generic connector.HookDialectHeader. The bash
// hook, kiro-hook.sh, sends connector.KiroSurfaceHeader. The generic header
// wins when a request carries both. An absent or unknown value selects the
// CLI 2.x veto set, which claims fewer blocks.
func kiroHookSurfaceFromHeaders(header http.Header) string {
	if surface := strings.TrimSpace(header.Get(connector.HookDialectHeader)); surface != "" {
		return surface
	}
	return strings.TrimSpace(header.Get(connector.KiroSurfaceHeader))
}
