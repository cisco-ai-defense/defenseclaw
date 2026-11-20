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

package sensor

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// agentProviderConfigs are, per CLI connector, the credential-adjacent
// provider configuration files its agent reads itself to reach its model
// provider. Claude Code on Amazon Bedrock loads the AWS shared config at
// every start, an idle TUI session included (GAP-1189). Only files the
// classifier grades credential-adjacent belong here: a secret store
// (~/.aws/credentials, the SSO token cache) is never one.
var agentProviderConfigs = map[string][]string{
	"claudecode": {"/.aws/config"},
}

// ownProviderConfigRead reports whether a credential-adjacent file read is
// the agent process itself (depth 0, recognised as a CLI connector by its
// executable, install path or script) reading its own provider config. Such
// a read is the agent starting up, not credential access, and is not
// recorded. The same read by anything the agent started, by a process
// recognised only by a name pattern or argv, of any other file, and every
// high-confidence read stay credential access.
func ownProviderConfigRead(event plane.Event, lineage agentchain.Lineage, match tactics.Match, indicators tactics.IndicatorSet) bool {
	if event.Kind != plane.KindFileRead || lineage.Depth != 0 ||
		match.SignalID != "agent_credential_access" || match.Confidence >= 1 {
		return false
	}
	for _, file := range agentProviderConfigs[lineage.Root.Agent.Connector] {
		if match.Detail == file && hasPathSuffix(event.Path, file, indicators.CaseInsensitivePaths) {
			return true
		}
	}
	return false
}

// hasPathSuffix reports whether path ends in suffix, folding case where the
// platform's filesystem does.
func hasPathSuffix(path, suffix string, caseInsensitive bool) bool {
	if len(path) < len(suffix) {
		return false
	}
	tail := path[len(path)-len(suffix):]
	if caseInsensitive {
		return strings.EqualFold(tail, suffix)
	}
	return tail == suffix
}
