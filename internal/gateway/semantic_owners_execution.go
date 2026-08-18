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

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

const (
	// Registered owner prerequisites prove the exact source-to-interpreter
	// pipeline. The CEL surface intentionally stays at the source-operation
	// level so the whole shipped catalog remains below its bounded static-cost
	// ceiling, matching the other command-specific semantic owners.
	semanticCurlDownloadExecExpression = `f.commands.exists(c, c.argv_complete && c.program in ['curl', 'curl.exe', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm'] && (defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_FETCH in c.operations || defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_UPLOAD in c.operations))`
	semanticWgetDownloadExecExpression = `f.commands.exists(c, c.argv_complete && c.program in ['wget', 'wget.exe'] && (defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_FETCH in c.operations || defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_UPLOAD in c.operations))`
	semanticBase64DecodeExecExpression = `f.commands.exists(c, c.argv_complete && c.program in ['base64', 'base64.exe'] && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_DECODE in c.operations)`
)

func curlDownloadExecPrerequisite(facts actionfacts.Facts) bool {
	return powerShellDownloadExecPrerequisite(facts) ||
		stdinInterpreterPipelineFallbackProof(
			facts,
			actionfacts.OperationFetch,
			"curl",
			"curl.exe",
		)
}

func wgetDownloadExecPrerequisite(facts actionfacts.Facts) bool {
	return stdinInterpreterPipelineFallbackProof(
		facts,
		actionfacts.OperationFetch,
		"wget",
		"wget.exe",
	)
}

func base64DecodeExecPrerequisite(facts actionfacts.Facts) bool {
	return stdinInterpreterPipelineFallbackProof(
		facts,
		actionfacts.OperationDecode,
		"base64",
		"base64.exe",
	)
}
