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

package semantic

import (
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
	"github.com/google/cel-go/cel"
)

func newEnvironment() (*cel.Env, error) {
	root := &semanticpb.Facts{}
	fullName := string(root.ProtoReflect().Descriptor().FullName())
	return cel.NewEnv(
		cel.Types(root),
		cel.Variable("f", cel.ObjectType(fullName)),
		cel.ParserExpressionSizeLimit(maxExpressionRunes),
		cel.ParserRecursionLimit(maxParserRecursion),
		cel.ParserErrorRecoveryLimit(maxParserRecoveries),
		// Keep a hard parser/checker ceiling above the explicit admission
		// limit so ordinary 4,097-node expressions receive CompileASTNodes
		// without interpreting cel-go diagnostic text.
		cel.ExpressionNodeLimit(maxParserNodes),
	)
}
