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
	"strings"

	"github.com/google/cel-go/checker"
)

type sizeBound struct {
	path string
	max  uint64
}

var semanticSizeBounds = [...]sizeBound{
	{"f.tool", maxScalarBytes},
	{"f.cwd", maxScalarBytes},
	{"f.active_home", maxScalarBytes},
	{"f.parse.issues", maxIssues},
	{"f.commands", maxCommands},
	{"f.commands.@items.executable", maxScalarBytes},
	{"f.commands.@items.program", maxScalarBytes},
	{"f.commands.@items.argv", maxArgvItems},
	{"f.commands.@items.argv.@items", maxScalarBytes},
	{"f.commands.@items.arguments", maxArgumentsPerCommand},
	{"f.commands.@items.arguments.@items.value", maxScalarBytes},
	{"f.commands.@items.operations", maxOperationsPerCommand},
	{"f.commands.@items.redirects", maxRedirectsPerCommand},
	{"f.commands.@items.redirects.@items.target", maxScalarBytes},
	{"f.commands.@items.wrappers", maxWrappersPerCommand},
	{"f.commands.@items.wrappers.@items.executable", maxScalarBytes},
	{"f.commands.@items.wrappers.@items.argv", maxArgvItems},
	{"f.commands.@items.wrappers.@items.argv.@items", maxScalarBytes},
	{"f.paths", maxPaths},
	{"f.paths.@items.value", maxScalarBytes},
	{"f.paths.@items.normalized", maxScalarBytes},
	{"f.paths.@items.resolved", maxScalarBytes},
	{"f.network", maxNetwork},
	{"f.network.@items.scheme", maxScalarBytes},
	{"f.network.@items.host", maxScalarBytes},
	{"f.network.@items.normalized_host", maxScalarBytes},
	{"f.data_flows", maxDataFlows},
}

type boundedCostEstimator struct{}

func (boundedCostEstimator) EstimateSize(node checker.AstNode) *checker.SizeEstimate {
	path := strings.Join(node.Path(), ".")
	for _, bound := range semanticSizeBounds {
		if bound.path == path {
			return &checker.SizeEstimate{Min: 0, Max: bound.max}
		}
	}
	return nil
}

func (boundedCostEstimator) EstimateCallCost(
	string,
	string,
	*checker.AstNode,
	[]checker.AstNode,
) *checker.CallEstimate {
	return nil
}

var _ checker.CostEstimator = boundedCostEstimator{}
