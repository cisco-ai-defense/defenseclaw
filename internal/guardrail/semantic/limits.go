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

const (
	// MaxCatalogRules bounds semantic expressions in one effective rulepack.
	MaxCatalogRules = 256
	// MaxEnabledCatalogStaticCost bounds enabled semantic expression cost.
	MaxEnabledCatalogStaticCost uint64 = 32_000_000

	maxExpressionBytes           = 16 << 10
	maxExpressionRunes           = 16 << 10
	maxParserRecursion           = 64
	maxParserRecoveries          = 8
	maxParserNodes               = 8192
	maxExpressionNodes           = 4096
	maxExpressionDepth           = 64
	maxComprehensionDepth        = 2
	maxRegexBytes                = 512
	maxRuleStaticCost     uint64 = 6_000_000
	maxRuleRuntimeCost    uint64 = 1_250_000
	interruptFrequency           = 16

	maxScalarBytes          = 4096
	maxArgvItems            = 256
	maxArgvBytes            = 65536
	maxCommands             = 128
	maxArgumentsPerCommand  = 256
	maxOperationsPerCommand = 30
	maxRedirectsPerCommand  = 256
	maxWrappersPerCommand   = 4
	maxPaths                = 256
	maxNetwork              = 128
	maxDataFlows            = 256
	maxIssues               = 8
)
