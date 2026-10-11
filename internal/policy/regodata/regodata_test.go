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

package regodata

import (
	"slices"
	"testing"

	"github.com/open-policy-agent/opa/ast" //nolint:staticcheck // v0 compat; migrate to opa/v1 later
)

// A computed key on the data root (data[key]) can name a removed data.json
// document, so it is a legacy read; a data.defenseclaw read is not, and a
// variable key under it still reaches the helper module (GAP-1425).
func TestModuleReadsComputedDataKey(t *testing.T) {
	parse := func(src string) *ast.Module {
		return ast.MustParseModuleWithOpts(src, ast.ParserOptions{RegoVersion: ast.RegoV1})
	}
	modules := map[string]*ast.Module{
		"admission.rego": parse("package defenseclaw.admission\nimport rego.v1\n" +
			"key := \"config\"\nverdict := \"blocked\" if data[key].block\n" +
			"verdict := \"blocked\" if { some k; data.defenseclaw[k].block }\n"),
		"helper.rego": parse("package defenseclaw.helper\nimport rego.v1\n" +
			"block if data[\"defenseclaw\"].admission.verdict == \"x\"\n"),
	}
	reads := OutsideReads(modules, "data.defenseclaw.admission")
	if len(reads) != 1 || reads[0].Module != "admission.rego" || !slices.Equal(reads[0].Docs, []string{"data[key]"}) {
		t.Fatalf("OutsideReads = %+v, want admission.rego reading data[key]", reads)
	}
	refs, docs := ModuleReads(modules["helper.rego"])
	if len(docs) != 0 || len(refs) != 1 {
		t.Fatalf("helper: refs %v docs %v, want one data.defenseclaw ref and no legacy doc", refs, docs)
	}
}
