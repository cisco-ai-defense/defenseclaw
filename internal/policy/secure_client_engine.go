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

package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"          //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/storage/inmem" //nolint:staticcheck // v0 compat; migrate to opa/v1 later
)

// PrepareSecureClientExact compiles a selected Secure Client policy bundle
// against its legacy data.json. The v9 legacy-data rejection must stay on the
// ordinary engine; Secure Client keeps the pre-1.0 policy commands (#1092).
func PrepareSecureClientExact(ctx context.Context, regoDir string) (*Prepared, error) {
	data, err := LoadSecureClientData(regoDir)
	if err != nil {
		return nil, err
	}
	modules, err := readModules(regoDir, nil)
	if err != nil {
		return nil, err
	}
	store := inmem.NewFromObject(data)
	prepare := func(query string) (rego.PreparedEvalQuery, error) {
		opts := append(regoOptions(query, modules), rego.Store(store))
		return rego.New(opts...).PrepareForEval(ctx)
	}
	admission, err := prepare(admissionQuery)
	if err != nil {
		return nil, fmt.Errorf("policy: prepare admission: %w", err)
	}
	guardrail, err := prepare(guardrailQuery)
	if err != nil {
		return nil, fmt.Errorf("policy: prepare guardrail: %w", err)
	}
	return &Prepared{Admission: admission, Guardrail: guardrail, RegoDigest: regoDigest(modules)}, nil
}
