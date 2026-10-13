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
	"github.com/open-policy-agent/opa/rego" //nolint:staticcheck // v0 compat; migrate to opa/v1 later
)

// CompiledAdmission is config admission: compiled for one asset type, once
// per generation: admission.defaults merged into the type, shorthands
// expanded, severities upper-cased and runtime spelled block|allow. It is
// sent as input.admission for input.target_type, so admission.rego and
// EvaluateAdmissionFallback read only input, never data.json.
type CompiledAdmission struct {
	ScanOnInstall       bool `json:"scan_on_install"`
	AllowListBypassScan bool `json:"allow_list_bypass_scan"`
	// Actions is keyed by CRITICAL, HIGH, MEDIUM, LOW, INFO. A severity
	// with no entry fails closed (install block, runtime block).
	Actions map[string]CompiledAction `json:"actions"`
	// ScannerOverrides is keyed by scan_result.scanner_name, then severity.
	ScannerOverrides    map[string]map[string]CompiledAction `json:"scanner_overrides,omitempty"`
	FirstPartyAllowList []CompiledFirstParty                 `json:"first_party_allow_list,omitempty"`
	// Source says where Actions came from: "config:admission.<type>.actions"
	// or "derived:scanners.<scanner>" (the scanner gate).
	Source string `json:"-"`
}

// CompiledAction is one install/file/runtime triple in Rego spelling.
type CompiledAction struct {
	// Install is block or none.
	Install string `json:"install"`
	// File is quarantine or none.
	File string `json:"file"`
	// Runtime is block or allow.
	Runtime string `json:"runtime"`
	// Verdict is "allowed" for the allow shorthand and empty otherwise,
	// so Rego can tell allow from warn (both are none/none/allow).
	Verdict string `json:"verdict,omitempty"`
}

// CompiledFirstParty is one first-party allow-list entry; SourcePathContains
// entries match whole path components.
type CompiledFirstParty struct {
	Name               string   `json:"name"`
	SourcePathContains []string `json:"source_path_contains"`
	Reason             string   `json:"reason,omitempty"`
}

// ThresholdsInput is input.thresholds for guardrail.rego: the resolved
// block and alert ranks (4=CRITICAL, 3=HIGH, 2=MEDIUM, 1=LOW) and the
// Cisco AI Defense trust level (full, advisory, none).
type ThresholdsInput struct {
	Block           int    `json:"block"`
	Alert           int    `json:"alert"`
	CiscoTrustLevel string `json:"cisco_trust_level"`
}

// Prepared holds the queries prepared once per generation from the loaded
// .rego modules; every evaluation reuses them instead of re-reading and
// re-compiling modules per call.
type Prepared struct {
	Admission rego.PreparedEvalQuery
	Guardrail rego.PreparedEvalQuery
	// RegoDigest is the sha256 of the sorted (name, bytes) of the modules.
	RegoDigest string
}
