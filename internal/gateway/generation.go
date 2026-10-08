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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// Generation is everything one applied configuration compiles to. It is
// built off the request path (load, migrate in memory, validate, compose
// rule packs, prepare OPA, compile admission, resolve thresholds, compute
// digests) and published with an atomic pointer swap. Every request loads
// the current generation once and reads only from it; a failed build keeps
// the previous generation and reports last_reload_error.
type Generation struct {
	// N is the in-process applied counter; it increments on every swap,
	// from a config or an asset change.
	N uint64
	// ConfigGen is config_generation from config.generation.json.
	ConfigGen uint64
	// ConfigGenRecorded is false when config.yaml's sha256 differs from the
	// one config.generation.json recorded (a hand edit).
	ConfigGenRecorded bool
	Config            *config.Config
	// RulePacks are the composed packs keyed by resolution key: global,
	// conn:<c>, prof:<p> or prof:<p>/<c>.
	RulePacks map[string]*guardrail.RulePack
	Profiles  *guardrailProfileSet
	// The hook judge is published with its policy so reload cannot pair a new
	// judge gate with a nil or previous judge.
	hookJudge      *LLMJudge
	hookJudgeBound bool
	OPA            *policy.Prepared
	// Admission is keyed by config.AdmissionType* (skill, mcp, plugin, tool).
	Admission   map[string]policy.CompiledAdmission
	AssetPolicy *config.AssetPolicyConfig
	Thresholds  thresholdTable
	Scanners    scannerSettings
	Providers   *generationProviders
	// Digest is effective_policy_digest: "sha256:" + hex of the canonical
	// JSON of the migrated config (secrets dropped, data_dir paths
	// rewritten), the asset digests and the profile digests.
	Digest string
	// Components holds the per-component digests (config, rule_pack:<key>,
	// rego, sandbox_pack, signature_pack:<path>, confidence_policy,
	// scanner_policy:skill, yara_rules:mcp, builtin, profile:<name>).
	Components map[string]string
	BuiltAt    time.Time

	// active is the pack the shared scanners and the judge use: the single
	// enabled connector's, else the global one.
	active *guardrail.RulePack
	// opaError is why a non-strict build has no OPA ("" when it has one).
	opaError string
	// assetDirs are the directories the config watcher follows for this
	// generation (rule packs and Rego modules).
	assetDirs []string
	// assetFiles are the single-file assets it follows: signature packs, the
	// discovery confidence policy, the skill-scanner policy file, the MCP
	// scanner's extra YARA rules and the custom providers' CA files.
	assetFiles []string
}

// ResolvedThresholds is the block and alert severity for one (profile,
// connector) pair. Source is "config:<path>" or "pack-default:<pack>".
type ResolvedThresholds struct {
	Block  string
	Alert  string
	Source string
}

// thresholdKey selects a ResolvedThresholds; empty fields mean no profile
// or no connector.
type thresholdKey struct {
	Profile   string
	Connector string
}

// thresholdTable is resolved for every (profile, connector) pair at
// generation build.
type thresholdTable map[thresholdKey]ResolvedThresholds

// scannerSettings is the scanner configuration of one generation; scanners
// are built from it per scan.
type scannerSettings struct {
	Skill config.SkillScannerConfig
	MCP   config.MCPScannerConfig
}

// generationProviders is the LLM provider registry of one generation, built
// from the embedded providers and llm_providers.
type generationProviders struct {
	Providers   []configs.Provider
	OllamaPorts []int
}

// PolicyHealth is the "policy" object of /health and /status. It is omitted
// under SecureClientIntegration().
type PolicyHealth struct {
	EffectiveDigest          string `json:"effective_digest"`
	Generation               uint64 `json:"generation"`
	ConfigGeneration         uint64 `json:"config_generation"`
	ConfigGenerationRecorded bool   `json:"config_generation_recorded"`
	BuiltAt                  string `json:"built_at"`
	LastReloadError          string `json:"last_reload_error,omitempty"`
	// PendingRestart lists the changed config keys that apply only after a
	// gateway restart.
	PendingRestart []string          `json:"pending_restart,omitempty"`
	Components     map[string]string `json:"components,omitempty"`
}
