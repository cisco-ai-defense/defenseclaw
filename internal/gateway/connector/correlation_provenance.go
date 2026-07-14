// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const correlationSourceCheckedDate = "2026-07-14"

func correlationContractSources(name string) []CorrelationContractSource {
	source := func(id, uri, revision string) []CorrelationContractSource {
		return []CorrelationContractSource{{
			ID: id, URI: uri, Revision: revision, CheckedDate: correlationSourceCheckedDate,
		}}
	}
	switch name {
	case "explicit":
		return source("defenseclaw-explicit-canonical-v1",
			"builtin://defenseclaw/explicit-canonical-correlation", "profile:explicit-canonical-v1")
	case "openclaw":
		return source("openclaw-source-b93f4bb3",
			"https://github.com/openclaw/openclaw", "b93f4bb3ac03f758cf807d109cdd3ef1702fdd6a")
	case "zeptoclaw":
		return source("zeptoclaw-source-2792c346",
			"https://github.com/qhkm/zeptoclaw", "2792c34670b243c98b0431a732d7329618051624")
	case "codex":
		return []CorrelationContractSource{{
			ID: "codex-source-f90e7dee", URI: "https://github.com/openai/codex",
			Revision: "f90e7deea6a715bbd153044af6f475eefa749177", CheckedDate: correlationSourceCheckedDate,
			Fixtures: []CorrelationContractFixture{{
				ID: "codex-tool-result-f90e7dee", Surface: CorrelationSurfaceNativeOTLP,
				Path:         "internal/gateway/testdata/correlation/codex/f90e7deea6a715bbd153044af6f475eefa749177/tool-result.logs.json",
				SHA256:       "sha256:ca4f38ce356512d4053ede15e60764985075344d7ad77a2260e97989154314e7",
				AgentVersion: "source-revision:f90e7deea6a715bbd153044af6f475eefa749177",
				EvidenceKind: "provider-source-derived",
			}},
		}}
	case "claudecode":
		return []CorrelationContractSource{
			{
				ID: "claudecode-hooks-doc-55fab1f8", URI: "https://code.claude.com/docs/en/hooks",
				Revision:    "sha256:55fab1f8e47c45025253505869bbdfc08e983521d83ee83837ccdd77eb734cd2",
				CheckedDate: correlationSourceCheckedDate,
			},
			{
				ID: "claudecode-monitoring-doc-30703875", URI: "https://code.claude.com/docs/en/monitoring-usage",
				Revision:    "sha256:30703875ce62463eda4f0efe92dd7f9d57207424f990f39fc72c77c06fb96190",
				CheckedDate: correlationSourceCheckedDate,
				Fixtures: []CorrelationContractFixture{
					{
						ID: "claudecode-post-tool-use-30703875", Surface: CorrelationSurfaceHook,
						Path:         "internal/gateway/testdata/correlation/claudecode/docs-sha256-30703875ce62463eda4f0efe92dd7f9d57207424f990f39fc72c77c06fb96190/post-tool-use.hook.source.json",
						SHA256:       "sha256:9ca911ebae4061cb221d25c49d667ec138f197faa10a80f156287fc99719c0e0",
						AgentVersion: "documentation-snapshot", EvidenceKind: "provider-source-derived",
					},
					{
						ID: "claudecode-tool-span-30703875", Surface: CorrelationSurfaceNativeOTLP,
						Path:         "internal/gateway/testdata/correlation/claudecode/docs-sha256-30703875ce62463eda4f0efe92dd7f9d57207424f990f39fc72c77c06fb96190/tool.span.source.json",
						SHA256:       "sha256:59f6131bb57275f4caab5ef6a2ff1de3ae3d9d285b73dd1cf1ea11604bdb613e",
						AgentVersion: "documentation-snapshot", EvidenceKind: "provider-source-derived",
					},
				},
			},
		}
	case "hermes":
		return source("hermes-source-7e84d2b5",
			"https://github.com/NousResearch/hermes-agent", "7e84d2b5a43d47b1da33cfa662d0f87991774b1c")
	case "cursor":
		return source("cursor-hooks-doc-d13a6fc6",
			"https://cursor.com/docs/hooks", "sha256:d13a6fc6c1cc3fbe1abccf8bbd9044781a24ebb6cb8ed4870574c3bd4b9694d4")
	case "windsurf":
		return source("windsurf-hooks-doc-9a43fa5d",
			"https://docs.windsurf.com/windsurf/cascade/hooks", "sha256:9a43fa5d3f3963f842e8b18b4861f59d121e3782c053dbedb230788f19ff04bd")
	case "geminicli":
		return source("geminicli-source-fa975395",
			"https://github.com/google-gemini/gemini-cli", "fa975395bcc6b609e44735e47320e54f51535d47")
	case "copilot":
		return source("copilot-hooks-doc-7d1b4045",
			"https://docs.github.com/en/copilot/reference/hooks-reference", "sha256:7d1b404551d6f91bb96fce7452b22ead4505374b79d8906a49652d1fae47d224")
	case "openhands":
		return source("openhands-source-a55f1ded",
			"https://github.com/All-Hands-AI/OpenHands", "a55f1ded61cac85d6e42aee9e460320ead93ae6a")
	case "antigravity":
		return source("antigravity-hooks-doc-9c9b420a",
			"https://antigravity.google/docs/hooks", "sha256:9c9b420a22b35ae6610133d803706678c66282cbb5479816a8f56f1175780acb")
	case "opencode":
		return source("opencode-source-75cf4cc8",
			"https://github.com/anomalyco/opencode", "75cf4cc8a83a5b5f99ba974f135f690a1f9b5a76")
	case "omnigent":
		return source("omnigent-source-9ee53ece",
			"https://github.com/omnigent-ai/omnigent", "9ee53ecea9ceaab679f84c0c5f15695c8ccd0c3d")
	default:
		return nil
	}
}

func correlationFieldEvidence(name string) []CorrelationFieldEvidence {
	switch name {
	case "codex":
		const (
			sourceID = "codex-source-f90e7dee"
			proofID  = "codex-tool-use-call-id-f90e7dee"
		)
		return []CorrelationFieldEvidence{
			{
				SourceID: sourceID, Surface: CorrelationSurfaceHook,
				Target: CorrelationTargetTool, Path: "tool_use_id", MirrorProofID: proofID,
			},
			{
				SourceID: sourceID, FixtureID: "codex-tool-result-f90e7dee", Surface: CorrelationSurfaceNativeOTLP,
				Target: CorrelationTargetTool, Path: "call_id", Authoritative: true,
				MirrorProofID: proofID,
			},
		}
	case "claudecode":
		const (
			sourceID = "claudecode-monitoring-doc-30703875"
			proofID  = "claudecode-tool-use-genai-call-30703875"
		)
		return []CorrelationFieldEvidence{
			{
				SourceID: sourceID, FixtureID: "claudecode-post-tool-use-30703875", Surface: CorrelationSurfaceHook,
				Target: CorrelationTargetTool, Path: "tool_use_id", MirrorProofID: proofID,
			},
			{
				SourceID: sourceID, FixtureID: "claudecode-tool-span-30703875", Surface: CorrelationSurfaceNativeOTLP,
				Target: CorrelationTargetTool, Path: "tool_use_id", Authoritative: true,
				MirrorProofID: proofID,
			},
			{
				SourceID: sourceID, FixtureID: "claudecode-tool-span-30703875", Surface: CorrelationSurfaceNativeOTLP,
				Target: CorrelationTargetTool, Path: "gen_ai.tool.call.id", Authoritative: true,
				MirrorProofID: proofID,
			},
		}
	default:
		return nil
	}
}

func (s CorrelationSpec) evidenceForValue(
	surface CorrelationSurface,
	value CorrelationValue,
) (CorrelationFieldEvidence, bool) {
	for _, evidence := range s.FieldEvidence {
		if evidence.Surface == surface && evidence.Target == value.Target &&
			evidence.Path == value.Path {
			return evidence, true
		}
	}
	return CorrelationFieldEvidence{}, false
}

// IsAuthoritativeValue requires evidence for this exact spelling and surface.
// Target-level capabilities alone are never enough: for example, a generic
// gen_ai.tool.call.id remains typed evidence even when a provider-specific
// call_id on the same target is authoritative.
func (s CorrelationSpec) IsAuthoritativeValue(surface CorrelationSurface, value CorrelationValue) bool {
	evidence, ok := s.evidenceForValue(surface, value)
	return ok && evidence.Authoritative && s.NativeTelemetry.IsAuthoritative(value.Target)
}

// MirrorProofForValue returns the immutable source proof for an exact field.
// An empty/missing field path fails closed rather than inheriting authority
// from another alias that happens to populate the same target.
func (s CorrelationSpec) MirrorProofForValue(
	surface CorrelationSurface,
	value CorrelationValue,
) (string, bool) {
	evidence, ok := s.evidenceForValue(surface, value)
	if !ok || strings.TrimSpace(evidence.MirrorProofID) == "" ||
		!s.AllowsMirrorTarget(value.Target) {
		return "", false
	}
	return evidence.MirrorProofID, true
}

func (s CorrelationSpec) mirrorProofIDsForTarget(target CorrelationTarget) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, 1)
	for _, evidence := range s.FieldEvidence {
		proof := strings.TrimSpace(evidence.MirrorProofID)
		if evidence.Target != target || proof == "" || seen[proof] {
			continue
		}
		seen[proof] = true
		result = append(result, proof)
	}
	return result
}

// MirrorProofIDForTarget returns the one reviewed equivalence rule for target.
// Multiple independent proofs require a future matcher capable of carrying a
// proof per identifier kind; until then ambiguity fails closed.
func (s CorrelationSpec) MirrorProofIDForTarget(target CorrelationTarget) (string, bool) {
	proofs := s.mirrorProofIDsForTarget(target)
	if len(proofs) != 1 {
		return "", false
	}
	return proofs[0], true
}

func (s CorrelationSpec) bindingsForSurface(surface CorrelationSurface) []CorrelationFieldBinding {
	switch surface {
	case CorrelationSurfaceHook:
		return s.HookBindings
	case CorrelationSurfaceNativeOTLP:
		return s.NativeOTLPBindings
	case CorrelationSurfaceProxy:
		return s.ProxyBindings
	case CorrelationSurfaceStream:
		return s.StreamBindings
	default:
		return nil
	}
}

func (s CorrelationSpec) bindingForEvidence(evidence CorrelationFieldEvidence) (CorrelationFieldBinding, bool) {
	for _, binding := range s.bindingsForSurface(evidence.Surface) {
		if binding.Target != evidence.Target {
			continue
		}
		for _, path := range binding.Paths {
			if path == evidence.Path {
				return binding, true
			}
		}
	}
	return CorrelationFieldBinding{}, false
}

func (s CorrelationSpec) validateProvenance(validTarget map[CorrelationTarget]bool) error {
	if len(s.ContractSources) == 0 {
		return fmt.Errorf("correlation profile %q has no immutable contract source", s.ProfileVersion)
	}
	sources := make(map[string]CorrelationContractSource, len(s.ContractSources))
	fixtures := make(map[string]CorrelationContractFixture)
	for _, source := range s.ContractSources {
		if strings.TrimSpace(source.ID) == "" || strings.TrimSpace(source.URI) == "" ||
			!immutableCorrelationRevision(source.URI, source.Revision) {
			return fmt.Errorf("correlation contract source %q is not immutable", source.ID)
		}
		if _, err := time.Parse("2006-01-02", source.CheckedDate); err != nil {
			return fmt.Errorf("correlation contract source %q has invalid checked date", source.ID)
		}
		if _, exists := sources[source.ID]; exists {
			return fmt.Errorf("correlation contract source %q is repeated", source.ID)
		}
		sources[source.ID] = source
		for _, fixture := range source.Fixtures {
			if strings.TrimSpace(fixture.ID) == "" || strings.TrimSpace(fixture.Path) == "" ||
				!validSHA256Revision(fixture.SHA256) || strings.TrimSpace(fixture.EvidenceKind) == "" {
				return fmt.Errorf("correlation contract fixture %q is incomplete", fixture.ID)
			}
			if _, exists := fixtures[fixture.ID]; exists {
				return fmt.Errorf("correlation contract fixture %q is repeated", fixture.ID)
			}
			fixtures[fixture.ID] = fixture
		}
	}

	authoritativeEvidence := make(map[CorrelationTarget]bool)
	type mirrorSide struct {
		native, other bool
		namespace     string
		kind          string
	}
	mirrors := make(map[string]mirrorSide)
	for _, evidence := range s.FieldEvidence {
		if !validTarget[evidence.Target] || strings.TrimSpace(evidence.SourceID) == "" ||
			strings.TrimSpace(evidence.Path) == "" {
			return fmt.Errorf("correlation field evidence is incomplete")
		}
		if _, ok := sources[evidence.SourceID]; !ok {
			return fmt.Errorf("correlation field evidence references unknown source %q", evidence.SourceID)
		}
		binding, ok := s.bindingForEvidence(evidence)
		if !ok {
			return fmt.Errorf("correlation field evidence %s/%s/%s has no binding", evidence.Surface, evidence.Target, evidence.Path)
		}
		if evidence.FixtureID != "" {
			fixture, ok := fixtures[evidence.FixtureID]
			if !ok || fixture.Surface != evidence.Surface {
				return fmt.Errorf("correlation field evidence references incompatible fixture %q", evidence.FixtureID)
			}
		}
		if evidence.Authoritative {
			if evidence.Surface != CorrelationSurfaceNativeOTLP {
				return fmt.Errorf("only native_otlp field evidence can be authoritative")
			}
			authoritativeEvidence[evidence.Target] = true
		}
		proof := strings.TrimSpace(evidence.MirrorProofID)
		if proof == "" {
			continue
		}
		if !s.AllowsMirrorTarget(evidence.Target) {
			return fmt.Errorf("field evidence declares disabled mirror target %q", evidence.Target)
		}
		side := mirrors[proof]
		if side.namespace == "" {
			side.namespace, side.kind = binding.Namespace, binding.IDKind
		} else if side.namespace != binding.Namespace || side.kind != binding.IDKind {
			return fmt.Errorf("mirror proof %q crosses typed identifier kinds", proof)
		}
		if evidence.Surface == CorrelationSurfaceNativeOTLP && evidence.Authoritative {
			side.native = true
		} else if evidence.Surface != CorrelationSurfaceNativeOTLP {
			side.other = true
		}
		mirrors[proof] = side
	}

	for _, target := range s.NativeTelemetry.AuthoritativeFields {
		if !authoritativeEvidence[target] {
			return fmt.Errorf("authoritative native field %q lacks exact source evidence", target)
		}
	}
	for target := range authoritativeEvidence {
		if !s.NativeTelemetry.IsAuthoritative(target) {
			return fmt.Errorf("field evidence grants undeclared native authority to %q", target)
		}
	}
	for _, target := range s.MirrorIdentityTargets {
		proofs := s.mirrorProofIDsForTarget(target)
		if len(proofs) == 0 {
			return fmt.Errorf("mirror target %q lacks immutable field proof", target)
		}
		for _, proof := range proofs {
			side := mirrors[proof]
			if !side.native || !side.other {
				return fmt.Errorf("mirror proof %q lacks authoritative native and peer-rail fields", proof)
			}
		}
	}
	return nil
}

func immutableCorrelationRevision(uri, revision string) bool {
	if strings.HasPrefix(uri, "builtin://") {
		return strings.HasPrefix(revision, "profile:") && len(strings.TrimPrefix(revision, "profile:")) > 0
	}
	if !strings.HasPrefix(uri, "https://") {
		return false
	}
	if validSHA256Revision(revision) {
		return true
	}
	return len(revision) == 40 && validLowerHex(revision)
}

func validSHA256Revision(revision string) bool {
	value := strings.TrimPrefix(revision, "sha256:")
	return value != revision && len(value) == 64 && validLowerHex(value)
}

func validLowerHex(value string) bool {
	if value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
