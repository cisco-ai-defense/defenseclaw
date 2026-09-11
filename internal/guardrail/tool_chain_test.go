// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestMatchToolChainsFixedCatalog(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	for _, definition := range ToolChainDefinitions() {
		t.Run(definition.ID, func(t *testing.T) {
			wantSeverity := "HIGH"
			if definition.ID == ToolChainSecretReadThenEgress ||
				definition.ID == ToolChainDownloadDecodeExecuteSameArtifact ||
				definition.ID == ToolChainStagedReverseShellPersistence {
				wantSeverity = "CRITICAL"
			}
			if definition.Step3Bit != 0 {
				return
			}
			if definition.Severity != wantSeverity {
				t.Fatalf("severity=%q want %s", definition.Severity, wantSeverity)
			}
			firstProjection := ToolChainProjection{
				ParseStatus:         actionfacts.StatusComplete,
				DetectionStepMask:   definition.Step1Bit,
				EnforcementStepMask: definition.Step1Bit,
			}
			finalProjection := ToolChainProjection{
				ParseStatus:         actionfacts.StatusComplete,
				DetectionStepMask:   definition.Step2Bit,
				EnforcementStepMask: definition.Step2Bit,
			}
			if definition.RequiresEnforcementJoin || definition.RequiresExactJoin {
				index, _ := ToolChainIndexByID(definition.ID)
				const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				firstProjection.EnforcementJoinDigests[index] = digest
				finalProjection.EnforcementJoinDigests[index] = digest
			}
			matches, err := MatchToolChains([]ToolChainWindowEvent{{
				SemanticEventID: "first", Sequence: 1, ReceivedAt: now,
				Projection: firstProjection,
			}}, ToolChainWindowEvent{
				SemanticEventID: "final", Sequence: 2, ReceivedAt: now.Add(time.Second),
				Projection: finalProjection,
			})
			if err != nil {
				t.Fatal(err)
			}
			wantEnforcement := definition.ResultBit
			if definition.DetectionOnly {
				wantEnforcement = 0
			}
			if matches.DetectedMask != definition.ResultBit ||
				matches.EnforcementSafeMask != wantEnforcement {
				t.Fatalf("masks=%08b/%08b want %08b/%08b",
					matches.DetectedMask, matches.EnforcementSafeMask,
					definition.ResultBit, wantEnforcement)
			}
		})
	}
}

func TestToolChainExistingBitAssignmentsRemainStable(t *testing.T) {
	want := map[string][3]uint64{
		ToolChainGuardrailsOffThenEgress:            {1 << 0, 1 << 1, 0},
		ToolChainPermissionDeniedThenBypass:         {1 << 2, 1 << 3, 0},
		ToolChainPrivilegeDiscoveryThenElevation:    {1 << 4, 1 << 5, 0},
		ToolChainSecretManagerReadThenEgress:        {1 << 6, 1 << 7, 0},
		ToolChainSecretReadThenEgress:               {1 << 8, 1 << 9, 0},
		ToolChainWorkloadIdentityThenLateralExec:    {1 << 10, 1 << 11, 0},
		ToolChainDownloadDecodeExecuteSameArtifact:  {1 << 12, 1 << 13, 1 << 14},
		ToolChainDownloadThenExecuteSameArtifact:    {1 << 15, 1 << 16, 0},
		ToolChainSensitiveEgressArtifactThenExec:    {1 << 17, 1 << 18, 0},
		ToolChainFirewallExpansionThenDestination:   {1 << 20, 1 << 21, 0},
		ToolChainSQLServerXPCommandShellExecution:   {1 << 22, 1 << 23, 0},
		ToolChainPrivilegedKubernetesHostRootExec:   {1 << 25, 1 << 26, 1 << 27},
		ToolChainWirelessCaptureThenDeauthSameBSSID: {1 << 29, 1 << 30, 0},
		ToolChainSecretsdumpThenPsExecSameIdentity:  {1 << 31, 1 << 32, 0},
		ToolChainCloudIAMPrincipalAdmin:             {1 << 33, 1 << 34, 0},
		ToolChainKubernetesPrivilegedCronJob:        {1 << 35, 1 << 36, 0},
		ToolChainSQLCommandUDF:                      {1 << 38, 1 << 39, 0},
		ToolChainStagedReverseShellPersistence:      {1 << 41, 1 << 42, 0},
	}
	for index, definition := range ToolChainDefinitions() {
		bits, ok := want[definition.ID]
		if !ok {
			t.Fatalf("unexpected chain %q", definition.ID)
		}
		if got := [3]uint64{definition.Step1Bit, definition.Step2Bit, definition.Step3Bit}; got != bits {
			t.Fatalf("%s bits=%v want=%v", definition.ID, got, bits)
		}
		if wantResult := uint32(1 << index); definition.ResultBit != wantResult {
			t.Fatalf("%s result bit=%d want=%d", definition.ID, definition.ResultBit, wantResult)
		}
	}
	if ToolChainCount != 18 || ToolChainLegacyCount != 13 ||
		ToolChainKnownResultMask != uint32(0x3ffff) ||
		ToolChainKnownResultMask&ToolChainReservedResultSignBit != 0 {
		t.Fatalf("result slot bounds=%d/%#x want 18/0x3ffff",
			ToolChainCount, ToolChainKnownResultMask)
	}
	definition, _ := ToolChainDefinitionByID(ToolChainSQLServerXPCommandShellExecution)
	if ToolChainKnownStepMask != uint64(0xfffffffffff) ||
		ToolChainArtifactMutationBarrier != uint64(1<<19) ||
		ToolChainKnownStepMask&ToolChainReservedSignBit != 0 {
		t.Fatalf("step/barrier bounds=%#x/%#x want 0xfffffffffff/0x80000",
			ToolChainKnownStepMask, ToolChainArtifactMutationBarrier)
	}
	if definition.MutationBit != uint64(1<<24) {
		t.Fatalf("SQL mutation bit=%#x want %#x", definition.MutationBit, uint64(1<<24))
	}
	kubernetesDefinition, _ := ToolChainDefinitionByID(ToolChainKubernetesPrivilegedCronJob)
	if kubernetesDefinition.MutationBit != uint64(1<<37) {
		t.Fatalf("Kubernetes CronJob mutation bit=%#x want 0x2000000000",
			kubernetesDefinition.MutationBit)
	}
	sqlUDFDefinition, _ := ToolChainDefinitionByID(ToolChainSQLCommandUDF)
	if sqlUDFDefinition.MutationBit != uint64(1<<40) {
		t.Fatalf("SQL command UDF mutation bit=%#x want 0x10000000000",
			sqlUDFDefinition.MutationBit)
	}
	persistenceDefinition, _ := ToolChainDefinitionByID(ToolChainStagedReverseShellPersistence)
	if persistenceDefinition.MutationBit != uint64(1<<43) {
		t.Fatalf("staged persistence mutation bit=%#x want 0x80000000000",
			persistenceDefinition.MutationBit)
	}
	kubernetes, _ := ToolChainDefinitionByID(ToolChainPrivilegedKubernetesHostRootExec)
	if kubernetes.MutationBit != uint64(1<<28) {
		t.Fatalf("Kubernetes mutation bit=%#x want %#x",
			kubernetes.MutationBit, uint64(1<<28))
	}
}

func TestMatchStagedReverseShellPersistenceRequiresExactPathAndNoRewrite(t *testing.T) {
	definition, ok := ToolChainDefinitionByID(ToolChainStagedReverseShellPersistence)
	if !ok || definition.DetectionOnly || !definition.RequiresExactJoin ||
		!definition.RequiresTerminalSuccess || definition.EventWindow != 9 ||
		definition.MutationBit == 0 || definition.Severity != "CRITICAL" {
		t.Fatalf("staged reverse-shell persistence definition=%+v", definition)
	}
	index, _ := ToolChainIndexByID(definition.ID)
	const (
		same  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	projection := func(step uint64, digest string) ToolChainProjection {
		result := ToolChainProjection{
			ParseStatus:         actionfacts.StatusComplete,
			DetectionStepMask:   step,
			EnforcementStepMask: step,
		}
		result.EnforcementJoinDigests[index] = digest
		return result
	}
	now := time.Date(2026, 9, 8, 13, 0, 0, 0, time.UTC)
	first := ToolChainWindowEvent{
		SemanticEventID: "write", Sequence: 1, ReceivedAt: now,
		Projection: projection(definition.Step1Bit, same),
	}
	final := ToolChainWindowEvent{
		SemanticEventID: "persist", Sequence: 9, ReceivedAt: now.Add(8 * time.Second),
		Projection: projection(definition.Step2Bit, same),
	}
	matches, err := MatchToolChains([]ToolChainWindowEvent{first}, final)
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask&definition.ResultBit == 0 ||
		matches.EnforcementSafeMask&definition.ResultBit == 0 {
		t.Fatalf("complete proof masks=%#x/%#x", matches.DetectedMask, matches.EnforcementSafeMask)
	}

	for _, test := range []struct {
		name  string
		prior []ToolChainWindowEvent
		final ToolChainWindowEvent
	}{
		{name: "path mismatch", prior: []ToolChainWindowEvent{first}, final: ToolChainWindowEvent{
			SemanticEventID: "mismatch", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.Step2Bit, other),
		}},
		{name: "same path rewritten", prior: []ToolChainWindowEvent{first, {
			SemanticEventID: "rewrite", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.MutationBit, same),
		}}, final: ToolChainWindowEvent{
			SemanticEventID: "after-rewrite", Sequence: 3, ReceivedAt: now.Add(2 * time.Second),
			Projection: projection(definition.Step2Bit, same),
		}},
		{name: "gap nine", prior: []ToolChainWindowEvent{first}, final: ToolChainWindowEvent{
			SemanticEventID: "far", Sequence: 10, ReceivedAt: now.Add(9 * time.Second),
			Projection: projection(definition.Step2Bit, same),
		}},
		{name: "install only", final: ToolChainWindowEvent{
			SemanticEventID: "alone", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.Step2Bit, same),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, matchErr := MatchToolChains(test.prior, test.final)
			if matchErr != nil {
				t.Fatal(matchErr)
			}
			if got.DetectedMask&definition.ResultBit != 0 ||
				got.EnforcementSafeMask&definition.ResultBit != 0 {
				t.Fatalf("hard negative matched: %+v", got)
			}
		})
	}
}

func TestMatchPrivilegedKubernetesRequiresBothJoinsBoundsAndNoMutation(t *testing.T) {
	definition, ok := ToolChainDefinitionByID(ToolChainPrivilegedKubernetesHostRootExec)
	if !ok || !definition.DetectionOnly || !definition.RequiresExactJoin ||
		!definition.RequiresTerminalSuccess || !definition.OutputJoinFromFirst ||
		definition.EventWindow != 9 || definition.MutationBit == 0 {
		t.Fatalf("Kubernetes definition=%+v", definition)
	}
	index, _ := ToolChainIndexByID(definition.ID)
	const artifact = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const pod = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const other = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	projection := func(step uint64, input, output string) ToolChainProjection {
		result := ToolChainProjection{
			ParseStatus:         actionfacts.StatusComplete,
			DetectionStepMask:   step,
			EnforcementStepMask: step,
		}
		result.EnforcementJoinDigests[index] = input
		result.EnforcementOutputJoinDigests[index] = output
		return result
	}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	prior := []ToolChainWindowEvent{
		{SemanticEventID: "write", Sequence: 1, ReceivedAt: now,
			Projection: projection(definition.Step1Bit, artifact, pod)},
		{SemanticEventID: "apply", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.Step2Bit, artifact, "")},
	}
	final := ToolChainWindowEvent{SemanticEventID: "exec", Sequence: 9,
		ReceivedAt: now.Add(8 * time.Second),
		Projection: projection(definition.Step3Bit, "", pod)}
	matches, err := MatchToolChains(prior, final)
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask&definition.ResultBit == 0 ||
		matches.EnforcementSafeMask&definition.ResultBit != 0 {
		t.Fatalf("detection/enforcement masks=%#x/%#x", matches.DetectedMask, matches.EnforcementSafeMask)
	}

	for _, test := range []struct {
		name   string
		mutate func([]ToolChainWindowEvent, *ToolChainWindowEvent)
	}{
		{name: "apply mismatch", mutate: func(events []ToolChainWindowEvent, _ *ToolChainWindowEvent) {
			events[1].Projection.EnforcementJoinDigests[index] = other
		}},
		{name: "pod mismatch", mutate: func(_ []ToolChainWindowEvent, event *ToolChainWindowEvent) {
			event.Projection.EnforcementOutputJoinDigests[index] = other
		}},
		{name: "gap nine", mutate: func(_ []ToolChainWindowEvent, event *ToolChainWindowEvent) {
			event.Sequence = 10
		}},
		{name: "same artifact mutation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := append([]ToolChainWindowEvent(nil), prior...)
			event := final
			if test.name == "same artifact mutation" {
				events = append(events, ToolChainWindowEvent{
					SemanticEventID: "mutation", Sequence: 3, ReceivedAt: now.Add(2 * time.Second),
					Projection: projection(definition.MutationBit, artifact, ""),
				})
			} else {
				test.mutate(events, &event)
			}
			got, matchErr := MatchToolChains(events, event)
			if matchErr != nil {
				t.Fatal(matchErr)
			}
			if got.DetectedMask&definition.ResultBit != 0 {
				t.Fatalf("hard negative matched: %+v", got)
			}
		})
	}
	otherMutation := append([]ToolChainWindowEvent(nil), prior...)
	otherMutation = append(otherMutation, ToolChainWindowEvent{
		SemanticEventID: "other-mutation", Sequence: 3, ReceivedAt: now.Add(2 * time.Second),
		Projection: projection(definition.MutationBit|ToolChainArtifactMutationBarrier, other, ""),
	})
	got, err := MatchToolChains(otherMutation, final)
	if err != nil || got.DetectedMask&definition.ResultBit == 0 {
		t.Fatalf("unrelated exact mutation suppressed proof: %+v err=%v", got, err)
	}
}

func TestMatchToolChainsSQLServerRequiresExactConnectionSuccessBoundsAndNoDisable(t *testing.T) {
	definition, ok := ToolChainDefinitionByID(ToolChainSQLServerXPCommandShellExecution)
	if !ok || !definition.DetectionOnly || !definition.RequiresExactJoin ||
		!definition.RequiresTerminalSuccess || definition.EventWindow != 9 ||
		definition.MutationBit == 0 {
		t.Fatalf("SQL Server chain definition=%+v", definition)
	}
	index, _ := ToolChainIndexByID(definition.ID)
	const same = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	projection := func(mask uint64, digest string) ToolChainProjection {
		result := ToolChainProjection{ParseStatus: actionfacts.StatusComplete, DetectionStepMask: mask}
		result.EnforcementJoinDigests[index] = digest
		return result
	}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	first := ToolChainWindowEvent{
		SemanticEventID: "enable", Sequence: 1, ReceivedAt: now,
		Projection: projection(definition.Step1Bit, same),
	}
	final := ToolChainWindowEvent{
		SemanticEventID: "invoke", Sequence: 9, ReceivedAt: now.Add(8 * time.Second),
		Projection: projection(definition.Step2Bit, same),
	}
	matches, err := MatchToolChains([]ToolChainWindowEvent{first}, final)
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask&definition.ResultBit == 0 ||
		matches.EnforcementSafeMask&definition.ResultBit != 0 {
		t.Fatalf("distance-eight match=%+v, want detection only", matches)
	}
	tests := []struct {
		name  string
		prior []ToolChainWindowEvent
		final ToolChainWindowEvent
	}{
		{name: "connection mismatch", prior: []ToolChainWindowEvent{first}, final: ToolChainWindowEvent{
			SemanticEventID: "other", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.Step2Bit, other),
		}},
		{name: "distance nine", prior: []ToolChainWindowEvent{first}, final: ToolChainWindowEvent{
			SemanticEventID: "far", Sequence: 10, ReceivedAt: now.Add(9 * time.Second),
			Projection: projection(definition.Step2Bit, same),
		}},
		{name: "intervening disable", prior: []ToolChainWindowEvent{first, ToolChainWindowEvent{
			SemanticEventID: "disable", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.MutationBit, same),
		}}, final: ToolChainWindowEvent{
			SemanticEventID: "after-disable", Sequence: 3, ReceivedAt: now.Add(2 * time.Second),
			Projection: projection(definition.Step2Bit, same),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, matchErr := MatchToolChains(test.prior, test.final)
			if matchErr != nil {
				t.Fatal(matchErr)
			}
			if got.DetectedMask&definition.ResultBit != 0 {
				t.Fatalf("hard negative matched: %+v", got)
			}
		})
	}
	for _, unrelated := range []ToolChainWindowEvent{
		{
			SemanticEventID: "disable-other", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.MutationBit, other),
		},
		{
			SemanticEventID: "file-mutation", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: ToolChainProjection{
				ParseStatus:       actionfacts.StatusComplete,
				DetectionStepMask: ToolChainArtifactMutationBarrier,
			},
		},
	} {
		got, matchErr := MatchToolChains([]ToolChainWindowEvent{first, unrelated}, ToolChainWindowEvent{
			SemanticEventID: "invoke-after-unrelated", Sequence: 3,
			ReceivedAt: now.Add(2 * time.Second), Projection: projection(definition.Step2Bit, same),
		})
		if matchErr != nil {
			t.Fatal(matchErr)
		}
		if got.DetectedMask&definition.ResultBit == 0 {
			t.Fatalf("unrelated mutation suppressed SQL proof: %+v", unrelated)
		}
	}
}

func TestMatchWirelessCaptureDeauthRequiresExactBSSIDAndBound(t *testing.T) {
	definition, ok := ToolChainDefinitionByID(ToolChainWirelessCaptureThenDeauthSameBSSID)
	if !ok || !definition.DetectionOnly || !definition.RequiresExactJoin ||
		!definition.RequiresTerminalSuccess || definition.EventWindow != 9 ||
		definition.Severity != "HIGH" {
		t.Fatalf("wireless chain definition=%+v", definition)
	}
	index, _ := ToolChainIndexByID(definition.ID)
	const same = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	projection := func(mask uint64, digest string) ToolChainProjection {
		result := ToolChainProjection{ParseStatus: actionfacts.StatusPartial, DetectionStepMask: mask}
		result.EnforcementJoinDigests[index] = digest
		return result
	}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	first := ToolChainWindowEvent{
		SemanticEventID: "capture", Sequence: 1, ReceivedAt: now,
		Projection: projection(definition.Step1Bit, same),
	}
	final := ToolChainWindowEvent{
		SemanticEventID: "deauth", Sequence: 9, ReceivedAt: now.Add(8 * time.Second),
		Projection: projection(definition.Step2Bit, same),
	}
	matches, err := MatchToolChains([]ToolChainWindowEvent{first}, final)
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask&definition.ResultBit == 0 ||
		matches.EnforcementSafeMask&definition.ResultBit != 0 {
		t.Fatalf("wireless detection/enforcement=%#x/%#x",
			matches.DetectedMask, matches.EnforcementSafeMask)
	}
	for _, test := range []struct {
		name  string
		prior []ToolChainWindowEvent
		final ToolChainWindowEvent
	}{
		{name: "identity mismatch", prior: []ToolChainWindowEvent{first}, final: ToolChainWindowEvent{
			SemanticEventID: "other", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.Step2Bit, other),
		}},
		{name: "missing predecessor identity", prior: []ToolChainWindowEvent{{
			SemanticEventID: "missing", Sequence: 1, ReceivedAt: now,
			Projection: projection(definition.Step1Bit, ""),
		}}, final: ToolChainWindowEvent{
			SemanticEventID: "sink", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.Step2Bit, same),
		}},
		{name: "gap nine", prior: []ToolChainWindowEvent{first}, final: ToolChainWindowEvent{
			SemanticEventID: "far", Sequence: 10, ReceivedAt: now.Add(9 * time.Second),
			Projection: projection(definition.Step2Bit, same),
		}},
		{name: "deauth alone", final: ToolChainWindowEvent{
			SemanticEventID: "alone", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.Step2Bit, same),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, matchErr := MatchToolChains(test.prior, test.final)
			if matchErr != nil {
				t.Fatal(matchErr)
			}
			if got.DetectedMask&definition.ResultBit != 0 {
				t.Fatalf("hard negative matched: %+v", got)
			}
		})
	}
}

func TestMatchSecretsdumpPsExecRequiresExactIdentitySuccessBound(t *testing.T) {
	definition, ok := ToolChainDefinitionByID(ToolChainSecretsdumpThenPsExecSameIdentity)
	if !ok || !definition.DetectionOnly || !definition.RequiresExactJoin ||
		!definition.RequiresTerminalSuccess || definition.EventWindow != 9 ||
		definition.Severity != "HIGH" || definition.Step1Bit != 1<<31 ||
		definition.Step2Bit != 1<<32 {
		t.Fatalf("credential remote-execution definition=%+v", definition)
	}
	index, _ := ToolChainIndexByID(definition.ID)
	const same = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	projection := func(mask uint64, digest string) ToolChainProjection {
		result := ToolChainProjection{ParseStatus: actionfacts.StatusPartial, DetectionStepMask: mask}
		result.EnforcementJoinDigests[index] = digest
		return result
	}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	first := ToolChainWindowEvent{
		SemanticEventID: "secretsdump", Sequence: 1, ReceivedAt: now,
		Projection: projection(definition.Step1Bit, same),
	}
	final := ToolChainWindowEvent{
		SemanticEventID: "psexec", Sequence: 9, ReceivedAt: now.Add(8 * time.Second),
		Projection: projection(definition.Step2Bit, same),
	}
	matches, err := MatchToolChains([]ToolChainWindowEvent{first}, final)
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask&definition.ResultBit == 0 ||
		matches.EnforcementSafeMask&definition.ResultBit != 0 {
		t.Fatalf("detection/enforcement=%#x/%#x", matches.DetectedMask, matches.EnforcementSafeMask)
	}
	for _, test := range []struct {
		name  string
		prior []ToolChainWindowEvent
		final ToolChainWindowEvent
	}{
		{name: "identity mismatch", prior: []ToolChainWindowEvent{first}, final: ToolChainWindowEvent{
			SemanticEventID: "other", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.Step2Bit, other),
		}},
		{name: "missing predecessor identity", prior: []ToolChainWindowEvent{{
			SemanticEventID: "missing", Sequence: 1, ReceivedAt: now,
			Projection: projection(definition.Step1Bit, ""),
		}}, final: ToolChainWindowEvent{
			SemanticEventID: "sink", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.Step2Bit, same),
		}},
		{name: "gap nine", prior: []ToolChainWindowEvent{first}, final: ToolChainWindowEvent{
			SemanticEventID: "far", Sequence: 10, ReceivedAt: now.Add(9 * time.Second),
			Projection: projection(definition.Step2Bit, same),
		}},
		{name: "psexec alone", final: ToolChainWindowEvent{
			SemanticEventID: "alone", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.Step2Bit, same),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, matchErr := MatchToolChains(test.prior, test.final)
			if matchErr != nil {
				t.Fatal(matchErr)
			}
			if got.DetectedMask&definition.ResultBit != 0 {
				t.Fatalf("hard negative matched: %+v", got)
			}
		})
	}
}

func TestLegacyToolChainProjectionFingerprintSurvivesWidening(t *testing.T) {
	projection := ToolChainProjection{
		ParseStatus: actionfacts.StatusComplete, DetectionStepMask: 1,
		EnforcementStepMask: 1,
	}
	got, err := ToolChainProjectionFingerprint(projection)
	if err != nil {
		t.Fatal(err)
	}
	const preWidening = "48afcc1cce9f975e18c409f8c29cde80e2950fcb313249790c1cdcca05ea5ccd"
	if got != preWidening {
		t.Fatalf("legacy projection fingerprint=%s want %s", got, preWidening)
	}
	wide := projection
	definition, ok := ToolChainDefinitionByID(ToolChainSQLCommandUDF)
	if !ok {
		t.Fatal("missing SQL command UDF chain definition")
	}
	wide.DetectionStepMask = definition.Step1Bit
	wide.EnforcementStepMask = 0
	index, _ := ToolChainIndexByID(definition.ID)
	wide.EnforcementJoinDigests[index] =
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	wideFingerprint, err := ToolChainProjectionFingerprint(wide)
	if err != nil || wideFingerprint == got {
		t.Fatalf("wide fingerprint=%q legacy=%q err=%v", wideFingerprint, got, err)
	}
}

func TestToolChainResultMaskRuntimeCapacityIncludesFutureBitEighteen(t *testing.T) {
	const futureNineteenthChain = uint32(1 << 18)
	matches := ToolChainMatches{
		DetectedMask:        futureNineteenthChain,
		EnforcementSafeMask: futureNineteenthChain,
	}
	if matches.DetectedMask != futureNineteenthChain ||
		matches.EnforcementSafeMask != futureNineteenthChain ||
		futureNineteenthChain&ToolChainReservedResultSignBit != 0 {
		t.Fatalf("uint32 result-mask capacity lost bit 18: %+v", matches)
	}
	if _, err := ToolChainIDs(futureNineteenthChain); err == nil {
		t.Fatal("future result bit was accepted before its catalog definition exists")
	}
}

func TestMatchToolChainsFirewallExpansionRequiresExactJoinAndStaysPolicyGated(t *testing.T) {
	definition, ok := ToolChainDefinitionByID(ToolChainFirewallExpansionThenDestination)
	if !ok || !definition.DetectionOnly || !definition.RequiresExactJoin ||
		definition.EventWindow != 8 {
		t.Fatalf("firewall chain definition=%+v", definition)
	}
	index, _ := ToolChainIndexByID(definition.ID)
	const destination = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	projection := func(step uint64) ToolChainProjection {
		result := ToolChainProjection{
			ParseStatus:         actionfacts.StatusComplete,
			DetectionStepMask:   step,
			EnforcementStepMask: step,
		}
		result.EnforcementJoinDigests[index] = destination
		return result
	}
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	matches, err := MatchToolChains([]ToolChainWindowEvent{{
		SemanticEventID: "edit", Sequence: 1, ReceivedAt: now,
		Projection: projection(definition.Step1Bit),
	}}, ToolChainWindowEvent{
		SemanticEventID: "connect", Sequence: 8, ReceivedAt: now.Add(7 * time.Second),
		Projection: projection(definition.Step2Bit),
	})
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask&definition.ResultBit == 0 ||
		matches.EnforcementSafeMask&definition.ResultBit != 0 {
		t.Fatalf("matches=%+v, want detection-only exact proof", matches)
	}
}

func TestMatchToolChainsDownloadThenExecuteRequiresExactJoinAndBounds(t *testing.T) {
	definition, ok := ToolChainDefinitionByID(ToolChainDownloadThenExecuteSameArtifact)
	if !ok || !definition.DetectionOnly || !definition.RequiresExactJoin {
		t.Fatalf("detection-only direct execution chain is missing: %+v", definition)
	}
	index, _ := ToolChainIndexByID(definition.ID)
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	const artifact = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	projection := func(step uint64, digest string) ToolChainProjection {
		result := ToolChainProjection{
			ParseStatus:       actionfacts.StatusComplete,
			DetectionStepMask: step,
		}
		result.EnforcementJoinDigests[index] = digest
		return result
	}
	first := ToolChainWindowEvent{
		SemanticEventID: "download", Sequence: 1, ReceivedAt: now,
		Projection: projection(definition.Step1Bit, artifact),
	}
	final := ToolChainWindowEvent{
		SemanticEventID: "execute", Sequence: 8,
		ReceivedAt: now.Add(30 * time.Minute),
		Projection: projection(definition.Step2Bit, artifact),
	}
	matches, err := MatchToolChains([]ToolChainWindowEvent{first}, final)
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask&definition.ResultBit == 0 ||
		matches.EnforcementSafeMask&definition.ResultBit != 0 {
		t.Fatalf("masks=%08b/%08b, want detection only", matches.DetectedMask, matches.EnforcementSafeMask)
	}

	for _, test := range []struct {
		name   string
		mutate func(*ToolChainWindowEvent, *ToolChainWindowEvent)
	}{
		{name: "unequal path", mutate: func(_ *ToolChainWindowEvent, event *ToolChainWindowEvent) {
			event.Projection.EnforcementJoinDigests[index] = other
		}},
		{name: "missing download identity", mutate: func(event *ToolChainWindowEvent, _ *ToolChainWindowEvent) {
			event.Projection.EnforcementJoinDigests[index] = ""
		}},
		{name: "missing execution identity", mutate: func(_ *ToolChainWindowEvent, event *ToolChainWindowEvent) {
			event.Projection.EnforcementJoinDigests[index] = ""
		}},
		{name: "outside event window", mutate: func(_ *ToolChainWindowEvent, event *ToolChainWindowEvent) {
			event.Sequence = 9
		}},
		{name: "outside time window", mutate: func(_ *ToolChainWindowEvent, event *ToolChainWindowEvent) {
			event.ReceivedAt = now.Add(30*time.Minute + time.Nanosecond)
		}},
		{name: "reversed order", mutate: func(event *ToolChainWindowEvent, final *ToolChainWindowEvent) {
			event.Sequence = final.Sequence + 1
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			priorEvent, finalEvent := first, final
			test.mutate(&priorEvent, &finalEvent)
			got, matchErr := MatchToolChains([]ToolChainWindowEvent{priorEvent}, finalEvent)
			if matchErr != nil {
				t.Fatal(matchErr)
			}
			if got.DetectedMask&definition.ResultBit != 0 ||
				got.EnforcementSafeMask&definition.ResultBit != 0 {
				t.Fatalf("unexpected match: %+v", got)
			}
		})
	}
}

func TestMatchToolChainsRejectsInterveningArtifactMutation(t *testing.T) {
	definition, _ := ToolChainDefinitionByID(ToolChainSensitiveEgressArtifactThenExec)
	index, _ := ToolChainIndexByID(definition.ID)
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	projection := func(step uint64) ToolChainProjection {
		result := ToolChainProjection{
			ParseStatus:       actionfacts.StatusComplete,
			DetectionStepMask: step,
		}
		if step != ToolChainArtifactMutationBarrier {
			result.EnforcementJoinDigests[index] = digest
		}
		return result
	}
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	prior := []ToolChainWindowEvent{
		{SemanticEventID: "write", Sequence: 1, ReceivedAt: now, Projection: projection(definition.Step1Bit)},
		{SemanticEventID: "mutation", Sequence: 2, ReceivedAt: now.Add(time.Second), Projection: projection(ToolChainArtifactMutationBarrier)},
	}
	final := ToolChainWindowEvent{
		SemanticEventID: "execute", Sequence: 3, ReceivedAt: now.Add(2 * time.Second),
		Projection: projection(definition.Step2Bit),
	}
	matches, err := MatchToolChains(prior, final)
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask&definition.ResultBit != 0 ||
		matches.EnforcementSafeMask&definition.ResultBit != 0 {
		t.Fatalf("intervening mutation completed exact chain: %+v", matches)
	}

	prior[1].Projection.DetectionStepMask = 0
	matches, err = MatchToolChains(prior, final)
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask&definition.ResultBit == 0 {
		t.Fatalf("non-mutating middle event suppressed exact chain: %+v", matches)
	}
}

func TestMatchToolChainsDownloadDecodeExecuteRequiresBothExactJoins(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	definition, ok := ToolChainDefinitionByID(ToolChainDownloadDecodeExecuteSameArtifact)
	if !ok || definition.Step3Bit == 0 {
		t.Fatal("three-step remote artifact definition is missing")
	}
	index, _ := ToolChainIndexByID(definition.ID)
	archive := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	derived := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	projection := func(step uint64, input, output string) ToolChainProjection {
		result := ToolChainProjection{
			ParseStatus:         actionfacts.StatusComplete,
			DetectionStepMask:   step,
			EnforcementStepMask: step,
		}
		result.EnforcementJoinDigests[index] = input
		result.EnforcementOutputJoinDigests[index] = output
		return result
	}
	prior := []ToolChainWindowEvent{
		{SemanticEventID: "download", Sequence: 1, ReceivedAt: now,
			Projection: projection(definition.Step1Bit, archive, "")},
		{SemanticEventID: "decode", Sequence: 2, ReceivedAt: now.Add(time.Second),
			Projection: projection(definition.Step2Bit, archive, derived)},
	}
	final := ToolChainWindowEvent{SemanticEventID: "execute", Sequence: 3,
		ReceivedAt: now.Add(2 * time.Second),
		Projection: projection(definition.Step3Bit, "", derived)}
	matches, err := MatchToolChains(prior, final)
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask != definition.ResultBit ||
		matches.EnforcementSafeMask != definition.ResultBit {
		t.Fatalf("masks=%08b/%08b want %08b", matches.DetectedMask,
			matches.EnforcementSafeMask, definition.ResultBit)
	}

	for _, test := range []struct {
		name          string
		mutate        func([]ToolChainWindowEvent, *ToolChainWindowEvent)
		wantDetection bool
	}{
		{name: "archive mismatch", mutate: func(events []ToolChainWindowEvent, _ *ToolChainWindowEvent) {
			events[1].Projection.EnforcementJoinDigests[index] = derived
		}},
		{name: "derived mismatch", mutate: func(_ []ToolChainWindowEvent, event *ToolChainWindowEvent) {
			event.Projection.EnforcementOutputJoinDigests[index] = archive
		}},
		{name: "unknown derived identity remains detection only", wantDetection: true,
			mutate: func(events []ToolChainWindowEvent, event *ToolChainWindowEvent) {
				events[1].Projection.EnforcementOutputJoinDigests[index] = ""
				event.Projection.EnforcementOutputJoinDigests[index] = ""
			}},
		{name: "outside eight event window", mutate: func(_ []ToolChainWindowEvent, event *ToolChainWindowEvent) {
			event.Sequence = 9
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := append([]ToolChainWindowEvent(nil), prior...)
			event := final
			test.mutate(events, &event)
			got, matchErr := MatchToolChains(events, event)
			if matchErr != nil {
				t.Fatal(matchErr)
			}
			if got.EnforcementSafeMask&definition.ResultBit != 0 {
				t.Fatalf("unexpected enforcement mask %08b", got.EnforcementSafeMask)
			}
			if detected := got.DetectedMask&definition.ResultBit != 0; detected != test.wantDetection {
				t.Fatalf("detected=%t want %t", detected, test.wantDetection)
			}
		})
	}
	withoutSuccessfulDecode, err := MatchToolChains(prior[:1], final)
	if err != nil {
		t.Fatal(err)
	}
	if withoutSuccessfulDecode.DetectedMask&definition.ResultBit != 0 ||
		withoutSuccessfulDecode.EnforcementSafeMask&definition.ResultBit != 0 {
		t.Fatalf("missing/failed decode armed chain: %+v", withoutSuccessfulDecode)
	}
}

func TestMatchToolChainsUsesIndependentEarliestPredecessors(t *testing.T) {
	definition, _ := ToolChainDefinitionByID(ToolChainSecretReadThenEgress)
	index, _ := ToolChainIndexByID(definition.ID)
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	enforcementProjection := ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: definition.Step1Bit, EnforcementStepMask: definition.Step1Bit,
	}
	enforcementProjection.EnforcementJoinDigests[index] = digest
	prior := []ToolChainWindowEvent{
		{
			SemanticEventID: "enforcement", Sequence: 4, ReceivedAt: now.Add(4 * time.Second),
			Projection: enforcementProjection,
		},
		{
			SemanticEventID: "detection", Sequence: 2, ReceivedAt: now.Add(2 * time.Second),
			Projection: ToolChainProjection{
				ParseStatus: actionfacts.StatusComplete, DetectionStepMask: definition.Step1Bit,
			},
		},
	}
	finalProjection := ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: definition.Step2Bit, EnforcementStepMask: definition.Step2Bit,
	}
	finalProjection.EnforcementJoinDigests[index] = digest
	matches, err := MatchToolChains(prior, ToolChainWindowEvent{
		SemanticEventID: "final", Sequence: 5, ReceivedAt: now.Add(5 * time.Second),
		Projection: finalProjection,
	})
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectionPredecessors[index] != "detection" ||
		matches.EnforcementPredecessors[index] != "enforcement" {
		t.Fatalf("predecessors=%q/%q", matches.DetectionPredecessors[index],
			matches.EnforcementPredecessors[index])
	}
}

func TestMatchToolChainsRejectsExactIdentityMismatch(t *testing.T) {
	definition, _ := ToolChainDefinitionByID(ToolChainSecretReadThenEgress)
	index, _ := ToolChainIndexByID(definition.ID)
	first := ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: definition.Step1Bit, EnforcementStepMask: definition.Step1Bit,
	}
	final := ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: definition.Step2Bit, EnforcementStepMask: definition.Step2Bit,
	}
	first.EnforcementJoinDigests[index] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	final.EnforcementJoinDigests[index] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	matches, err := MatchToolChains([]ToolChainWindowEvent{{
		SemanticEventID: "read", Sequence: 1, ReceivedAt: now, Projection: first,
	}}, ToolChainWindowEvent{
		SemanticEventID: "send", Sequence: 2, ReceivedAt: now.Add(time.Second), Projection: final,
	})
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask != 0 || matches.EnforcementSafeMask != 0 {
		t.Fatalf("masks=%06b/%06b, want exact mismatch rejected", matches.DetectedMask, matches.EnforcementSafeMask)
	}
}

func TestMatchToolChainsKeepsUnknownIdentityDetectionOnly(t *testing.T) {
	definition, _ := ToolChainDefinitionByID(ToolChainSecretReadThenEgress)
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	matches, err := MatchToolChains([]ToolChainWindowEvent{{
		SemanticEventID: "read", Sequence: 1, ReceivedAt: now,
		Projection: ToolChainProjection{
			ParseStatus: actionfacts.StatusComplete, DetectionStepMask: definition.Step1Bit,
		},
	}}, ToolChainWindowEvent{
		SemanticEventID: "send", Sequence: 2, ReceivedAt: now.Add(time.Second),
		Projection: ToolChainProjection{
			ParseStatus: actionfacts.StatusComplete, DetectionStepMask: definition.Step2Bit,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if matches.DetectedMask != definition.ResultBit || matches.EnforcementSafeMask != 0 {
		t.Fatalf("masks=%06b/%06b, want detection only", matches.DetectedMask, matches.EnforcementSafeMask)
	}
}

func TestMatchToolChainsEnforcesOrderAndBothWindows(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	for _, definition := range ToolChainDefinitions() {
		t.Run(definition.ID, func(t *testing.T) {
			final := ToolChainWindowEvent{
				SemanticEventID: "final",
				Sequence:        definition.EventWindow + 2,
				ReceivedAt:      now,
				Projection: ToolChainProjection{
					ParseStatus:       actionfacts.StatusComplete,
					DetectionStepMask: definition.Step2Bit,
				},
			}
			for name, prior := range map[string]ToolChainWindowEvent{
				"reversed": {
					SemanticEventID: "later",
					Sequence:        final.Sequence + 1,
					ReceivedAt:      now,
				},
				"event-window": {
					SemanticEventID: "old-sequence",
					Sequence:        final.Sequence - definition.EventWindow,
					ReceivedAt:      now,
				},
				"time-window": {
					SemanticEventID: "old-time",
					Sequence:        final.Sequence - 1,
					ReceivedAt:      now.Add(-definition.TimeWindow - time.Nanosecond),
				},
			} {
				t.Run(name, func(t *testing.T) {
					prior.Projection = ToolChainProjection{
						ParseStatus:       actionfacts.StatusComplete,
						DetectionStepMask: definition.Step1Bit,
					}
					matches, err := MatchToolChains([]ToolChainWindowEvent{prior}, final)
					if err != nil {
						t.Fatal(err)
					}
					if matches.DetectedMask != 0 {
						t.Fatalf("out-of-window match=%06b", matches.DetectedMask)
					}
				})
			}
		})
	}
}

func TestToolChainProjectionAndFingerprintsAreClosed(t *testing.T) {
	if err := ValidateToolChainProjection(ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: 1, EnforcementStepMask: 2,
	}); err == nil {
		t.Fatal("non-subset enforcement mask accepted")
	}
	if _, err := ToolChainRulesetFingerprint("not-a-digest"); err == nil {
		t.Fatal("invalid relevant-owner digest accepted")
	}
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	first, err := ToolChainRulesetFingerprint(digest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ToolChainFingerprint(ToolChainSecretReadThenEgress, first)
	if err != nil || len(second) != 64 {
		t.Fatalf("chain fingerprint=%q err=%v", second, err)
	}
}
