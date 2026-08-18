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
	"runtime"
	"strconv"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/asrruntime"
)

// localActionSemanticsContext returns a projection context only when the
// trusted host target and normalized input envelope prove it. It never reads
// or interprets command text. Callers replaying a different target platform
// must provide ASRContext explicitly.
func localActionSemanticsContext(input actionfacts.Input) *actionfacts.ASRProjectionContext {
	if runtime.GOOS != "linux" {
		return nil
	}
	context := actionfacts.ASRProjectionContext{
		Platform: actionfacts.ASRPlatformLinux,
		Profile:  actionfacts.ASRProfileUniversalLinux,
	}
	switch {
	case len(input.Argv) != 0:
		context.Provenance = actionfacts.ASRCommandProvenanceStructuredArgv
	case input.Command != "" && input.DialectHint == actionfacts.DialectPOSIX:
		context.Provenance = actionfacts.ASRCommandProvenanceActionFactsStaticPOSIX
	default:
		return nil
	}
	return &context
}

// actionSemanticsRuntime is the private in-process boundary used by the
// ActionFacts bridge. Implementations must satisfy asrruntime's pure, bounded
// evaluator contract. Keeping the interface private prevents remote input from
// selecting an evaluator or asserting authority.
type actionSemanticsRuntime interface {
	Evaluate(asrruntime.NormalizedInvocation) asrruntime.Result
	Pins() asrruntime.Pins
	CanAuthorize() bool
}

// actionSemanticsNodeEvaluation binds one ASR result to the ActionFacts command
// node that produced it. Authoritative is owned by this bridge, not by the
// evaluator: every correlation, status, pin, parity, and outer-action check
// must pass before it can become true.
type actionSemanticsNodeEvaluation struct {
	CommandID              int64
	CandidateAuthoritative bool
	Result                 asrruntime.Result
	Authoritative          bool
}

// actionSemanticsBridgeReport is ephemeral and value-bearing. It must remain
// inside the trusted process boundary and must not be serialized to audit logs
// or telemetry. Callers may derive only bounded, value-free counters from it.
type actionSemanticsBridgeReport struct {
	Projection  actionfacts.ASRCommandProjection
	Evaluations []actionSemanticsNodeEvaluation
	LoadFailed  bool
}

var (
	embeddedActionSemanticsOnce    sync.Once
	embeddedActionSemanticsRuntime actionSemanticsRuntime
	embeddedActionSemanticsErr     error
)

func loadEmbeddedActionSemanticsRuntime() (actionSemanticsRuntime, error) {
	embeddedActionSemanticsOnce.Do(func() {
		embeddedActionSemanticsRuntime, embeddedActionSemanticsErr = asrruntime.LoadEmbedded()
	})
	return embeddedActionSemanticsRuntime, embeddedActionSemanticsErr
}

// evaluateActionSemanticsNodes projects every ActionFacts command node and
// evaluates each projectable node exactly once. Projection happens even when
// the enclosing shell action is partial; candidate.Authoritative remains false
// in that case, so the result is shadow evidence only.
func evaluateActionSemanticsNodes(
	facts actionfacts.Facts,
	projectionContext actionfacts.ASRProjectionContext,
	runtime actionSemanticsRuntime,
) actionSemanticsBridgeReport {
	report := actionSemanticsBridgeReport{
		Projection: actionfacts.ProjectASRCommandNodes(facts, projectionContext),
	}
	projectable := 0
	for _, candidate := range report.Projection.Candidates {
		if candidate.Projectable {
			projectable++
		}
	}
	if projectable == 0 {
		return report
	}
	if runtime == nil {
		var err error
		runtime, err = loadEmbeddedActionSemanticsRuntime()
		if err != nil || runtime == nil {
			report.LoadFailed = true
			return report
		}
	}

	report.Evaluations = make([]actionSemanticsNodeEvaluation, 0, projectable)
	for _, candidate := range report.Projection.Candidates {
		if !candidate.Projectable {
			continue
		}
		callID := strconv.FormatInt(candidate.CommandID, 10)
		result := runtime.Evaluate(asrruntime.NormalizedInvocation{
			CallID:       callID,
			Program:      candidate.Program,
			Surface:      actionSemanticsSurface(candidate.Surface),
			Profile:      string(report.Projection.Context.Profile),
			Argv:         append([]string(nil), candidate.Argv...),
			ArgvComplete: true,
			Context: actionSemanticsInvocationContext(
				candidate.CWD,
				candidate.ActiveHome,
			),
		})
		evaluation := actionSemanticsNodeEvaluation{
			CommandID:              candidate.CommandID,
			CandidateAuthoritative: candidate.Authoritative,
			Result:                 result,
		}
		evaluation.Authoritative = candidate.Authoritative &&
			result.CallID == callID &&
			result.Status == asrruntime.StatusComplete &&
			result.Authoritative &&
			runtime.CanAuthorize() &&
			result.Pins == runtime.Pins()
		report.Evaluations = append(report.Evaluations, evaluation)
	}
	return report
}

func actionSemanticsSurface(surface actionfacts.ASRCommandSurface) asrruntime.Surface {
	switch surface {
	case actionfacts.ASRCommandSurfaceDirectArgv:
		return asrruntime.SurfaceDirectArgv
	case actionfacts.ASRCommandSurfacePOSIX:
		return asrruntime.SurfacePOSIXShell
	default:
		return asrruntime.Surface("")
	}
}

func actionSemanticsInvocationContext(cwd, activeHome string) *asrruntime.InvocationContext {
	if cwd == "" && activeHome == "" {
		return nil
	}
	return &asrruntime.InvocationContext{CWD: cwd, ActiveHome: activeHome}
}

func actionSemanticsTelemetry(report actionSemanticsBridgeReport) trustedActionTelemetry {
	telemetry := trustedActionTelemetry{}
	for _, candidate := range report.Projection.Candidates {
		if candidate.Projectable {
			telemetry.ASRProjectableCount++
		}
		if candidate.Authoritative {
			telemetry.ASRCandidateAuthoritativeCount++
		}
	}
	if report.LoadFailed {
		telemetry.ASRRuntimeErrorCount++
	}
	for _, evaluation := range report.Evaluations {
		switch evaluation.Result.Status {
		case asrruntime.StatusComplete:
			telemetry.ASRCompleteCount++
		case asrruntime.StatusPartial:
			telemetry.ASRPartialCount++
		case asrruntime.StatusInvalid:
			telemetry.ASRInvalidCount++
		case asrruntime.StatusUnsupported:
			telemetry.ASRUnsupportedCount++
		case asrruntime.StatusError:
			telemetry.ASRRuntimeErrorCount++
		default:
			telemetry.ASRRuntimeErrorCount++
		}
		if evaluation.Authoritative {
			telemetry.ASRAuthoritativeCount++
		}
	}
	return telemetry
}
