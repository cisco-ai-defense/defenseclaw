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
	"context"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/interpreter"
)

// Result is the value-free result of one exact Boolean evaluation.
type Result struct {
	Matched bool
	Cost    uint64
}

// EvalBool evaluates one immutable program against one fresh projection.
func (p *Program) EvalBool(
	ctx context.Context,
	facts *semanticpb.Facts,
) (Result, EvalCode) {
	if p == nil || p.program == nil {
		return Result{}, EvalError
	}
	if ctx == nil || facts == nil {
		return Result{}, EvalProjectionInvalid
	}
	value, details, err := p.program.ContextEval(
		ctx,
		map[string]any{"f": facts},
	)
	result := Result{}
	if details != nil && details.ActualCost() != nil {
		result.Cost = *details.ActualCost()
	}
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return result, EvalDeadline
		case errors.Is(err, context.Canceled):
			return result, EvalCancelled
		}
		var cancelled interpreter.EvalCancelledError
		if errors.As(err, &cancelled) &&
			cancelled.Cause == interpreter.CostLimitExceeded {
			return result, EvalCost
		}
		return result, EvalError
	}
	if types.IsUnknown(value) {
		return result, EvalUnknown
	}
	if types.IsError(value) {
		return result, EvalError
	}
	boolean, ok := value.(types.Bool)
	if !ok {
		return result, EvalNonBool
	}
	result.Matched = bool(boolean)
	return result, EvalOK
}
