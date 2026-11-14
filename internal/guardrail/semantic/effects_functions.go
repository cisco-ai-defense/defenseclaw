// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// Protected-set answers of protected(target) and protected(target, set).
const (
	ProtectedKnown   = "known"
	ProtectedUnknown = "unknown"
	ProtectedNo      = "no"
)

const protectedFunction = "protected"

// effectTargetType is the CEL type of f.effects[i].target.
var effectTargetType = cel.ObjectType(string((&semanticpb.EffectTarget{}).ProtoReflect().Descriptor().FullName()))

// effectFunctions declares the read-only effect helpers. They read only the
// projected target (its protected matches were graded when the effects were
// projected), so evaluation stays pure: no file system, no clock.
func effectFunctions() cel.EnvOption {
	return cel.Function(protectedFunction,
		cel.Overload("protected_effect_target",
			[]*cel.Type{effectTargetType}, cel.StringType,
			cel.UnaryBinding(func(target ref.Val) ref.Val {
				return types.String(ProtectedState(protoTarget(target), ""))
			})),
		cel.Overload("protected_effect_target_set",
			[]*cel.Type{effectTargetType, cel.StringType}, cel.StringType,
			cel.BinaryBinding(func(target, set ref.Val) ref.Val {
				name, ok := set.(types.String)
				if !ok {
					return types.String(ProtectedUnknown)
				}
				return types.String(ProtectedState(protoTarget(target), string(name)))
			})),
	)
}

func protoTarget(value ref.Val) *semanticpb.EffectTarget {
	if value == nil {
		return nil
	}
	target, _ := value.Value().(*semanticpb.EffectTarget)
	return target
}

// ProtectedState folds a target's protected matches: known when one match
// in scope is known, unknown when one may match, otherwise no. set "" means
// every set. A nil target is unknown, never no.
func ProtectedState(target *semanticpb.EffectTarget, set string) string {
	if target == nil {
		return ProtectedUnknown
	}
	state := ProtectedNo
	for _, match := range target.GetProtected() {
		if set != "" && match.GetSet() != set {
			continue
		}
		switch match.GetState() {
		case ProtectedKnown:
			return ProtectedKnown
		case ProtectedNo:
		default:
			state = ProtectedUnknown
		}
	}
	return state
}
