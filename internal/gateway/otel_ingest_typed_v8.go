// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// otlpTypedAttributeState is the closed lexical state of one exact OTLP
// attribute key. A duplicate is never reduced to first- or last-value wins,
// even when both wire values are byte-equivalent. Generated bindings decide
// whether the affected target is ambiguous or invalid without seeing an
// arbitrary map representation.
type otlpTypedAttributeState uint8

const (
	otlpTypedAttributeAbsent otlpTypedAttributeState = iota
	otlpTypedAttributeUnique
	otlpTypedAttributeDuplicate
	otlpTypedAttributeInvalid
)

// otlpTypedAnyValueKind identifies the protobuf oneof arm without coercion.
// Conversion and normalization are generated target rules layered above this
// transport boundary.
type otlpTypedAnyValueKind uint8

const (
	otlpTypedAnyValueInvalid otlpTypedAnyValueKind = iota
	otlpTypedAnyValueString
	otlpTypedAnyValueBool
	otlpTypedAnyValueInt64
	otlpTypedAnyValueDouble
	otlpTypedAnyValueArray
	otlpTypedAnyValueKeyValueList
	otlpTypedAnyValueBytes
)

// otlpTypedAttributeIndex references the request-owned protobuf values and is
// valid only while that decoded request is being processed. It never clones,
// flattens, stringifies, or retains sender content beyond the request scope.
type otlpTypedAttributeIndex struct {
	values     map[string]*commonpb.AnyValue
	duplicates map[string]struct{}
	invalid    int
}

func newOTLPTypedAttributeIndex(attributes []*commonpb.KeyValue) otlpTypedAttributeIndex {
	index := otlpTypedAttributeIndex{
		values:     make(map[string]*commonpb.AnyValue, len(attributes)),
		duplicates: make(map[string]struct{}),
	}
	for _, attribute := range attributes {
		if attribute == nil || attribute.GetKey() == "" {
			index.invalid++
			continue
		}
		key := attribute.GetKey()
		valueInvalid := attribute.Value == nil ||
			otlpTypedValueKind(attribute.Value) == otlpTypedAnyValueInvalid
		if valueInvalid {
			index.invalid++
		}
		if _, duplicate := index.duplicates[key]; duplicate {
			continue
		}
		if _, present := index.values[key]; present {
			delete(index.values, key)
			index.duplicates[key] = struct{}{}
			continue
		}
		if valueInvalid {
			index.values[key] = nil
		} else {
			index.values[key] = attribute.Value
		}
	}
	return index
}

func (index otlpTypedAttributeIndex) lookup(key string) (*commonpb.AnyValue, otlpTypedAttributeState) {
	if key == "" {
		return nil, otlpTypedAttributeInvalid
	}
	if _, duplicate := index.duplicates[key]; duplicate {
		return nil, otlpTypedAttributeDuplicate
	}
	value, present := index.values[key]
	if !present {
		return nil, otlpTypedAttributeAbsent
	}
	if value == nil || otlpTypedValueKind(value) == otlpTypedAnyValueInvalid {
		return nil, otlpTypedAttributeInvalid
	}
	return value, otlpTypedAttributeUnique
}

func (index otlpTypedAttributeIndex) stringValue(key string) (string, otlpTypedAttributeState) {
	value, state := index.lookup(key)
	if state != otlpTypedAttributeUnique {
		return "", state
	}
	typed, ok := value.Value.(*commonpb.AnyValue_StringValue)
	if !ok {
		return "", otlpTypedAttributeInvalid
	}
	return typed.StringValue, otlpTypedAttributeUnique
}

func (index otlpTypedAttributeIndex) int64Value(key string) (int64, otlpTypedAttributeState) {
	value, state := index.lookup(key)
	if state != otlpTypedAttributeUnique {
		return 0, state
	}
	typed, ok := value.Value.(*commonpb.AnyValue_IntValue)
	if !ok {
		return 0, otlpTypedAttributeInvalid
	}
	return typed.IntValue, otlpTypedAttributeUnique
}

func (index otlpTypedAttributeIndex) doubleValue(key string) (float64, otlpTypedAttributeState) {
	value, state := index.lookup(key)
	if state != otlpTypedAttributeUnique {
		return 0, state
	}
	typed, ok := value.Value.(*commonpb.AnyValue_DoubleValue)
	if !ok {
		return 0, otlpTypedAttributeInvalid
	}
	return typed.DoubleValue, otlpTypedAttributeUnique
}

func (index otlpTypedAttributeIndex) boolValue(key string) (bool, otlpTypedAttributeState) {
	value, state := index.lookup(key)
	if state != otlpTypedAttributeUnique {
		return false, state
	}
	typed, ok := value.Value.(*commonpb.AnyValue_BoolValue)
	if !ok {
		return false, otlpTypedAttributeInvalid
	}
	return typed.BoolValue, otlpTypedAttributeUnique
}

func (index otlpTypedAttributeIndex) keys() []string {
	keys := make([]string, 0, len(index.values)+len(index.duplicates))
	for key := range index.values {
		keys = append(keys, key)
	}
	for key := range index.duplicates {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func (index otlpTypedAttributeIndex) invalidCount() int { return index.invalid }

func otlpTypedValueKind(value *commonpb.AnyValue) otlpTypedAnyValueKind {
	if value == nil {
		return otlpTypedAnyValueInvalid
	}
	switch value.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return otlpTypedAnyValueString
	case *commonpb.AnyValue_BoolValue:
		return otlpTypedAnyValueBool
	case *commonpb.AnyValue_IntValue:
		return otlpTypedAnyValueInt64
	case *commonpb.AnyValue_DoubleValue:
		return otlpTypedAnyValueDouble
	case *commonpb.AnyValue_ArrayValue:
		return otlpTypedAnyValueArray
	case *commonpb.AnyValue_KvlistValue:
		return otlpTypedAnyValueKeyValueList
	case *commonpb.AnyValue_BytesValue:
		return otlpTypedAnyValueBytes
	default:
		return otlpTypedAnyValueInvalid
	}
}
