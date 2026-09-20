// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

type otlpInboundJSONMember struct {
	name string
	raw  json.RawMessage
}

// decodeInboundJSONObject retains member order and never materializes a
// sender-controlled map. Duplicate members fail before a generated capability
// can select one of them.
func decodeInboundJSONObject(raw []byte) ([]otlpInboundJSONMember, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errOTLPInboundMappingV8
	}
	seen := make(map[string]struct{})
	result := make([]otlpInboundJSONMember, 0)
	for decoder.More() {
		nameToken, nameErr := decoder.Token()
		name, ok := nameToken.(string)
		if nameErr != nil || !ok || name == "" {
			return nil, errOTLPInboundMappingV8
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, errOTLPInboundMappingV8
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errOTLPInboundMappingV8
		}
		result = append(result, otlpInboundJSONMember{name: name, raw: append(json.RawMessage(nil), value...)})
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errOTLPInboundMappingV8
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errOTLPInboundMappingV8
	}
	return result, nil
}

func inboundJSONMember(members []otlpInboundJSONMember, name string) (json.RawMessage, bool) {
	for _, member := range members {
		if member.name == name {
			return append(json.RawMessage(nil), member.raw...), true
		}
	}
	return nil, false
}

func inboundJSONAnyValue(raw json.RawMessage, depth int) (*commonpb.AnyValue, error) {
	if depth > 8 || len(raw) == 0 || validateUniqueOTLPJSONMembers(raw) != nil {
		return nil, errOTLPInboundMappingV8
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return nil, errOTLPInboundMappingV8
	}
	finish := func(result *commonpb.AnyValue) (*commonpb.AnyValue, error) {
		if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
			return nil, errOTLPInboundMappingV8
		}
		return result, nil
	}
	switch value := token.(type) {
	case string:
		return finish(&commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}})
	case bool:
		return finish(&commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: value}})
	case json.Number:
		if integer, integerErr := strconv.ParseInt(value.String(), 10, 64); integerErr == nil {
			return finish(&commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: integer}})
		}
		number, numberErr := strconv.ParseFloat(value.String(), 64)
		if numberErr != nil || math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, errOTLPInboundMappingV8
		}
		return finish(&commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: number}})
	case json.Delim:
		switch value {
		case '[':
			items := make([]*commonpb.AnyValue, 0)
			for decoder.More() {
				var item json.RawMessage
				if err := decoder.Decode(&item); err != nil {
					return nil, errOTLPInboundMappingV8
				}
				converted, err := inboundJSONAnyValue(item, depth+1)
				if err != nil {
					return nil, err
				}
				items = append(items, converted)
			}
			if close, err := decoder.Token(); err != nil || close != json.Delim(']') {
				return nil, errOTLPInboundMappingV8
			}
			return finish(&commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: items}}})
		case '{':
			seen := make(map[string]struct{})
			items := make([]*commonpb.KeyValue, 0)
			for decoder.More() {
				nameToken, nameErr := decoder.Token()
				name, ok := nameToken.(string)
				if nameErr != nil || !ok || name == "" {
					return nil, errOTLPInboundMappingV8
				}
				if _, duplicate := seen[name]; duplicate {
					return nil, errOTLPInboundMappingV8
				}
				seen[name] = struct{}{}
				var item json.RawMessage
				if err := decoder.Decode(&item); err != nil {
					return nil, errOTLPInboundMappingV8
				}
				converted, err := inboundJSONAnyValue(item, depth+1)
				if err != nil {
					return nil, err
				}
				items = append(items, &commonpb.KeyValue{Key: name, Value: converted})
			}
			if close, err := decoder.Token(); err != nil || close != json.Delim('}') {
				return nil, errOTLPInboundMappingV8
			}
			return finish(&commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: items}}})
		}
	}
	// Null has no canonical generated JSON arm and is rejected instead of being
	// smuggled through a generic interface value.
	return nil, errOTLPInboundMappingV8
}

func inboundMappedFieldFromAny(
	target observability.InboundTarget,
	field observability.InboundTargetField,
	value *commonpb.AnyValue,
) (observability.InboundMappedField, error) {
	kind, ok := target.MappedValueKind(field)
	if !ok || value == nil {
		return observability.InboundMappedField{}, errOTLPInboundMappingV8
	}
	switch kind {
	case observability.InboundMappedValueString:
		text, ok := value.Value.(*commonpb.AnyValue_StringValue)
		if !ok {
			return observability.InboundMappedField{}, errOTLPInboundMappingV8
		}
		return observability.NewInboundMappedString(field, text.StringValue), nil
	case observability.InboundMappedValueBoolean:
		boolean, ok := value.Value.(*commonpb.AnyValue_BoolValue)
		if !ok {
			return observability.InboundMappedField{}, errOTLPInboundMappingV8
		}
		return observability.NewInboundMappedBoolean(field, boolean.BoolValue), nil
	case observability.InboundMappedValueInt64:
		integer, ok := value.Value.(*commonpb.AnyValue_IntValue)
		if !ok {
			return observability.InboundMappedField{}, errOTLPInboundMappingV8
		}
		return observability.NewInboundMappedInt64(field, integer.IntValue), nil
	case observability.InboundMappedValueUint32:
		integer, ok := value.Value.(*commonpb.AnyValue_IntValue)
		if !ok || integer.IntValue < 0 || integer.IntValue > math.MaxUint32 {
			return observability.InboundMappedField{}, errOTLPInboundMappingV8
		}
		return observability.NewInboundMappedUint32(field, uint32(integer.IntValue)), nil
	case observability.InboundMappedValueUint64:
		integer, ok := value.Value.(*commonpb.AnyValue_IntValue)
		if !ok || integer.IntValue < 0 {
			return observability.InboundMappedField{}, errOTLPInboundMappingV8
		}
		return observability.NewInboundMappedUint64(field, uint64(integer.IntValue)), nil
	case observability.InboundMappedValueDouble:
		number, ok := value.Value.(*commonpb.AnyValue_DoubleValue)
		if !ok || math.IsNaN(number.DoubleValue) || math.IsInf(number.DoubleValue, 0) {
			return observability.InboundMappedField{}, errOTLPInboundMappingV8
		}
		return observability.NewInboundMappedDouble(field, number.DoubleValue), nil
	case observability.InboundMappedValueStringArray:
		array, ok := value.Value.(*commonpb.AnyValue_ArrayValue)
		if !ok || array.ArrayValue == nil {
			return observability.InboundMappedField{}, errOTLPInboundMappingV8
		}
		items := make([]string, 0, len(array.ArrayValue.Values))
		for _, item := range array.ArrayValue.Values {
			text, ok := item.GetValue().(*commonpb.AnyValue_StringValue)
			if !ok {
				return observability.InboundMappedField{}, errOTLPInboundMappingV8
			}
			items = append(items, text.StringValue)
		}
		return observability.NewInboundMappedStringArray(field, items), nil
	case observability.InboundMappedValueGenAIInputMessages:
		messages, err := inboundGenAIInputMessages(value)
		if err != nil {
			return observability.InboundMappedField{}, err
		}
		return observability.NewInboundMappedGenAIInputMessages(field, messages)
	case observability.InboundMappedValueGenAIOutputMessages:
		messages, err := inboundGenAIOutputMessages(value)
		if err != nil {
			return observability.InboundMappedField{}, err
		}
		return observability.NewInboundMappedGenAIOutputMessages(field, messages)
	case observability.InboundMappedValueGenAIToolCallArguments:
		entries, err := inboundToolArguments(value)
		if err != nil {
			return observability.InboundMappedField{}, err
		}
		return observability.NewInboundMappedGenAIToolCallArguments(field, entries)
	case observability.InboundMappedValueGenAIToolCallResult:
		entries, err := inboundToolResult(value)
		if err != nil {
			return observability.InboundMappedField{}, err
		}
		return observability.NewInboundMappedGenAIToolCallResult(field, entries)
	default:
		return observability.InboundMappedField{}, errOTLPInboundMappingV8
	}
}

func inboundCanonicalJSON(value *commonpb.AnyValue, depth int) (observability.TelemetryStructuredGenAICanonicalJSON, error) {
	if value == nil || depth > 8 {
		return nil, errOTLPInboundMappingV8
	}
	switch typed := value.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return observability.TelemetryStructuredArmGenAICanonicalJSONString{Value: typed.StringValue}, nil
	case *commonpb.AnyValue_BoolValue:
		return observability.TelemetryStructuredArmGenAICanonicalJSONBoolean{Value: typed.BoolValue}, nil
	case *commonpb.AnyValue_IntValue:
		return observability.TelemetryStructuredArmGenAICanonicalJSONInt64{Value: typed.IntValue}, nil
	case *commonpb.AnyValue_DoubleValue:
		if math.IsNaN(typed.DoubleValue) || math.IsInf(typed.DoubleValue, 0) {
			return nil, errOTLPInboundMappingV8
		}
		return observability.TelemetryStructuredArmGenAICanonicalJSONFiniteDouble{Value: typed.DoubleValue}, nil
	case *commonpb.AnyValue_ArrayValue:
		if typed.ArrayValue == nil {
			return nil, errOTLPInboundMappingV8
		}
		items := make([]observability.TelemetryStructuredGenAICanonicalJSON, 0, len(typed.ArrayValue.Values))
		for _, item := range typed.ArrayValue.Values {
			converted, err := inboundCanonicalJSON(item, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, converted)
		}
		return observability.TelemetryStructuredArmGenAICanonicalJSONArray{Items: items}, nil
	case *commonpb.AnyValue_KvlistValue:
		if typed.KvlistValue == nil {
			return nil, errOTLPInboundMappingV8
		}
		index := newOTLPTypedAttributeIndex(typed.KvlistValue.Values)
		if index.invalidCount() != 0 || len(index.keys()) != len(typed.KvlistValue.Values) {
			return nil, errOTLPInboundMappingV8
		}
		entries := make([]observability.GenAICanonicalJSONEntryMemberInput, 0, len(typed.KvlistValue.Values))
		for _, item := range typed.KvlistValue.Values {
			converted, err := inboundCanonicalJSON(item.Value, depth+1)
			if err != nil {
				return nil, err
			}
			entry, err := observability.NewGenAICanonicalJSONEntryMember(item.Key, converted)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}
		return observability.TelemetryStructuredArmGenAICanonicalJSONObject{Entries: entries}, nil
	default:
		return nil, errOTLPInboundMappingV8
	}
}

func inboundGenAIInputMessages(value *commonpb.AnyValue) (observability.TelemetryStructuredGenAIInputMessages, error) {
	if text, ok := value.GetValue().(*commonpb.AnyValue_StringValue); ok {
		return observability.TelemetryStructuredGenAIInputMessages{Items: []observability.TelemetryStructuredGenAIChatMessage{{
			Role: "user", Parts: inboundTextParts(text.StringValue),
		}}}, nil
	}
	array, ok := value.GetValue().(*commonpb.AnyValue_ArrayValue)
	if !ok || array.ArrayValue == nil {
		return observability.TelemetryStructuredGenAIInputMessages{}, errOTLPInboundMappingV8
	}
	result := observability.TelemetryStructuredGenAIInputMessages{Items: make([]observability.TelemetryStructuredGenAIChatMessage, 0, len(array.ArrayValue.Values))}
	for _, item := range array.ArrayValue.Values {
		message, err := inboundGenAIChatMessage(item)
		if err != nil {
			return observability.TelemetryStructuredGenAIInputMessages{}, err
		}
		result.Items = append(result.Items, message)
	}
	return result, nil
}

func inboundGenAIOutputMessages(value *commonpb.AnyValue) (observability.TelemetryStructuredGenAIOutputMessages, error) {
	if text, ok := value.GetValue().(*commonpb.AnyValue_StringValue); ok {
		return observability.TelemetryStructuredGenAIOutputMessages{Items: []observability.TelemetryStructuredGenAIOutputMessage{{
			Role: "assistant", Parts: inboundTextParts(text.StringValue), FinishReason: observability.Absent[string](),
		}}}, nil
	}
	array, ok := value.GetValue().(*commonpb.AnyValue_ArrayValue)
	if !ok || array.ArrayValue == nil {
		return observability.TelemetryStructuredGenAIOutputMessages{}, errOTLPInboundMappingV8
	}
	result := observability.TelemetryStructuredGenAIOutputMessages{Items: make([]observability.TelemetryStructuredGenAIOutputMessage, 0, len(array.ArrayValue.Values))}
	for _, item := range array.ArrayValue.Values {
		message, err := inboundGenAIOutputMessage(item)
		if err != nil {
			return observability.TelemetryStructuredGenAIOutputMessages{}, err
		}
		result.Items = append(result.Items, message)
	}
	return result, nil
}

func inboundTextParts(content string) observability.TelemetryStructuredGenAIMessageParts {
	return observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
		observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: content}},
	}}
}

func inboundKVList(value *commonpb.AnyValue) ([]*commonpb.KeyValue, otlpTypedAttributeIndex, error) {
	list, ok := value.GetValue().(*commonpb.AnyValue_KvlistValue)
	if !ok || list.KvlistValue == nil {
		return nil, otlpTypedAttributeIndex{}, errOTLPInboundMappingV8
	}
	index := newOTLPTypedAttributeIndex(list.KvlistValue.Values)
	if index.invalidCount() != 0 || len(index.keys()) != len(list.KvlistValue.Values) {
		return nil, otlpTypedAttributeIndex{}, errOTLPInboundMappingV8
	}
	return list.KvlistValue.Values, index, nil
}

func inboundGenAIChatMessage(value *commonpb.AnyValue) (observability.TelemetryStructuredGenAIChatMessage, error) {
	items, index, err := inboundKVList(value)
	if err != nil {
		return observability.TelemetryStructuredGenAIChatMessage{}, err
	}
	role, state := index.stringValue("role")
	partsValue, partsState := index.lookup("parts")
	if state != otlpTypedAttributeUnique || partsState != otlpTypedAttributeUnique {
		return observability.TelemetryStructuredGenAIChatMessage{}, errOTLPInboundMappingV8
	}
	parts, err := inboundGenAIMessageParts(partsValue)
	if err != nil {
		return observability.TelemetryStructuredGenAIChatMessage{}, err
	}
	result := observability.TelemetryStructuredGenAIChatMessage{Role: role, Parts: parts}
	if name, nameState := index.stringValue("name"); nameState == otlpTypedAttributeUnique {
		result.Name = observability.Present(name)
	} else if nameState != otlpTypedAttributeAbsent {
		return observability.TelemetryStructuredGenAIChatMessage{}, errOTLPInboundMappingV8
	}
	for _, item := range items {
		if item.Key == "role" || item.Key == "parts" || item.Key == "name" {
			continue
		}
		converted, err := inboundCanonicalJSON(item.Value, 0)
		if err != nil {
			return observability.TelemetryStructuredGenAIChatMessage{}, err
		}
		entry, err := observability.NewGenAIChatMessageEntryMember(item.Key, converted)
		if err != nil {
			return observability.TelemetryStructuredGenAIChatMessage{}, err
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}

func inboundGenAIOutputMessage(value *commonpb.AnyValue) (observability.TelemetryStructuredGenAIOutputMessage, error) {
	items, index, err := inboundKVList(value)
	if err != nil {
		return observability.TelemetryStructuredGenAIOutputMessage{}, err
	}
	role, roleState := index.stringValue("role")
	finish, finishState := index.stringValue("finish_reason")
	partsValue, partsState := index.lookup("parts")
	if roleState != otlpTypedAttributeUnique ||
		(finishState != otlpTypedAttributeUnique && finishState != otlpTypedAttributeAbsent) ||
		partsState != otlpTypedAttributeUnique {
		return observability.TelemetryStructuredGenAIOutputMessage{}, errOTLPInboundMappingV8
	}
	parts, err := inboundGenAIMessageParts(partsValue)
	if err != nil {
		return observability.TelemetryStructuredGenAIOutputMessage{}, err
	}
	result := observability.TelemetryStructuredGenAIOutputMessage{
		Role: role, FinishReason: observability.Absent[string](), Parts: parts,
	}
	if finishState == otlpTypedAttributeUnique {
		result.FinishReason = observability.Present(finish)
	}
	if name, nameState := index.stringValue("name"); nameState == otlpTypedAttributeUnique {
		result.Name = observability.Present(name)
	} else if nameState != otlpTypedAttributeAbsent {
		return observability.TelemetryStructuredGenAIOutputMessage{}, errOTLPInboundMappingV8
	}
	for _, item := range items {
		if item.Key == "role" || item.Key == "parts" || item.Key == "name" || item.Key == "finish_reason" {
			continue
		}
		converted, err := inboundCanonicalJSON(item.Value, 0)
		if err != nil {
			return observability.TelemetryStructuredGenAIOutputMessage{}, err
		}
		entry, err := observability.NewGenAIOutputMessageEntryMember(item.Key, converted)
		if err != nil {
			return observability.TelemetryStructuredGenAIOutputMessage{}, err
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}

func inboundGenAIMessageParts(value *commonpb.AnyValue) (observability.TelemetryStructuredGenAIMessageParts, error) {
	array, ok := value.GetValue().(*commonpb.AnyValue_ArrayValue)
	if !ok || array.ArrayValue == nil {
		return observability.TelemetryStructuredGenAIMessageParts{}, errOTLPInboundMappingV8
	}
	result := observability.TelemetryStructuredGenAIMessageParts{Items: make([]observability.TelemetryStructuredGenAIMessagePart, 0, len(array.ArrayValue.Values))}
	for _, item := range array.ArrayValue.Values {
		part, err := inboundGenAIMessagePart(item)
		if err != nil {
			return observability.TelemetryStructuredGenAIMessageParts{}, err
		}
		result.Items = append(result.Items, part)
	}
	return result, nil
}

func inboundGenAIMessagePart(value *commonpb.AnyValue) (observability.TelemetryStructuredGenAIMessagePart, error) {
	items, index, err := inboundKVList(value)
	if err != nil {
		return nil, err
	}
	typeName, state := index.stringValue("type")
	if state != otlpTypedAttributeUnique {
		return nil, errOTLPInboundMappingV8
	}
	stringRequired := func(key string) (string, error) {
		value, state := index.stringValue(key)
		if state != otlpTypedAttributeUnique {
			return "", errOTLPInboundMappingV8
		}
		return value, nil
	}
	optionalString := func(key string) (observability.Optional[string], error) {
		value, state := index.stringValue(key)
		switch state {
		case otlpTypedAttributeAbsent:
			return observability.Absent[string](), nil
		case otlpTypedAttributeUnique:
			return observability.Present(value), nil
		default:
			return observability.Absent[string](), errOTLPInboundMappingV8
		}
	}
	switch typeName {
	case "text":
		content, err := stringRequired("content")
		if err != nil {
			return nil, err
		}
		entries, err := inboundGenAIPartEntries(items, map[string]bool{"type": true, "content": true}, observability.NewGenAITextPartEntryMember)
		return observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: content, Entries: entries}}, err
	case "reasoning":
		content, err := stringRequired("content")
		if err != nil {
			return nil, err
		}
		entries, err := inboundGenAIPartEntries(items, map[string]bool{"type": true, "content": true}, observability.NewGenAIReasoningPartEntryMember)
		return observability.TelemetryStructuredArmGenAIMessagePartReasoning{Value: observability.TelemetryStructuredGenAIReasoningPart{Content: content, Entries: entries}}, err
	case "blob":
		modality, err := stringRequired("modality")
		if err != nil {
			return nil, err
		}
		content, err := stringRequired("content")
		if err != nil {
			return nil, err
		}
		mime, err := optionalString("mime_type")
		if err != nil {
			return nil, err
		}
		entries, err := inboundGenAIPartEntries(items, map[string]bool{"type": true, "modality": true, "content": true, "mime_type": true}, observability.NewGenAIBlobPartEntryMember)
		return observability.TelemetryStructuredArmGenAIMessagePartBlob{Value: observability.TelemetryStructuredGenAIBlobPart{Modality: modality, Content: content, MimeType: mime, Entries: entries}}, err
	case "file":
		modality, err := stringRequired("modality")
		if err != nil {
			return nil, err
		}
		fileID, err := stringRequired("file_id")
		if err != nil {
			return nil, err
		}
		mime, err := optionalString("mime_type")
		if err != nil {
			return nil, err
		}
		entries, err := inboundGenAIPartEntries(items, map[string]bool{"type": true, "modality": true, "file_id": true, "mime_type": true}, observability.NewGenAIFilePartEntryMember)
		return observability.TelemetryStructuredArmGenAIMessagePartFile{Value: observability.TelemetryStructuredGenAIFilePart{Modality: modality, FileID: fileID, MimeType: mime, Entries: entries}}, err
	case "uri":
		modality, err := stringRequired("modality")
		if err != nil {
			return nil, err
		}
		uri, err := stringRequired("uri")
		if err != nil {
			return nil, err
		}
		mime, err := optionalString("mime_type")
		if err != nil {
			return nil, err
		}
		entries, err := inboundGenAIPartEntries(items, map[string]bool{"type": true, "modality": true, "uri": true, "mime_type": true}, observability.NewGenAIUriPartEntryMember)
		return observability.TelemetryStructuredArmGenAIMessagePartUri{Value: observability.TelemetryStructuredGenAIUriPart{Modality: modality, Uri: uri, MimeType: mime, Entries: entries}}, err
	case "compaction":
		id, err := optionalString("id")
		if err != nil {
			return nil, err
		}
		content, err := optionalString("content")
		if err != nil {
			return nil, err
		}
		entries, err := inboundGenAIPartEntries(items, map[string]bool{"type": true, "id": true, "content": true}, observability.NewGenAICompactionPartEntryMember)
		return observability.TelemetryStructuredArmGenAIMessagePartCompaction{Value: observability.TelemetryStructuredGenAICompactionPart{ID: id, Content: content, Entries: entries}}, err
	case "tool_call":
		name, err := stringRequired("name")
		if err != nil {
			return nil, err
		}
		id, err := optionalString("id")
		if err != nil {
			return nil, err
		}
		part := observability.TelemetryStructuredGenAIToolCallRequestPart{ID: id, Name: name}
		if raw, state := index.lookup("arguments"); state == otlpTypedAttributeUnique {
			converted, err := inboundCanonicalJSON(raw, 0)
			if err != nil {
				return nil, err
			}
			part.Arguments = observability.Present[observability.TelemetryStructuredGenAICanonicalJSON](converted)
		} else if state != otlpTypedAttributeAbsent {
			return nil, errOTLPInboundMappingV8
		}
		part.Entries, err = inboundGenAIPartEntries(items, map[string]bool{"type": true, "id": true, "name": true, "arguments": true}, observability.NewGenAIToolCallRequestPartEntryMember)
		if err != nil {
			return nil, err
		}
		return observability.TelemetryStructuredArmGenAIMessagePartToolCall{Value: part}, nil
	case "tool_call_response":
		response, state := index.lookup("response")
		if state != otlpTypedAttributeUnique {
			return nil, errOTLPInboundMappingV8
		}
		converted, err := inboundCanonicalJSON(response, 0)
		if err != nil {
			return nil, err
		}
		id, err := optionalString("id")
		if err != nil {
			return nil, err
		}
		entries, err := inboundGenAIPartEntries(items, map[string]bool{"type": true, "id": true, "response": true}, observability.NewGenAIToolCallResponsePartEntryMember)
		return observability.TelemetryStructuredArmGenAIMessagePartToolCallResponse{Value: observability.TelemetryStructuredGenAIToolCallResponsePart{ID: id, Response: converted, Entries: entries}}, err
	case "server_tool_call":
		name, err := stringRequired("name")
		if err != nil {
			return nil, err
		}
		id, err := optionalString("id")
		if err != nil {
			return nil, err
		}
		payloadValue, state := index.lookup("server_tool_call")
		if state != otlpTypedAttributeUnique {
			return nil, errOTLPInboundMappingV8
		}
		payload, err := inboundGenericServerToolPayload(payloadValue)
		if err != nil {
			return nil, err
		}
		entries, err := inboundGenAIPartEntries(items, map[string]bool{"type": true, "id": true, "name": true, "server_tool_call": true}, observability.NewGenAIServerToolCallPartEntryMember)
		return observability.TelemetryStructuredArmGenAIMessagePartServerToolCall{Value: observability.TelemetryStructuredGenAIServerToolCallPart{ID: id, Name: name, ServerToolCall: payload, Entries: entries}}, err
	case "server_tool_call_response":
		id, err := optionalString("id")
		if err != nil {
			return nil, err
		}
		payloadValue, state := index.lookup("server_tool_call_response")
		if state != otlpTypedAttributeUnique {
			return nil, errOTLPInboundMappingV8
		}
		payload, err := inboundGenericServerToolPayload(payloadValue)
		if err != nil {
			return nil, err
		}
		entries, err := inboundGenAIPartEntries(items, map[string]bool{"type": true, "id": true, "server_tool_call_response": true}, observability.NewGenAIServerToolCallResponsePartEntryMember)
		return observability.TelemetryStructuredArmGenAIMessagePartServerToolCallResponse{Value: observability.TelemetryStructuredGenAIServerToolCallResponsePart{ID: id, ServerToolCallResponse: payload, Entries: entries}}, err
	default:
		entries := make([]observability.GenAIGenericPartEntryMemberInput, 0, len(items)-1)
		for _, item := range items {
			if item.Key == "type" {
				continue
			}
			converted, err := inboundCanonicalJSON(item.Value, 0)
			if err != nil {
				return nil, err
			}
			entry, err := observability.NewGenAIGenericPartEntryMember(item.Key, converted)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}
		return observability.TelemetryStructuredArmGenAIMessagePartGeneric{Tag: typeName, Value: observability.TelemetryStructuredGenAIGenericPart{Entries: entries}}, nil
	}
}

func inboundGenAIPartEntries[T any](
	items []*commonpb.KeyValue,
	reserved map[string]bool,
	newEntry func(string, observability.TelemetryStructuredGenAICanonicalJSON) (T, error),
) ([]T, error) {
	result := make([]T, 0, len(items))
	for _, item := range items {
		if item == nil || reserved[item.Key] {
			continue
		}
		converted, err := inboundCanonicalJSON(item.Value, 0)
		if err != nil {
			return nil, err
		}
		entry, err := newEntry(item.Key, converted)
		if err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	return result, nil
}

func inboundGenericServerToolPayload(value *commonpb.AnyValue) (observability.TelemetryStructuredGenAIGenericServerToolPayload, error) {
	items, index, err := inboundKVList(value)
	if err != nil {
		return observability.TelemetryStructuredGenAIGenericServerToolPayload{}, err
	}
	typeName, state := index.stringValue("type")
	if state != otlpTypedAttributeUnique {
		return observability.TelemetryStructuredGenAIGenericServerToolPayload{}, errOTLPInboundMappingV8
	}
	entries, err := inboundGenAIPartEntries(items, map[string]bool{"type": true}, observability.NewGenAIGenericServerToolPayloadEntryMember)
	if err != nil {
		return observability.TelemetryStructuredGenAIGenericServerToolPayload{}, err
	}
	return observability.TelemetryStructuredGenAIGenericServerToolPayload{Type: typeName, Entries: entries}, nil
}

func inboundToolArguments(value *commonpb.AnyValue) (observability.TelemetryStructuredGenAIToolCallArguments, error) {
	items, _, err := inboundKVList(value)
	if err != nil {
		return observability.TelemetryStructuredGenAIToolCallArguments{}, err
	}
	result := observability.TelemetryStructuredGenAIToolCallArguments{Entries: make([]observability.GenAIToolCallArgumentsEntryMemberInput, 0, len(items))}
	for _, item := range items {
		converted, err := inboundCanonicalJSON(item.Value, 0)
		if err != nil {
			return observability.TelemetryStructuredGenAIToolCallArguments{}, err
		}
		entry, err := observability.NewGenAIToolCallArgumentsEntryMember(item.Key, converted)
		if err != nil {
			return observability.TelemetryStructuredGenAIToolCallArguments{}, err
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}

func inboundToolResult(value *commonpb.AnyValue) (observability.TelemetryStructuredGenAIToolCallResult, error) {
	items, _, err := inboundKVList(value)
	if err != nil {
		return observability.TelemetryStructuredGenAIToolCallResult{}, err
	}
	result := observability.TelemetryStructuredGenAIToolCallResult{Entries: make([]observability.GenAIToolCallResultEntryMemberInput, 0, len(items))}
	for _, item := range items {
		converted, err := inboundCanonicalJSON(item.Value, 0)
		if err != nil {
			return observability.TelemetryStructuredGenAIToolCallResult{}, err
		}
		entry, err := observability.NewGenAIToolCallResultEntryMember(item.Key, converted)
		if err != nil {
			return observability.TelemetryStructuredGenAIToolCallResult{}, err
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}
