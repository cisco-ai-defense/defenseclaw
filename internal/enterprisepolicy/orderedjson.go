// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// object is a JSON object that remembers key order, so merging DefenseClaw
// entries into a shared administrator file keeps every foreign key and
// hook in the order the administrator wrote it.
type object struct {
	keys   []string
	values map[string]any
}

func newObject() *object { return &object{values: map[string]any{}} }

func (o *object) get(key string) (any, bool) {
	value, ok := o.values[key]
	return value, ok
}

func (o *object) set(key string, value any) {
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *object) delete(key string) {
	if _, ok := o.values[key]; !ok {
		return
	}
	delete(o.values, key)
	for i, candidate := range o.keys {
		if candidate == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			return
		}
	}
}

func (o *object) len() int { return len(o.keys) }

// decodeOrdered parses one JSON document into ordered objects, arrays,
// json.Number, string, bool and nil. Duplicate keys and trailing data are
// rejected: a vendor would read one of the duplicates, and guessing which
// could hide an administrator setting.
func decodeOrdered(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the JSON document")
	}
	return value, nil
}

const maxJSONDepth = 64

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			obj := newObject()
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, dup := obj.values[key]; dup {
					return nil, fmt.Errorf("duplicate JSON key %q", key)
				}
				child, err := decodeValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				obj.set(key, child)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			list := []any{}
			for decoder.More() {
				child, err := decodeValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				list = append(list, child)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return list, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", value)
		}
	default:
		return value, nil
	}
}

// decodeOrderedObject decodes a document whose root must be an object; an
// empty or whitespace-only document yields an empty object.
func decodeOrderedObject(data []byte) (*object, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return newObject(), nil
	}
	value, err := decodeOrdered(data)
	if err != nil {
		return nil, err
	}
	obj, ok := value.(*object)
	if !ok {
		return nil, errors.New("JSON document root is not an object")
	}
	return obj, nil
}

// encodeOrdered renders value with two-space indentation and a trailing
// newline, matching json.MarshalIndent output for ordinary values.
func encodeOrdered(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, value, 0); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

func writeValue(buf *bytes.Buffer, value any, indent int) error {
	switch v := value.(type) {
	case *object:
		if v.len() == 0 {
			buf.WriteString("{}")
			return nil
		}
		buf.WriteString("{\n")
		for i, key := range v.keys {
			buf.WriteString(strings.Repeat("  ", indent+1))
			encodedKey, _ := json.Marshal(key)
			buf.Write(encodedKey)
			buf.WriteString(": ")
			if err := writeValue(buf, v.values[key], indent+1); err != nil {
				return err
			}
			if i < len(v.keys)-1 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		buf.WriteString(strings.Repeat("  ", indent))
		buf.WriteByte('}')
	case []any:
		if len(v) == 0 {
			buf.WriteString("[]")
			return nil
		}
		buf.WriteString("[\n")
		for i, item := range v {
			buf.WriteString(strings.Repeat("  ", indent+1))
			if err := writeValue(buf, item, indent+1); err != nil {
				return err
			}
			if i < len(v)-1 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		buf.WriteString(strings.Repeat("  ", indent))
		buf.WriteByte(']')
	case map[string]any:
		return writeValue(buf, orderedFromMap(v), indent)
	case []map[string]any:
		list := make([]any, 0, len(v))
		for _, item := range v {
			list = append(list, item)
		}
		return writeValue(buf, list, indent)
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(encoded)
	}
	return nil
}

// orderedFromMap converts a plain map (sorted keys) into an ordered object.
func orderedFromMap(m map[string]any) *object {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	obj := newObject()
	for _, key := range keys {
		obj.set(key, m[key])
	}
	return obj
}

// canonicalJSON renders value compactly with sorted keys; it identifies an
// entry independent of formatting (allowlist digests, ownership compare).
func canonicalJSON(value any) []byte {
	var buf bytes.Buffer
	writeCanonical(&buf, value)
	return buf.Bytes()
}

func writeCanonical(buf *bytes.Buffer, value any) {
	switch v := value.(type) {
	case *object:
		keys := append([]string(nil), v.keys...)
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodedKey, _ := json.Marshal(key)
			buf.Write(encodedKey)
			buf.WriteByte(':')
			writeCanonical(buf, v.values[key])
		}
		buf.WriteByte('}')
	case map[string]any:
		writeCanonical(buf, orderedFromMap(v))
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonical(buf, item)
		}
		buf.WriteByte(']')
	default:
		encoded, _ := json.Marshal(v)
		buf.Write(encoded)
	}
}

func stringField(value any, key string) string {
	switch v := value.(type) {
	case *object:
		s, _ := v.values[key].(string)
		return s
	case map[string]any:
		s, _ := v[key].(string)
		return s
	}
	return ""
}

func boolField(value any, key string) (bool, bool) {
	switch v := value.(type) {
	case *object:
		b, ok := v.values[key].(bool)
		return b, ok
	case map[string]any:
		b, ok := v[key].(bool)
		return b, ok
	}
	return false, false
}
