// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bridgeproto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Encoder serializes complete frames without an intermediate queue. Its
// writer must be an owned pipe whose deadline/closure the supervisor controls.
// A partial write poisons this encoder; a different frame is never retried on
// the damaged stream. It does not kill a process or claim cleanup on failure.
type Encoder struct {
	mu     sync.Mutex
	writer io.Writer
	err    error
}

func NewEncoder(writer io.Writer) *Encoder { return &Encoder{writer: writer} }

func (e *Encoder) Encode(frame Frame) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return e.err
	}
	if e.writer == nil || frame.Validate() != nil {
		e.err = ErrProtocol
		return e.err
	}
	data, err := json.Marshal(frame)
	if err != nil || len(data) == 0 || len(data) > MaxFrameBytes {
		e.err = ErrProtocol
		return e.err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	for _, part := range [][]byte{header[:], data} {
		for len(part) > 0 {
			n, err := e.writer.Write(part)
			if n < 0 || n > len(part) {
				err = ErrProtocol
			} else {
				part = part[n:]
			}
			if err != nil {
				e.err = err
				return err
			}
			if n == 0 {
				e.err = io.ErrShortWrite
				return e.err
			}
		}
	}
	return nil
}

// Decoder reads one bounded frame without read-ahead or a background reader.
// Malformed/truncated input and EOF permanently close this decoder. The owner
// must contain and wait its helper/workload when its private peer disappears.
type Decoder struct {
	mu     sync.Mutex
	reader io.Reader
	err    error
}

func NewDecoder(reader io.Reader) *Decoder { return &Decoder{reader: reader} }

func (d *Decoder) Decode() (Frame, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return Frame{}, d.err
	}
	refuse := func(err error) (Frame, error) {
		d.err = err
		return Frame{}, err
	}
	if d.reader == nil {
		return refuse(ErrProtocol)
	}
	var header [4]byte
	if _, err := io.ReadFull(d.reader, header[:]); err != nil {
		return refuse(err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameBytes {
		return refuse(ErrProtocol)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(d.reader, data); err != nil {
		return refuse(err)
	}
	frame, err := Parse(data)
	if err != nil {
		return refuse(err)
	}
	return frame, nil
}

// Parse rejects JSON ambiguities that encoding/json otherwise accepts: invalid
// UTF-8, lossy unpaired UTF-16 escapes, duplicate keys, case-insensitive field
// aliases, unknown fields, trailing JSON and excessive nesting/token counts.
func Parse(data []byte) (Frame, error) {
	if len(data) == 0 || len(data) > MaxFrameBytes || !utf8.Valid(data) || !pairedUnicodeEscapes(data) {
		return Frame{}, ErrProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	tokens := 0
	if !uniqueJSONValue(decoder, 0, &tokens) {
		return Frame{}, ErrProtocol
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Frame{}, ErrProtocol
	}
	if !exactFields(data, reflect.TypeFor[Frame]()) {
		return Frame{}, ErrProtocol
	}
	var frame Frame
	if json.Unmarshal(data, &frame) != nil || frame.Validate() != nil {
		return Frame{}, ErrProtocol
	}
	return frame, nil
}

func uniqueJSONValue(decoder *json.Decoder, depth int, tokens *int) bool {
	*tokens++
	if depth > 24 || *tokens > 32768 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	if value, ok := token.(string); ok {
		return !strings.ContainsRune(value, 0)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	var end json.Delim
	switch delimiter {
	case '{':
		end = '}'
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || strings.ContainsRune(name, 0) || seen[name] {
				return false
			}
			seen[name] = true
			if !uniqueJSONValue(decoder, depth+1, tokens) {
				return false
			}
		}
	case '[':
		end = ']'
		for decoder.More() {
			if !uniqueJSONValue(decoder, depth+1, tokens) {
				return false
			}
		}
	default:
		return false
	}
	closing, err := decoder.Token()
	return err == nil && closing == end
}

func exactFields(data json.RawMessage, target reflect.Type) bool {
	if target.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
			return false // omitted optional fields are allowed; explicit null is not
		}
		return exactFields(data, target.Elem())
	}
	switch target.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if json.Unmarshal(data, &object) != nil || object == nil {
			return false
		}
		fields := map[string]reflect.Type{}
		for index := range target.NumField() {
			field := target.Field(index)
			name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
			fields[name] = field.Type
			if _, present := object[name]; !present && options != "omitempty" {
				return false
			}
		}
		for name, value := range object {
			field, ok := fields[name]
			if !ok || !exactFields(value, field) {
				return false
			}
		}
	case reflect.Slice:
		if target.Elem().Kind() == reflect.Uint8 {
			return true // encoding/json checks bounded base64; Frame checks size
		}
		var values []json.RawMessage
		if json.Unmarshal(data, &values) != nil || values == nil {
			return false
		}
		for _, value := range values {
			if !exactFields(value, target.Elem()) {
				return false
			}
		}
	default:
		return !bytes.Equal(bytes.TrimSpace(data), []byte("null"))
	}
	return true
}

func pairedUnicodeEscapes(data []byte) bool {
	inside := false
	for index := 0; index < len(data); index++ {
		if data[index] == '"' {
			inside = !inside
			continue
		}
		if !inside || data[index] != '\\' {
			continue
		}
		index++
		if index >= len(data) {
			return false
		}
		if data[index] != 'u' {
			continue
		}
		if index+4 >= len(data) {
			return false
		}
		unit, err := strconv.ParseUint(string(data[index+1:index+5]), 16, 16)
		if err != nil || unit >= 0xdc00 && unit <= 0xdfff {
			return false
		}
		index += 4
		if unit >= 0xd800 && unit <= 0xdbff {
			if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[index+3:index+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			index += 6
		}
	}
	return !inside
}
