// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

var (
	ErrBatchUnsupported = errors.New("ACP JSON-RPC batches are not supported")
	ErrInvalidMessage   = errors.New("invalid ACP JSON-RPC message")
)

type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
	Raw     json.RawMessage `json:"-"`
}

func ParseMessage(frame []byte) (Message, error) { return parseMessage(frame, false) }

// ParseMessageAllowingNullIDErrors is ParseMessage that also accepts the
// error response JSON-RPC 2.0 sends with a null id when the id of the request
// could not be determined (section 5.1), such as an editor's answer to an
// agent notification it could not parse. ParseMessage refuses it, which in
// action mode ended the whole session (GAP-0351). Secure Client keeps
// ParseMessage (issue #1092).
func ParseMessageAllowingNullIDErrors(frame []byte) (Message, error) {
	return parseMessage(frame, true)
}

// IsNullIDError reports an error response with a null id: it answers no
// pending request.
func (m Message) IsNullIDError() bool {
	return m.Method == "" && bytes.Equal(bytes.TrimSpace(m.ID), []byte("null")) && len(m.Error) > 0 && len(m.Result) == 0
}

func parseMessage(frame []byte, allowNullIDError bool) (Message, error) {
	frame = bytes.TrimSpace(frame)
	if len(frame) == 0 || len(frame) > MaxFrameBytes {
		return Message{}, fmt.Errorf("%w: frame size %d", ErrInvalidMessage, len(frame))
	}
	if frame[0] == '[' {
		return Message{}, ErrBatchUnsupported
	}
	if frame[0] != '{' {
		return Message{}, ErrInvalidMessage
	}
	if err := rejectDuplicateJSONKeys(frame); err != nil {
		return Message{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(frame))
	var msg Message
	if err := decoder.Decode(&msg); err != nil {
		return Message{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Message{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidMessage)
	}
	if msg.JSONRPC != "2.0" {
		return Message{}, fmt.Errorf("%w: jsonrpc must be 2.0", ErrInvalidMessage)
	}
	hasID := len(msg.ID) > 0 && string(msg.ID) != "null"
	hasMethod := msg.Method != ""
	hasResult := len(msg.Result) > 0
	hasError := len(msg.Error) > 0
	if hasID && !validJSONRPCID(msg.ID) {
		return Message{}, fmt.Errorf("%w: id must be a string or number", ErrInvalidMessage)
	}
	if len(msg.Params) > 0 {
		trimmed := bytes.TrimSpace(msg.Params)
		if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
			return Message{}, fmt.Errorf("%w: params must be an object or array", ErrInvalidMessage)
		}
	}
	if hasMethod {
		if hasResult || hasError {
			return Message{}, fmt.Errorf("%w: request cannot contain result or error", ErrInvalidMessage)
		}
	} else if (!hasID && !(allowNullIDError && msg.IsNullIDError())) || hasResult == hasError {
		return Message{}, fmt.Errorf("%w: response must contain exactly one of result or error", ErrInvalidMessage)
	}
	msg.Raw = append([]byte(nil), frame...)
	return msg, nil
}

func validJSONRPCID(id json.RawMessage) bool {
	trimmed := bytes.TrimSpace(id)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return false
	}
	if trimmed[0] == '"' {
		var value string
		return json.Unmarshal(trimmed, &value) == nil
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return false
	}
	return number.String() != ""
}

// acpFreeFormKey names the members that hold data nothing here reads by key:
// the output a tool reported (rawOutput) and the extension metadata (_meta,
// ACP's reserved member). Keys that differ only in case are ordinary there (a
// header map with ETag and etag), so the folded check stops at them; an
// exact duplicate is still refused.
func acpFreeFormKey(key string) bool { return key == "rawOutput" || key == "_meta" }

// foldJSONKey is a key as encoding/json matches it to a struct field: with
// simple case folding, each rune read as the smallest rune of its fold orbit.
func foldJSONKey(key string) string {
	return strings.Map(func(r rune) rune {
		smallest := r
		for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
			if folded < smallest {
				smallest = folded
			}
		}
		return smallest
	}, key)
}

// rejectDuplicateJSONKeys recursively rejects ambiguous objects. Different
// JSON implementations disagree about whether the first or last duplicate
// wins, which otherwise creates a parser-smuggling boundary between the guard
// and the ACP peer. Keys that differ only in letter case are duplicates too,
// except inside free-form members (acpFreeFormKey)
// (rel-1-0-10:GAP-0295): encoding/json, which reads every frame here, matches
// a field name without regard to case and keeps the last such key, while the
// editor and the agent (serde and other exact-match readers) read the exact
// key, so a "Command" after a "command" made the guard judge one action and
// the editor run another.
func rejectDuplicateJSONKeys(frame []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.UseNumber()
	var visit func(free bool) error
	visit = func(free bool) error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]string{}
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return keyErr
				}
				key, keyOK := keyToken.(string)
				if !keyOK {
					return errors.New("object key is not a string")
				}
				folded := key
				if !free {
					folded = foldJSONKey(key)
				}
				if first, duplicate := seen[folded]; duplicate {
					if first == key {
						return fmt.Errorf("duplicate JSON key %q", key)
					}
					return fmt.Errorf("JSON keys %q and %q differ only in letter case", first, key)
				}
				seen[folded] = key
				if err := visit(free || acpFreeFormKey(key)); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := visit(free); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected closing delimiter")
		}
	}
	if err := visit(false); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func (m Message) IsRequest() bool      { return m.Method != "" && len(m.ID) > 0 && string(m.ID) != "null" }
func (m Message) IsNotification() bool { return m.Method != "" && !m.IsRequest() }

func (m Message) IDKey() string {
	if len(m.ID) == 0 {
		return ""
	}
	return string(m.ID)
}

func ErrorResponse(id json.RawMessage, code int, message string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	payload := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id}
	payload.Error.Code = code
	payload.Error.Message = message
	out, _ := json.Marshal(payload)
	return out
}

type Direction string

const (
	ClientToAgent Direction = "client_to_agent"
	AgentToClient Direction = "agent_to_client"
)

type Surface string

const (
	SurfaceProtocol   Surface = "protocol"
	SurfacePrompt     Surface = "prompt"
	SurfaceOutput     Surface = "output"
	SurfaceTool       Surface = "tool"
	SurfacePermission Surface = "permission"
	SurfaceFilesystem Surface = "filesystem"
	SurfaceTerminal   Surface = "terminal"
)

func Classify(msg Message, direction Direction) Surface {
	switch msg.Method {
	case "session/prompt":
		return SurfacePrompt
	case "session/update":
		return SurfaceOutput
	case "session/request_permission", "elicitation/create":
		return SurfacePermission
	case "fs/read_text_file", "fs/write_text_file":
		return SurfaceFilesystem
	case "terminal/create", "terminal/kill", "terminal/output", "terminal/release", "terminal/wait_for_exit":
		return SurfaceTerminal
	}
	if direction == AgentToClient && msg.Method != "" {
		return SurfaceTool
	}
	return SurfaceProtocol
}
