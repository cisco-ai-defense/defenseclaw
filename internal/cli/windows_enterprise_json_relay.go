// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"io"
)

// windowsEnterpriseJSONRelayMax bounds how much of the child's stdout is
// held back; the result object is printed last, so older output can go to
// stderr as it arrives.
const windowsEnterpriseJSONRelayMax = 4 << 20

// windowsEnterpriseJSONRelay keeps the installer's stdout a single JSON
// result: it holds the child's stdout and, when the child exits, writes the
// last top-level JSON object to stdout and every other byte to stderr. It is
// only used under -Json, so output with no JSON object at all goes to stderr
// too; the caller then writes its own failure result to stdout.
type windowsEnterpriseJSONRelay struct {
	stdout io.Writer
	stderr io.Writer
	held   bytes.Buffer
}

func newWindowsEnterpriseJSONRelay(stdout, stderr io.Writer) *windowsEnterpriseJSONRelay {
	return &windowsEnterpriseJSONRelay{stdout: stdout, stderr: stderr}
}

func (relay *windowsEnterpriseJSONRelay) Write(body []byte) (int, error) {
	_, _ = relay.held.Write(body)
	if over := relay.held.Len() - windowsEnterpriseJSONRelayMax; over > 0 {
		// Spill whole lines so a JSON object is never split.
		pending := relay.held.Bytes()
		cut := bytes.LastIndexByte(pending[:over], '\n') + 1
		if cut == 0 {
			cut = over
		}
		_, _ = relay.stderr.Write(pending[:cut])
		relay.held.Next(cut)
	}
	return len(body), nil
}

// Finish writes the held output. It is called once, after the child exits.
func (relay *windowsEnterpriseJSONRelay) Finish() {
	body := relay.held.Bytes()
	start, end, ok := lastWindowsEnterpriseJSONObjectSpan(body)
	if !ok {
		_, _ = relay.stderr.Write(body)
		relay.held.Reset()
		return
	}
	result := body[start:end]
	if before := bytes.TrimSpace(body[:start]); len(before) > 0 {
		_, _ = relay.stderr.Write(append(append([]byte{}, before...), '\n'))
	}
	if after := bytes.TrimSpace(body[end:]); len(after) > 0 {
		_, _ = relay.stderr.Write(append(append([]byte{}, after...), '\n'))
	}
	_, _ = relay.stdout.Write(append(append([]byte{}, result...), '\n'))
	relay.held.Reset()
}

// lastWindowsEnterpriseJSONObjectSpan locates the same object as
// lastWindowsEnterpriseJSONObject and returns its byte range in body.
func lastWindowsEnterpriseJSONObjectSpan(body []byte) (start, end int, ok bool) {
	var starts []int
	for index := 0; index < len(body); {
		lineStart := index
		if bytes.HasPrefix(body[index:], []byte{0xef, 0xbb, 0xbf}) {
			index += 3
		}
		if index < len(body) && body[index] == '{' {
			starts = append(starts, index)
		}
		next := bytes.IndexByte(body[lineStart:], '\n')
		if next < 0 {
			break
		}
		index = lineStart + next + 1
	}
	for candidate := len(starts) - 1; candidate >= 0; candidate-- {
		decoder := json.NewDecoder(bytes.NewReader(body[starts[candidate]:]))
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil || len(raw) == 0 || raw[0] != '{' {
			continue
		}
		return starts[candidate], starts[candidate] + int(decoder.InputOffset()), true
	}
	return 0, 0, false
}
