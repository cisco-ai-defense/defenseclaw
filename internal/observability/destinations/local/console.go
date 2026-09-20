// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

// Console writes one injection-safe JSON line for each destination-projected
// JSON record. It does not own or close the supplied writer (normally stdout or
// stderr), but Close permanently stops this generation from writing to it.
type Console struct {
	writer io.Writer
	gate   chan struct{}
	closed bool
}

// NewConsole performs all fallible adapter preparation. The writer must be
// supplied explicitly so runtime assembly, rather than this package, chooses
// stdout, stderr, or a test stream.
func NewConsole(writer io.Writer) (*Console, error) {
	if writer == nil {
		return nil, newError(ErrorInvalidConfig)
	}
	adapter := &Console{writer: writer, gate: make(chan struct{}, 1)}
	adapter.gate <- struct{}{}
	return adapter, nil
}

// EncodedSize returns a conservative ceiling for complete console output. A
// projected byte can expand to at most one six-byte JSON escape; one newline is
// added per record. Deliver verifies that actual output does not exceed it.
func (*Console) EncodedSize(projectedSizes []int) (int, bool) {
	total := 0
	for _, size := range projectedSizes {
		if size < 0 || size > (maxInt-1)/6 {
			return 0, false
		}
		encoded := size*6 + 1
		if total > maxInt-encoded {
			return 0, false
		}
		total += encoded
	}
	return total, true
}

// Deliver validates and renders only Batch projected bytes. Whitespace is
// compacted, then terminal controls are represented as JSON escapes. Embedded
// CR/LF, ESC/CSI, bidi controls, and other formatting controls therefore cannot
// create a second line or execute a terminal control sequence.
func (adapter *Console) Deliver(ctx context.Context, batch delivery.Batch) delivery.DeliveryResult {
	if adapter == nil || ctx == nil {
		return localResult(delivery.OutcomePermanentPayload)
	}
	estimate, ok := adapter.EncodedSize(batchSizes(batch))
	if !ok || estimate != batch.EncodedSize() {
		return localResult(delivery.OutcomePermanentPayload)
	}

	// Prepare the complete bounded batch before the first write. A malformed
	// later item can never make an earlier item appear ambiguously delivered.
	lines := make([][]byte, 0, batch.Len())
	actual := 0
	for _, item := range batch.Items() {
		projected := item.Bytes()
		if !utf8.Valid(projected) || !json.Valid(projected) {
			return localResult(delivery.OutcomePermanentPayload)
		}
		var compact bytes.Buffer
		compact.Grow(len(projected))
		if err := json.Compact(&compact, projected); err != nil {
			return localResult(delivery.OutcomePermanentPayload)
		}
		line := escapeTerminalControls(compact.Bytes())
		line = append(line, '\n')
		if actual > estimate-len(line) {
			return localResult(delivery.OutcomePermanentPayload)
		}
		actual += len(line)
		lines = append(lines, line)
	}

	if !adapter.lock(ctx) {
		return localResult(delivery.OutcomeTransient)
	}
	defer adapter.unlock()
	if adapter.closed {
		return localResult(delivery.OutcomePermanentPayload)
	}
	wroteAny := false
	for _, line := range lines {
		if err := ctx.Err(); err != nil {
			if wroteAny {
				return localResult(delivery.OutcomeAmbiguous)
			}
			return localResult(delivery.OutcomeTransient)
		}
		n, err := adapter.writer.Write(line)
		if n > 0 {
			wroteAny = true
		}
		if err != nil || n != len(line) {
			if wroteAny {
				return localResult(delivery.OutcomeAmbiguous)
			}
			return localResult(delivery.OutcomeTransient)
		}
	}
	return localResult(delivery.OutcomeDelivered)
}

// Close is context-bounded while another write owns the adapter. It is
// idempotent and retryable and intentionally does not close the supplied stream.
func (adapter *Console) Close(ctx context.Context) error {
	if adapter == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorInvalidConfig)
	}
	if !adapter.lock(ctx) {
		return ctx.Err()
	}
	defer adapter.unlock()
	adapter.closed = true
	return nil
}

func (adapter *Console) lock(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-adapter.gate:
		return true
	}
}

func (adapter *Console) unlock() { adapter.gate <- struct{}{} }

func batchSizes(batch delivery.Batch) []int {
	items := batch.Items()
	sizes := make([]int, len(items))
	for index := range items {
		sizes[index] = items[index].Size()
	}
	return sizes
}

func escapeTerminalControls(input []byte) []byte {
	result := make([]byte, 0, len(input))
	for len(input) > 0 {
		character, width := utf8.DecodeRune(input)
		if terminalUnsafe(character) {
			result = appendUnicodeEscape(result, character)
		} else {
			result = append(result, input[:width]...)
		}
		input = input[width:]
	}
	return result
}

func terminalUnsafe(character rune) bool {
	return unicode.Is(unicode.Cc, character) ||
		unicode.Is(unicode.Cf, character) ||
		character == '\u2028' || character == '\u2029'
}

func appendUnicodeEscape(output []byte, character rune) []byte {
	if character <= 0xffff {
		return appendHexEscape(output, uint16(character))
	}
	high, low := utf16.EncodeRune(character)
	output = appendHexEscape(output, uint16(high))
	return appendHexEscape(output, uint16(low))
}

func appendHexEscape(output []byte, value uint16) []byte {
	const hex = "0123456789abcdef"
	return append(output, '\\', 'u',
		hex[value>>12], hex[value>>8&0xf], hex[value>>4&0xf], hex[value&0xf])
}

func localResult(outcome delivery.DeliveryOutcome) delivery.DeliveryResult {
	return delivery.DeliveryResult{Outcome: outcome}
}

const maxInt = int(^uint(0) >> 1)
