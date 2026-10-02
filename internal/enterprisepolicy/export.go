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
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// ExportFormats lists every export format.
var ExportFormats = []string{"toml", "json", "claude-hklm-json", "reg", "plist", "intune-settings-catalog", "version-floor"}

// Export renders connector's DefenseClaw entries in format.
func Export(opts Options, connectorName, format string) ([]byte, error) {
	target, ok := TargetFor(connectorName)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, connectorName)
	}
	return target.Export(opts, strings.ToLower(strings.TrimSpace(format)))
}

// limitedBuffer collects up to limit bytes of command output and discards
// the rest. It never returns a write error, so exec keeps draining the
// child's pipe and a chatty child cannot stall on a full pipe until its
// timeout. Writes and reads are serialized, so one buffer may back both
// Stdout and Stderr and be read while the command still runs.
type limitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	room := l.limit - l.buf.Len()
	if room < len(p) {
		if room > 0 {
			l.buf.Write(p[:room])
		}
		l.truncated = true
		return len(p), nil
	}
	l.buf.Write(p)
	return len(p), nil
}

// Bytes returns a copy of the collected output.
func (l *limitedBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.buf.Bytes()...)
}

func (l *limitedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Truncated reports whether output past the limit was discarded.
func (l *limitedBuffer) Truncated() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.truncated
}

// renderPlist converts a JSON object into an XML property list dictionary,
// for macOS configuration-profile payloads (managed preferences domains).
func renderPlist(jsonDoc []byte) ([]byte, error) {
	value, err := decodeOrdered(jsonDoc)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	buf.WriteString(`<plist version="1.0">` + "\n")
	if err := writePlistValue(&buf, value, 0); err != nil {
		return nil, err
	}
	buf.WriteString("</plist>\n")
	return buf.Bytes(), nil
}

func writePlistValue(buf *bytes.Buffer, value any, indent int) error {
	pad := strings.Repeat("\t", indent)
	escape := func(s string) string {
		var out bytes.Buffer
		_ = xml.EscapeText(&out, []byte(s))
		return out.String()
	}
	switch v := value.(type) {
	case *object:
		buf.WriteString(pad + "<dict>\n")
		for _, key := range v.keys {
			buf.WriteString(pad + "\t<key>" + escape(key) + "</key>\n")
			if err := writePlistValue(buf, v.values[key], indent+1); err != nil {
				return err
			}
		}
		buf.WriteString(pad + "</dict>\n")
	case []any:
		buf.WriteString(pad + "<array>\n")
		for _, item := range v {
			if err := writePlistValue(buf, item, indent+1); err != nil {
				return err
			}
		}
		buf.WriteString(pad + "</array>\n")
	case string:
		buf.WriteString(pad + "<string>" + escape(v) + "</string>\n")
	case bool:
		if v {
			buf.WriteString(pad + "<true/>\n")
		} else {
			buf.WriteString(pad + "<false/>\n")
		}
	case json.Number:
		if strings.ContainsAny(v.String(), ".eE") {
			buf.WriteString(pad + "<real>" + v.String() + "</real>\n")
		} else {
			buf.WriteString(pad + "<integer>" + v.String() + "</integer>\n")
		}
	case nil:
		return errors.New("property lists cannot represent null")
	default:
		return fmt.Errorf("unsupported JSON value %T", value)
	}
	return nil
}
