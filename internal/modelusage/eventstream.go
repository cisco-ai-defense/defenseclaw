// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
)

// maxFrameBytes bounds one AWS event-stream frame. Converse and invoke stream
// frames carry a few hundred bytes; a larger frame stops parsing for the call.
const maxFrameBytes = 256 << 10

// eventStreamState reassembles AWS event-stream frames (the binary framing of
// ConverseStream and InvokeModelWithResponseStream) from forwarded bytes.
type eventStreamState struct {
	buf    []byte
	broken bool
}

func (s *StreamParser) writeEventStream(p []byte) {
	es := &s.es
	if es.broken {
		return
	}
	es.buf = append(es.buf, p...)
	for {
		if len(es.buf) < 12 {
			return
		}
		total := int(binary.BigEndian.Uint32(es.buf[0:4]))
		hlen := int(binary.BigEndian.Uint32(es.buf[4:8]))
		if total < 16 || total > maxFrameBytes || hlen < 0 || hlen > total-16 {
			es.broken, es.buf = true, nil
			s.dropped++
			return
		}
		if len(es.buf) < total {
			return
		}
		frame := es.buf[:total]
		headers := frame[12 : 12+hlen]
		payload := frame[12+hlen : total-4]
		s.handleFrame(eventType(headers), payload)
		es.buf = append(es.buf[:0], es.buf[total:]...)
	}
}

// eventType returns the :event-type header (a string header), or "".
func eventType(h []byte) string {
	for len(h) > 0 {
		nl := int(h[0])
		if len(h) < 1+nl+1 {
			return ""
		}
		name := string(h[1 : 1+nl])
		typ := h[1+nl]
		h = h[1+nl+1:]
		var val []byte
		switch typ {
		case 0, 1:
		case 2:
			if len(h) < 1 {
				return ""
			}
			h = h[1:]
		case 3:
			if len(h) < 2 {
				return ""
			}
			h = h[2:]
		case 4:
			if len(h) < 4 {
				return ""
			}
			h = h[4:]
		case 5, 8:
			if len(h) < 8 {
				return ""
			}
			h = h[8:]
		case 9:
			if len(h) < 16 {
				return ""
			}
			h = h[16:]
		case 6, 7:
			if len(h) < 2 {
				return ""
			}
			vl := int(binary.BigEndian.Uint16(h[0:2]))
			if len(h) < 2+vl {
				return ""
			}
			val = h[2 : 2+vl]
			h = h[2+vl:]
		default:
			return ""
		}
		if name == ":event-type" && typ == 7 {
			return string(val)
		}
	}
	return ""
}

func (s *StreamParser) handleFrame(event string, payload []byte) {
	switch s.family {
	case FamilyConverse:
		if event != "metadata" {
			return
		}
		var m struct {
			Usage *converseUsage `json:"usage"`
		}
		if json.Unmarshal(payload, &m) == nil && m.Usage != nil {
			var u Usage
			m.Usage.apply(&u)
			s.replace(u, "")
		}
	case FamilyInvoke:
		if event != "chunk" {
			return
		}
		var c struct {
			Bytes string `json:"bytes"`
		}
		if json.Unmarshal(payload, &c) != nil || c.Bytes == "" {
			return
		}
		raw, err := base64.StdEncoding.DecodeString(c.Bytes)
		if err != nil || len(raw) == 0 || raw[0] != 0x7b {
			return
		}
		s.handleAnthropic(raw)
	}
}
