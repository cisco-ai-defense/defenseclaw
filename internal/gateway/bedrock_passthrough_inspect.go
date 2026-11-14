// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// Bedrock's native model API (GAP-0098). InvokeModel answers in the shape
// of the model family (an Anthropic Messages body for Claude), and
// InvokeModelWithResponseStream and ConverseStream answer in the binary
// AWS eventstream. The passthrough proxy inspects both: the body by its
// family, the stream frame by frame while the bytes go to the caller
// unchanged.

// bedrockStreamingPath reports a Bedrock path that answers with a stream.
func bedrockStreamingPath(p string) bool {
	return strings.HasSuffix(p, "/invoke-with-response-stream") || strings.HasSuffix(p, "/converse-stream")
}

// bedrockInvokeText is the assistant text of an InvokeModel body: the
// Anthropic Messages shape (Claude) or the Nova, Llama, Mistral and Cohere
// shapes. "" when the body has none.
func bedrockInvokeText(body []byte) string {
	if t := extractPassthroughResponseContent(body, "anthropic"); t != "" {
		return t
	}
	var other struct {
		Generation string `json:"generation"` // Meta Llama
		Outputs    []struct {
			Text string `json:"text"`
		} `json:"outputs"` // Mistral
		Generations []struct {
			Text string `json:"text"`
		} `json:"generations"` // Cohere
		Completion string `json:"completion"` // Anthropic text completions
	}
	if json.Unmarshal(body, &other) != nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(other.Generation)
	sb.WriteString(other.Completion)
	for _, o := range other.Outputs {
		sb.WriteString(o.Text)
	}
	for _, g := range other.Generations {
		sb.WriteString(g.Text)
	}
	return sb.String()
}

// bedrockStreamMaxFrame bounds one eventstream message the inspector holds.
const bedrockStreamMaxFrame = 16 << 20

// bedrockEventStreamText decodes an AWS eventstream as it arrives and
// returns the assistant text of each whole message. It keeps only the
// bytes of the message not yet complete. A malformed stream stops the
// decoding (the bytes still reach the caller); Broken reports it.
type bedrockEventStreamText struct {
	buf    []byte
	dec    *eventstream.Decoder
	broken bool
	model  string
}

func newBedrockEventStreamText() *bedrockEventStreamText {
	return &bedrockEventStreamText{dec: eventstream.NewDecoder()}
}

// Broken reports a stream the decoder could not frame.
func (s *bedrockEventStreamText) Broken() bool { return s.broken }

// Pending is the bytes of the message not yet complete: their text is not
// read yet.
func (s *bedrockEventStreamText) Pending() int { return len(s.buf) }

// Model is the model the stream named (Anthropic message_start), if any.
func (s *bedrockEventStreamText) Model() string { return s.model }

// Feed takes the next bytes of the stream and returns the text of the
// messages they complete.
func (s *bedrockEventStreamText) Feed(p []byte) string {
	if s.broken {
		return ""
	}
	s.buf = append(s.buf, p...)
	var sb strings.Builder
	for len(s.buf) >= 12 {
		total := int(binary.BigEndian.Uint32(s.buf[:4]))
		if total < 16 || total > bedrockStreamMaxFrame {
			s.broken, s.buf = true, nil
			break
		}
		if len(s.buf) < total {
			break
		}
		msg, err := s.dec.Decode(bytes.NewReader(s.buf[:total]), nil)
		s.buf = s.buf[total:]
		if err != nil {
			s.broken, s.buf = true, nil
			break
		}
		sb.WriteString(s.messageText(msg))
	}
	if len(s.buf) == 0 {
		s.buf = nil
	}
	return sb.String()
}

func (s *bedrockEventStreamText) messageText(msg eventstream.Message) string {
	var mtype, etype string
	for _, h := range msg.Headers {
		switch h.Name {
		case ":message-type":
			mtype = h.Value.String()
		case ":event-type":
			etype = h.Value.String()
		}
	}
	if mtype != "event" {
		return ""
	}
	switch etype {
	case "chunk":
		// InvokeModelWithResponseStream: {"bytes":"<base64 model event>"};
		// for Claude the event is an Anthropic stream event.
		var c struct {
			Bytes string `json:"bytes"`
		}
		if json.Unmarshal(msg.Payload, &c) != nil || c.Bytes == "" {
			return ""
		}
		inner, err := base64.StdEncoding.DecodeString(c.Bytes)
		if err != nil {
			return ""
		}
		if s.model == "" {
			var start struct {
				Message struct {
					Model string `json:"model"`
				} `json:"message"`
			}
			if json.Unmarshal(inner, &start) == nil {
				s.model = start.Message.Model
			}
		}
		if t := extractSSEChunkText(string(inner), "anthropic"); t != "" {
			return t
		}
		var other struct {
			Generation string `json:"generation"`
			OutputText string `json:"outputText"`
			Completion string `json:"completion"`
		}
		if json.Unmarshal(inner, &other) == nil {
			return other.Generation + other.OutputText + other.Completion
		}
	case "contentBlockDelta":
		// ConverseStream: the event type names the frame, the payload is
		// {"contentBlockIndex":0,"delta":{"text":"..."}}.
		var d struct {
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if json.Unmarshal(msg.Payload, &d) == nil {
			return d.Delta.Text
		}
	}
	return ""
}
