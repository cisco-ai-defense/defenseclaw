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

package extproc

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"io"
	"mime"
	"strings"
	"unicode/utf8"
)

// Why a buffered body can't be read the way its origin will read it
// (GAP-0044). The callout inspects what the origin sees, so a body it
// can't decode is never treated as "no tool call".
const (
	unreadableEncoding = "content_encoding"
	unreadableCharset  = "charset"
	unreadableUTF8     = "not_utf8"
	unreadableJSON     = "not_json"
)

// maxContentEncodings bounds the encodings a body may stack.
const maxContentEncodings = 2

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// decodeBody returns body as its origin reads it: the Content-Encoding
// layers MCP clients use (gzip, x-gzip, deflate; identity) undone, at most
// max bytes, and a UTF-8 byte order mark dropped. why is
// unreadableEncoding for any other encoding or a corrupt one, whyOverCap
// for a decoded body over max, and unreadableCharset for a declared
// charset other than UTF-8 (or US-ASCII).
func decodeBody(body []byte, contentEncoding, contentType string, max int64) (out []byte, why string) {
	out = body
	if ce := strings.TrimSpace(contentEncoding); ce != "" {
		layers := strings.Split(ce, ",")
		if len(layers) > maxContentEncodings {
			return nil, unreadableEncoding
		}
		// The last encoding listed was applied last.
		for i := len(layers) - 1; i >= 0; i-- {
			var r io.Reader
			var err error
			switch strings.ToLower(strings.TrimSpace(layers[i])) {
			case "identity", "":
				continue
			case "gzip", "x-gzip":
				r, err = gzip.NewReader(bytes.NewReader(out))
			case "deflate":
				r, err = zlib.NewReader(bytes.NewReader(out))
			default:
				return nil, unreadableEncoding
			}
			if err != nil {
				return nil, unreadableEncoding
			}
			dec, err := io.ReadAll(io.LimitReader(r, max+1))
			if err != nil {
				return nil, unreadableEncoding
			}
			if int64(len(dec)) > max {
				return nil, whyOverCap
			}
			out = dec
		}
	}
	if contentType != "" {
		if _, params, err := mime.ParseMediaType(contentType); err == nil {
			switch cs := strings.ToLower(strings.TrimSpace(params["charset"])); cs {
			case "", "utf-8", "utf8", "us-ascii":
			default:
				return nil, unreadableCharset
			}
		}
	}
	return bytes.TrimPrefix(out, utf8BOM), ""
}

// jsonRPCReadable reports why an MCP body is not JSON the callout can
// parse, or "": an empty body has nothing to parse. UTF-16 or UTF-32
// without a charset is not UTF-8; NaN, Infinity and other JSON
// extensions some servers accept are not JSON.
func jsonRPCReadable(body []byte) string {
	b := bytes.TrimSpace(body)
	switch {
	case len(b) == 0:
		return ""
	case !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0:
		return unreadableUTF8
	case !json.Valid(b):
		return unreadableJSON
	}
	return ""
}

// unreadable applies GAP-0044 to a body on an inspected host that can't be
// decoded or parsed: refused when the failure mode is closed (the managed
// default), an alert when open. It is never a silent allow.
func (e *Engine) unreadable(v Verdict, why string) Verdict {
	if e.cfg.FailureMode == FailureClosed {
		reason := "DefenseClaw inspects the requests sent to this host, and this one's body can't be read"
		switch why {
		case unreadableEncoding:
			reason += " (its Content-Encoding is not gzip or deflate, or is corrupt)."
		case unreadableCharset:
			reason += " (its charset is not UTF-8)."
		case unreadableUTF8:
			reason += " (it is not UTF-8 text)."
		case unreadableJSON:
			reason += " (it is not valid JSON-RPC)."
		default:
			reason += "."
		}
		return deny(v, CategoryBodyUninspected, sourceCallout, why, reason)
	}
	v.Alert = true
	v.Findings = append(v.Findings, "body_unreadable:"+why)
	return v
}
