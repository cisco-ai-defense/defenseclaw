// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"io"
)

// validUniqueGatewayResponse checks the entire bounded response before any
// field can be used as a tool verdict. encoding/json's map decoder accepts
// duplicate keys, selecting the last one; that is ambiguous for an action.
func validUniqueGatewayResponse(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	if !uniqueGatewayJSONObject(decoder, 0) {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

const maxGatewayResponseJSONDepth = 128

func uniqueGatewayJSONValue(decoder *json.Decoder, depth int) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return true
	}
	if depth >= maxGatewayResponseJSONDepth {
		return false
	}
	switch delim {
	case '{':
		return uniqueGatewayJSONObject(decoder, depth+1)
	case '[':
		for decoder.More() {
			if !uniqueGatewayJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}

func uniqueGatewayJSONObject(decoder *json.Decoder, depth int) bool {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := keyToken.(string)
		if !ok {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		if !uniqueGatewayJSONValue(decoder, depth) {
			return false
		}
	}
	end, err := decoder.Token()
	return err == nil && end == json.Delim('}')
}
