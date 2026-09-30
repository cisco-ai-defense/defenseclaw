// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"

	"github.com/klauspost/compress/zstd"
)

func isZstdBody(body []byte) bool {
	return len(body) >= 4 && body[0] == 0x28 && body[1] == 0xb5 && body[2] == 0x2f && body[3] == 0xfd
}

func decompressZstd(body []byte) ([]byte, error) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.DecodeAll(body, nil)
}

// patchModelInBody replaces the "model" field in the JSON body with the given value.
func patchModelInBody(body []byte, model string) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	if raw == nil {
		return body
	}
	modelJSON, err := json.Marshal(model)
	if err != nil {
		return body
	}
	raw["model"] = modelJSON
	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}
