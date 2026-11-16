// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"fmt"
	"io"
)

// PerUserPluginRequest is the JSON request the OpenCode and Amp per-user
// plugins write on stdin to hook-post. The gateway CLI and the small
// defenseclaw-hook-post helper read the same request and answer with
// PerUserHookReply as JSON.
type PerUserPluginRequest struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// MaxPerUserPluginRequest bounds a plugin request on stdin.
const MaxPerUserPluginRequest = 6 << 20

// ReadPerUserPluginRequest decodes one bounded plugin request.
func ReadPerUserPluginRequest(source io.Reader) (PerUserPluginRequest, error) {
	input, err := io.ReadAll(io.LimitReader(source, MaxPerUserPluginRequest+1))
	if err != nil {
		return PerUserPluginRequest{}, err
	}
	return DecodePerUserPluginRequest(input)
}

// DecodePerUserPluginRequest decodes a plugin request already read.
func DecodePerUserPluginRequest(input []byte) (PerUserPluginRequest, error) {
	if len(input) > MaxPerUserPluginRequest {
		return PerUserPluginRequest{}, fmt.Errorf("plugin hook input is too large")
	}
	var request PerUserPluginRequest
	if err := json.Unmarshal(input, &request); err != nil {
		return PerUserPluginRequest{}, fmt.Errorf("decode plugin hook input: %w", err)
	}
	return request, nil
}
