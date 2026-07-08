// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "encoding/json"

// loadGlobalModelRouter returns the globally registered ModelRouter (or nil).
func loadGlobalModelRouter() ModelRouter {
	return globalModelRouter
}

// patchModelInBody replaces the "model" field in the JSON body with the given value.
func patchModelInBody(body []byte, model string) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
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
