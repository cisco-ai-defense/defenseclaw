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
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

// GAP-1673: the provider error users see in status, doctor and the gateway
// health line names the provider, not the internal "bifrost" library.
func TestBifrostErrorToGoNamesTheProvider(t *testing.T) {
	code := 400
	withCode := &schemas.BifrostError{StatusCode: &code, Error: &schemas.ErrorField{Message: "The provided model identifier is invalid."}}
	noCode := &schemas.BifrostError{Error: &schemas.ErrorField{Message: "failed to retrieve aws credentials"}}
	for _, tc := range []struct {
		provider schemas.ModelProvider
		err      *schemas.BifrostError
		want     string
	}{
		{schemas.Bedrock, withCode, "Bedrock returned 400: The provided model identifier is invalid."},
		{schemas.Bedrock, noCode, "Bedrock request failed: failed to retrieve aws credentials"},
		{schemas.Anthropic, withCode, "Anthropic returned 400: The provided model identifier is invalid."},
		{schemas.OpenAI, &schemas.BifrostError{}, "OpenAI request failed: unknown error"},
	} {
		if got := bifrostErrorToGo(tc.provider, tc.err).Error(); got != tc.want {
			t.Errorf("bifrostErrorToGo(%s) = %q, want %q", tc.provider, got, tc.want)
		}
	}
	if bifrostErrorToGo(schemas.Bedrock, nil) != nil {
		t.Error("nil error must stay nil")
	}
}
