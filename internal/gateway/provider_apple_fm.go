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
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// apple-fm selects the on-device system model. There is no HTTP endpoint
// and no API key. The call itself is provided by
// github.com/blacktop/go-foundationmodels, which is linked only into a
// darwin/arm64 CGO build (-tags applefm). Release binaries stay
// CGO_ENABLED=0 and report that the bridge is not linked.
const (
	appleFMModelPrefix           = "apple-fm/"
	appleFMUnderscoreModelPrefix = "apple_fm/"
)

var errAppleFMNotLinked = errors.New("apple-fm requires a gateway built with CGO_ENABLED=1 GOARCH=arm64 -tags applefm on macOS 26 or later, using github.com/blacktop/go-foundationmodels")

// errAppleFMGenerationLimits is returned when a request asks for controls
// the pinned bridge cannot apply. SessionCompat.Respond ignores
// GenerationOptions and calls the optionless native response.
var errAppleFMGenerationLimits = errors.New("apple-fm: max_tokens and temperature are not applied by github.com/blacktop/go-foundationmodels v0.1.8; omit them")

type appleFMCall struct {
	instructions string
	prompt       string
}

// appleFMAvailable is true only in the cgo build that links the
// Foundation Models bridge. Tests flip it to exercise routing without
// the on-device model.
var appleFMAvailable bool

// appleFMComplete runs one on-device completion. The stub reports that
// this binary was not built with the bridge; the cgo file replaces it.
var appleFMComplete = func(context.Context, appleFMCall) (string, error) {
	return "", errAppleFMNotLinked
}

func isAppleFMProvider(providerType, model string) bool {
	switch strings.ToLower(strings.TrimSpace(providerType)) {
	case "apple-fm", "apple_fm":
		return true
	case "":
		// A model prefix selects Apple FM only when no role or overlay
		// provider was specified. An explicit family such as openai wins.
		return isAppleFMModel(model)
	default:
		return false
	}
}

func isAppleFMModel(model string) bool {
	return appleFMPrefixLen(model) > 0
}

func appleFMPrefixLen(model string) int {
	lower := strings.ToLower(strings.TrimSpace(model))
	switch {
	case strings.HasPrefix(lower, appleFMModelPrefix):
		return len(appleFMModelPrefix)
	case strings.HasPrefix(lower, appleFMUnderscoreModelPrefix):
		return len(appleFMUnderscoreModelPrefix)
	default:
		return 0
	}
}

func canonicalAppleFMModel(model string) string {
	model = strings.TrimSpace(model)
	if n := appleFMPrefixLen(model); n > 0 {
		model = strings.TrimSpace(model[n:])
	}
	if model == "" || strings.EqualFold(model, "system") {
		return "apple-fm/system"
	}
	return "apple-fm/" + model
}

// appleFMResponseError turns the pinned bridge's swallowed native
// failure into an error. RespondSync catches a model error and returns
// the text "Error: ..."; SessionCompat.Respond then reports success.
func appleFMResponseError(text string) error {
	const prefix = "Error: "
	if !strings.HasPrefix(text, prefix) {
		return nil
	}
	detail := strings.TrimSpace(strings.TrimPrefix(text, prefix))
	if detail == "" {
		return errors.New("apple-fm: Foundation Models returned an error")
	}
	return fmt.Errorf("apple-fm: Foundation Models error: %s", detail)
}

func newAppleFMProvider(model string) (LLMProvider, error) {
	if !appleFMAvailable {
		return nil, errAppleFMNotLinked
	}
	return &appleFMProvider{model: canonicalAppleFMModel(model)}, nil
}

type appleFMProvider struct {
	model string
}

func (p *appleFMProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	call, err := appleFMCallFromRequest(req)
	if err != nil {
		return nil, err
	}
	content, err := appleFMComplete(ctx, call)
	if err != nil {
		return nil, err
	}
	finish := "stop"
	return &ChatResponse{
		ID:      fmt.Sprintf("apple-fm-%d", time.Now().UnixNano()),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   p.model,
		Choices: []ChatChoice{{
			Message:      &ChatMessage{Role: "assistant", Content: content},
			FinishReason: &finish,
		}},
	}, nil
}

func (p *appleFMProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
	resp, err := p.ChatCompletion(ctx, req)
	if err != nil {
		return nil, err
	}
	if chunkCb != nil && len(resp.Choices) > 0 && resp.Choices[0].Message != nil {
		finish := "stop"
		chunkCb(StreamChunk{
			ID:      resp.ID,
			Object:  "chat.completion.chunk",
			Created: resp.Created,
			Model:   resp.Model,
			Choices: []ChatChoice{{
				Delta:        &ChatMessage{Role: "assistant", Content: resp.Choices[0].Message.Content},
				FinishReason: &finish,
			}},
		})
	}
	return resp.Usage, nil
}

func appleFMCallFromRequest(req *ChatRequest) (appleFMCall, error) {
	call := appleFMCall{}
	if req == nil {
		return call, nil
	}
	if req.MaxTokens != nil || req.Temperature != nil {
		return call, errAppleFMGenerationLimits
	}
	var systemParts []string
	var turns []appleFMTurn
	for _, message := range req.Messages {
		text := strings.TrimSpace(message.Content)
		if text == "" {
			continue
		}
		role := strings.ToLower(strings.TrimSpace(message.Role))
		if role == "system" || role == "developer" {
			systemParts = append(systemParts, text)
			continue
		}
		if role == "" {
			role = "user"
		}
		turns = append(turns, appleFMTurn{role: role, text: text})
	}
	call.instructions = strings.Join(systemParts, "\n\n")
	call.prompt = appleFMPromptFromTurns(turns)
	if call.prompt == "" {
		call.prompt = call.instructions
		call.instructions = ""
	}
	return call, nil
}

type appleFMTurn struct {
	role string
	text string
}

// appleFMPromptFromTurns keeps a single user turn as plain text. A
// longer transcript names each role so an assistant reply is not sent
// to the model as the next user prompt. The pinned session API accepts
// one instruction string and one prompt, so the history is inlined.
func appleFMPromptFromTurns(turns []appleFMTurn) string {
	if len(turns) == 0 {
		return ""
	}
	if len(turns) == 1 && turns[0].role == "user" {
		return turns[0].text
	}
	var b strings.Builder
	for i, turn := range turns {
		if i > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(appleFMRoleLabel(turn.role))
		b.WriteString(":\n")
		b.WriteString(turn.text)
	}
	return b.String()
}

func appleFMRoleLabel(role string) string {
	switch role {
	case "user":
		return "User"
	case "assistant":
		return "Assistant"
	default:
		if role == "" {
			return "User"
		}
		return role
	}
}
