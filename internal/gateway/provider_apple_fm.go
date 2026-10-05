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
const appleFMModelPrefix = "apple-fm/"

var errAppleFMNotLinked = errors.New("apple-fm requires a gateway built with CGO_ENABLED=1 GOARCH=arm64 -tags applefm on macOS 26 or later, using github.com/blacktop/go-foundationmodels")

type appleFMCall struct {
	instructions string
	prompt       string
	maxTokens    int
	temperature  float32
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
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(model)), appleFMModelPrefix)
}

func canonicalAppleFMModel(model string) string {
	model = strings.TrimSpace(model)
	lower := strings.ToLower(model)
	if strings.HasPrefix(lower, appleFMModelPrefix) {
		name := strings.TrimSpace(model[len(appleFMModelPrefix):])
		if name == "" || strings.EqualFold(name, "system") {
			return "apple-fm/system"
		}
		return "apple-fm/" + name
	}
	if model == "" || strings.EqualFold(model, "system") {
		return "apple-fm/system"
	}
	return "apple-fm/" + model
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
	call := appleFMCallFromRequest(req)
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

func appleFMCallFromRequest(req *ChatRequest) appleFMCall {
	call := appleFMCall{}
	if req == nil {
		return call
	}
	var systemParts []string
	var userParts []string
	for _, message := range req.Messages {
		text := strings.TrimSpace(message.Content)
		if text == "" {
			continue
		}
		if strings.EqualFold(message.Role, "system") {
			systemParts = append(systemParts, text)
			continue
		}
		userParts = append(userParts, text)
	}
	call.instructions = strings.Join(systemParts, "\n\n")
	call.prompt = strings.Join(userParts, "\n\n")
	if call.prompt == "" {
		call.prompt = call.instructions
		call.instructions = ""
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		call.maxTokens = *req.MaxTokens
	}
	if req.Temperature != nil {
		call.temperature = float32(*req.Temperature)
	}
	return call
}
