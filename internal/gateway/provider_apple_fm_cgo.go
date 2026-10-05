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

//go:build darwin && arm64 && cgo && applefm

package gateway

import (
	"context"
	"fmt"
	"sync"

	fm "github.com/blacktop/go-foundationmodels"
)

func init() {
	appleFMAvailable = true
	appleFMComplete = completeWithFoundationModels
}

// Sessions are created per call and serialized. The bridge keeps process
// global tool state, and the judge runs injection, PII, and exfil checks
// at the same time.
var appleFMSessionMu sync.Mutex

func completeWithFoundationModels(ctx context.Context, call appleFMCall) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := appleFMAvailabilityError(); err != nil {
		return "", err
	}
	if call.prompt == "" {
		return "", fmt.Errorf("apple-fm: messages is required")
	}

	appleFMSessionMu.Lock()
	defer appleFMSessionMu.Unlock()

	if err := ctx.Err(); err != nil {
		return "", err
	}
	var session *fm.Session
	if call.instructions != "" {
		session = fm.NewSessionWithInstructions(call.instructions)
	} else {
		session = fm.NewSession()
	}
	if session == nil {
		return "", fmt.Errorf("apple-fm: Foundation Models session was not created")
	}
	defer session.Release()

	// Respond ignores GenerationOptions and calls RespondSync. Requests
	// that set max_tokens or temperature are rejected before this point.
	text := session.Respond(call.prompt, nil)
	if text == "" {
		return "", fmt.Errorf("apple-fm: Foundation Models returned an empty response")
	}
	if err := appleFMResponseError(text); err != nil {
		return "", err
	}
	return text, nil
}

func appleFMAvailabilityError() error {
	switch fm.CheckModelAvailability() {
	case fm.ModelAvailable:
		return nil
	case fm.ModelUnavailableAINotEnabled:
		return fmt.Errorf("apple-fm: Apple Intelligence is not enabled")
	case fm.ModelUnavailableNotReady:
		return fmt.Errorf("apple-fm: the on-device model is not ready")
	case fm.ModelUnavailableDeviceNotEligible:
		return fmt.Errorf("apple-fm: this Mac cannot run Apple Foundation Models")
	default:
		return fmt.Errorf("apple-fm: Apple Foundation Models are unavailable")
	}
}
