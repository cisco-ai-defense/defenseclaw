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

	fm "github.com/blacktop/go-foundationmodels"
)

func init() {
	appleFMAvailable = true
	appleFMComplete = completeWithFoundationModels
}

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

	if err := acquireAppleFMSession(ctx); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		releaseAppleFMSession()
		return "", err
	}
	var session *fm.Session
	if call.instructions != "" {
		session = fm.NewSessionWithInstructions(call.instructions)
	} else {
		session = fm.NewSession()
	}
	if session == nil {
		releaseAppleFMSession()
		return "", fmt.Errorf("apple-fm: Foundation Models session was not created")
	}

	// RespondSync does not take a context and cannot be cancelled.
	// The caller stops waiting when ctx ends. This goroutine keeps the
	// session slot until the native call returns, then releases it, so
	// a cancelled waiter is not stuck behind the lock.
	type fmResult struct{ text string }
	done := make(chan fmResult, 1)
	go func() {
		var text string
		func() {
			defer session.Release()
			text = session.Respond(call.prompt, nil)
		}()
		releaseAppleFMSession()
		done <- fmResult{text: text}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-done:
		if res.text == "" {
			return "", fmt.Errorf("apple-fm: Foundation Models returned an empty response")
		}
		if err := appleFMResponseError(res.text); err != nil {
			return "", err
		}
		return res.text, nil
	}
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
