// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package configwrite

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestApplyComputedChecksCASAndManagedBeforeCallback(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	for _, tc := range []struct {
		name, source, expect string
		want                 error
	}{
		{"stale hash", "guardrail: {mode: observe}\n", strings.Repeat("0", 64), ErrConflict},
		{"managed", "deployment_mode: managed_enterprise\nenterprise: {profile: standalone}\n", "", ErrManaged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestConfig(t, tc.source)
			before, _ := os.ReadFile(path)
			called := false
			_, err := ApplyComputed(context.Background(), path, func([]byte) ([]Change, error) {
				called = true
				return []Change{{Path: "guardrail.mode", Value: "action"}}, nil
			}, Options{Actor: "cli:test", ExpectSHA256: tc.expect})
			if !errors.Is(err, tc.want) || called {
				t.Fatalf("ApplyComputed = %v, called = %v; want %v before callback", err, called, tc.want)
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(before) {
				t.Fatal("refused callback changed the document")
			}
			if _, err := ReadGenerationState(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refused callback created a generation: %v", err)
			}
		})
	}
}

func TestApplyComputedValidatesCandidateAndKeepsAcceptedGeneration(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	path := writeTestConfig(t, "# retained note\nguardrail: {mode: observe}\n")
	opt := Options{Actor: "cli:test"}
	accepted, err := ApplyComputed(context.Background(), path, func(current []byte) ([]Change, error) {
		if !strings.Contains(string(current), "mode: observe") {
			t.Fatalf("callback did not receive current source: %s", current)
		}
		// Mutating the callback's copy cannot affect the committed source.
		clear(current)
		return []Change{{Path: "guardrail.mode", Value: "action"}}, nil
	}, opt)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if !strings.Contains(string(before), "# retained note") {
		t.Fatal("callback corrupted the source document")
	}
	_, err = ApplyComputed(context.Background(), path, func([]byte) ([]Change, error) {
		return []Change{{Path: "guardrail.mode", Value: "invalid"}}, nil
	}, opt)
	if err == nil {
		t.Fatal("invalid computed candidate was accepted")
	}
	after, _ := os.ReadFile(path)
	state, stateErr := ReadGenerationState(path)
	if string(after) != string(before) || stateErr != nil || state.Generation != accepted.Generation || state.ConfigSHA256 != accepted.SHA256 {
		t.Fatalf("rejection changed the accepted document or generation: %+v, %v", state, stateErr)
	}
}
