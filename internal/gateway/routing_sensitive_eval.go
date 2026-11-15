// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// SensitiveEvalChecker runs the routing.sensitive.check of cfg exactly as
// the gateway does (the same checker, question, input bound and timeout),
// for the S12 routing harness (benchmarks/routing). nil when cfg turns the
// check off or names no usable decision model.
type SensitiveEvalChecker struct {
	cfg     *config.Config
	checker engine.SensitiveChecker
}

// NewSensitiveEvalChecker builds the checker of cfg; dotenv is the .env
// file key references may name ("" for none).
func NewSensitiveEvalChecker(cfg *config.Config, dotenv string) *SensitiveEvalChecker {
	r := newEngineRouter(cfg, nil, dotenv)
	c := r.sensitiveCheckerFor(cfg)
	if c == nil {
		return nil
	}
	return &SensitiveEvalChecker{cfg: cfg, checker: c}
}

// Name is the checker source label (decision_model or judge).
func (s *SensitiveEvalChecker) Name() string { return s.checker.Name() }

// Check asks the question about the chat messages: sensitive, whether the
// bounded input was truncated, and the error of a check that could not
// answer (engine.ClassifierError with a closed code).
func (s *SensitiveEvalChecker) Check(ctx context.Context, messages []ChatMessage) (sensitive, truncated bool, err error) {
	sc := s.cfg.Routing.Sensitive
	text, truncated := sensitiveCheckInput(&ModelRouterInput{Messages: messages}, sc.EffectiveMaxBytes())
	cctx, cancel := context.WithTimeout(ctx, time.Duration(sc.EffectiveCheckTimeoutMs())*time.Millisecond)
	defer cancel()
	ok, err := s.checker.Check(cctx, engine.SensitiveInput{Text: text, Truncated: truncated, Definition: sc.Definition})
	return ok, truncated, err
}
