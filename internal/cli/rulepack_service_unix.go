// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// rulePackServiceReadProblem names why an enterprise host's gateway service
// account could not read the pack at dir, or "" (also on hosts without one).
func rulePackServiceReadProblem(ctx context.Context, dir string) string {
	if ctx == nil {
		ctx = context.Background()
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	env, err := enterpriseunix.NewEnv(enterpriseunix.CurrentGOOS(), appVersion)
	if err != nil {
		return ""
	}
	return env.RulePackServiceReadProblem(ctx, abs)
}
