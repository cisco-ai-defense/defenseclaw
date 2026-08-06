// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package guardrail

import "testing"

func TestLoadRulePackRejectsSensitiveToolNameWhitespace(t *testing.T) {
	dir := t.TempDir()
	writeRulePackFile(t, dir, "sensitive-tools.yaml", `version: 1
tools:
  - name: ' users_list '
    result_inspection: true
    judge_result: false
`)

	_, err := LoadRulePack(dir)
	packErr := requireRulePackError(t, err, "validation")
	if packErr.Path != "sensitive-tools.yaml" {
		t.Fatalf("error path = %q, want sensitive-tools.yaml", packErr.Path)
	}
}
