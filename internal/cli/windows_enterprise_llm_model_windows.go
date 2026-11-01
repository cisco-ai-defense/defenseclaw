// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// appendWindowsEnterpriseLLMModelWarning warns, in status, verify and
// ensure, when the installed admin config's llm.model is not a model id the
// gateway can route (GAP-0172): Setup /ensure applied llm.model "luna" or
// "not-a-model" without a word, and every judge call then fell back. A
// config the reader cannot parse adds nothing here (other checks report it).
func appendWindowsEnterpriseLLMModelWarning(result *enterprisestatus.Result) {
	body, err := readWindowsStandaloneScannerConfig()
	if err != nil {
		return
	}
	var document struct {
		LLM config.LLMConfig `yaml:"llm"`
	}
	if yaml.Unmarshal(trimWindowsJSONBOM(body), &document) != nil {
		return
	}
	if message := document.LLM.ModelIDProblem("llm.model"); message != "" {
		result.AddWarning(enterprisestatus.CodeLLMModelUnroutable, message+"; then run Setup /ensure with the corrected config")
	}
}
