// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

// scannerRuntimeName is the standalone Windows enterprise payload's scanner
// runtime (cmd/defenseclaw-scanners): one executable that carries the Python
// scanners and is told which one to run by its first argument.
const scannerRuntimeName = "defenseclaw-scanners"

// usesScannerRuntime reports whether binary is the embedded scanner runtime.
func usesScannerRuntime(binary string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(binary)))
	return base == scannerRuntimeName || base == scannerRuntimeName+".exe"
}

// runtimeEnv is the MCP scan's environment under the embedded runtime: the
// skill scanner's allowlist plus the judge and AI Defense settings derived
// from config (the runtime reads no config of its own).
func (s *MCPScanner) runtimeEnv() []string {
	llm := s.LLM
	derived := map[string]string{
		"NO_COLOR":                         "1",
		"TERM":                             "dumb",
		"DEFENSECLAW_SCANNER_LLM_MODEL":    liteLLMModel(llm),
		"DEFENSECLAW_SCANNER_LLM_PROVIDER": strings.TrimSpace(llm.Provider),
		"DEFENSECLAW_SCANNER_LLM_API_KEY":  llm.ResolvedAPIKey(),
		"DEFENSECLAW_SCANNER_LLM_BASE_URL": strings.TrimSpace(llm.BaseURL),
		"DEFENSECLAW_SCANNER_LLM_REGION":   strings.TrimSpace(llm.Region),
		"DEFENSECLAW_SCANNER_AID_API_KEY":  s.CiscoAIDefense.ResolvedAPIKey(),
		"DEFENSECLAW_SCANNER_AID_ENDPOINT": strings.TrimSpace(s.CiscoAIDefense.Endpoint),
	}
	if llm.Bedrock != nil && strings.TrimSpace(llm.Bedrock.Region) != "" {
		derived["DEFENSECLAW_SCANNER_LLM_REGION"] = strings.TrimSpace(llm.Bedrock.Region)
	}
	if region := derived["DEFENSECLAW_SCANNER_LLM_REGION"]; region != "" {
		derived["AWS_REGION"] = region
	}
	env := make([]string, 0, 32)
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		upper := strings.ToUpper(name)
		if v, set := derived[upper]; set && v != "" {
			continue
		}
		if skillScannerEnvPassthrough[upper] || hasAnyPrefix(upper, skillScannerEnvPassthroughPrefixes) {
			env = append(env, kv)
		}
	}
	for name, value := range derived {
		if value != "" {
			env = append(env, name+"="+value)
		}
	}
	return env
}
