//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const claudeHKLMPolicyKey = `SOFTWARE\Policies\ClaudeCode`

// platformClaudeHigherSources reads the HKLM policy value MDM/GPO deliver,
// which outranks the Program Files managed settings files.
func platformClaudeHigherSources(Options) ([]higherClaudeSource, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, claudeHKLMPolicyKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open HKLM\\%s: %w", claudeHKLMPolicyKey, err)
	}
	defer key.Close()
	value, _, err := key.GetStringValue("Settings")
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read HKLM\\%s\\Settings: %w", claudeHKLMPolicyKey, err)
	}
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	if len(value) > policyFileLimit {
		return nil, fmt.Errorf("HKLM\\%s\\Settings exceeds %d bytes", claudeHKLMPolicyKey, policyFileLimit)
	}
	doc, err := decodeOrderedObject([]byte(value))
	if err != nil {
		return nil, fmt.Errorf("HKLM\\%s\\Settings is not a JSON object (Claude Code refuses to start): %w", claudeHKLMPolicyKey, err)
	}
	return []higherClaudeSource{{name: `HKLM\` + claudeHKLMPolicyKey + `\Settings`, doc: doc}}, nil
}
