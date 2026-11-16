// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/jsonc"
)

// ErrOpenClawConfigSyntax marks an openclaw.json that is neither JSON nor
// JSON5. The file is the user's to fix; no agent holds it open.
var ErrOpenClawConfigSyntax = errors.New("openclaw.json is not valid JSON5")

type openClawConfigSyntaxError struct {
	path  string
	cause *jsonc.SyntaxError
}

func (e *openClawConfigSyntaxError) Error() string {
	return fmt.Sprintf("%s is not valid JSON5: %v (OpenClaw reads this file as JSON5 too: fix that spot in the file)", e.path, e.cause)
}

func (e *openClawConfigSyntaxError) Unwrap() []error {
	return []error{e.cause, ErrOpenClawConfigSyntax}
}

// parseOpenClawConfig is the one reader of openclaw.json in this package.
// OpenClaw reads the file as JSON5 (comments, trailing commas, hexadecimal
// numbers, bare keys, single quotes), so a reader that took only strict JSON
// refused a file OpenClaw runs on and stopped the gateway from starting
// (GAP-0907). The setup patch, the uninstall and the residue checks all come
// here. A document that is not JSON5 names the file, the line and column, and
// the text at fault.
func parseOpenClawConfig(configPath string, data []byte) (map[string]interface{}, error) {
	cfg := map[string]interface{}{}
	if err := jsonc.UnmarshalJSON5(data, &cfg); err != nil {
		var syntax *jsonc.SyntaxError
		if errors.As(err, &syntax) {
			return nil, &openClawConfigSyntaxError{path: configPath, cause: syntax}
		}
		return nil, fmt.Errorf("parse %s: %w", configPath, err)
	}
	if cfg == nil {
		cfg = map[string]interface{}{}
	}
	return cfg, nil
}
