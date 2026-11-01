// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// SettingError is a runtime-loader refusal of one setting (a guardrail
// profile, its sandbox section, the openshell section), with the YAML path it
// is about and the loader's own rule text. The text names configured names
// (profiles, connectors, credentials), never a secret value, so `config
// validate` can show it. It replaces a typed-error-free string that
// `config-v8 validate` and Windows Setup reduced to "configuration could not
// be compiled safely" at "$" (GAP-0337, GAP-0323).
type SettingError struct {
	// Path is the YAML path of the setting, without the leading "$":
	// guardrail.profiles["contractors"].
	Path string
	// bare marks a cause that already starts with its own path: Error is the
	// cause as it is.
	bare  bool
	cause error
}

func (e *SettingError) Error() string {
	if e == nil || e.cause == nil {
		return ""
	}
	if e.bare {
		return e.cause.Error()
	}
	return e.Path + ": " + e.cause.Error()
}

func (e *SettingError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Detail is the rule text on one line: the cause without the path, and a
// joined cause's lines separated by "; ".
func (e *SettingError) Detail() string {
	if e == nil || e.cause == nil {
		return ""
	}
	detail := strings.TrimSpace(e.cause.Error())
	if e.bare {
		// settingErrorAt preserves the loader's path in Error(), while the
		// structured diagnostic carries it separately from its rule text.
		detail = strings.TrimPrefix(detail, e.Path+": ")
	}
	lines := strings.Split(detail, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return strings.Join(lines, "; ")
}

// profileSettingError is err about guardrail.profiles[name], worded as before.
func profileSettingError(name string, err error) error {
	if err == nil {
		return nil
	}
	return &SettingError{Path: "guardrail.profiles[" + strconv.Quote(name) + "]", cause: err}
}

// enterpriseSettingPath finds the enterprise.* setting a refusal names.
var enterpriseSettingPath = lazyregexp.New(`\benterprise(?:\.[a-z0-9_]+)+`)

// enterpriseSettingError makes a refusal of the enterprise block a
// SettingError at the first enterprise.* setting its text names, so `config
// validate` and Windows Setup show the setting and the rule instead of
// "configuration could not be compiled safely" at "$" (GAP-0553: a default
// OpenShell port that collides with gateway.api_port was refused that way).
// A refusal that already carries its own path, or names no setting, is
// returned as it is.
func enterpriseSettingError(err error) error {
	if err == nil {
		return nil
	}
	var semantic *V8SemanticError
	var setting *SettingError
	if errors.As(err, &semantic) || errors.As(err, &setting) {
		return err
	}
	path := enterpriseSettingPath.FindString(err.Error())
	if path == "" {
		return err
	}
	return settingErrorAt(path, err)
}

// settingErrorAt is err about path, whose text already names the path.
func settingErrorAt(path string, err error) error {
	if err == nil {
		return nil
	}
	return &SettingError{Path: path, bare: true, cause: err}
}
