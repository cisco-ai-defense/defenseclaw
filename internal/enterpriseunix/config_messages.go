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

package enterpriseunix

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"gopkg.in/yaml.v3"
)

// settingsReferenceURL is the enterprise settings reference; the managed
// packages ship no per-user CLI to print the schema with.
const settingsReferenceURL = "https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/configuration/#settings-reference"

var configHeaderPattern = regexp.MustCompile(`headers(?:\["([^"]+)"\]|\.([A-Za-z0-9_.-]+))$`)

// plainConfigProblem renders an invalid enum value or an unstored protected
// credential as one plain sentence: the file and line, the field, the value
// and the fix. The raw diagnostic leads with the validator's rule id, a
// JSONPath and the YAML node type ("(received object)"), and for an enum it
// does not show the rejected value (GAP-1944, GAP-1948).
func (e *Env) plainConfigProblem(err error, source string, raw []byte) (string, bool) {
	where := source
	if where == "" {
		where = e.Layout.ConfigPath
	}
	if strings.Contains(err.Error(), "enterprise.profile=") && strings.Contains(err.Error(), "conflicts with immutable") {
		return fmt.Sprintf("%s: enterprise.profile is fixed to standalone on this host; change the profile by reinstalling the deployment", where), true
	}
	var yamlErr *config.V8YAMLError
	if errors.As(err, &yamlErr) {
		field := configField(yamlErr.Path)
		message := yamlErr.Summary
		switch yamlErr.Code {
		case config.V8YAMLErrorDuplicateKey:
			message = field + " appears twice; merge the definitions into one"
		case config.V8YAMLErrorInvalidUTF8:
			message = "the file is not valid UTF-8; save it as UTF-8"
		case config.V8YAMLErrorVersionUnsupported:
			message = "config_version is not supported by this installation; use config_version 9 or install a matching enterprise package"
		case config.V8YAMLErrorVersionRequired, config.V8YAMLErrorVersionInvalid:
			message = "config_version is required; add `config_version: 9` as the first line of the file"
		case config.V8YAMLErrorVersionUpgrade:
			message = "the file uses an older config_version; write it in config_version 9 format"
		case config.V8YAMLErrorLegacyKeyForbidden:
			message = field + " is a retired key; remove or migrate it in the administrator's config"
		default:
			if yamlErr.Action != "" {
				message += "; " + yamlErr.Action
			}
		}
		return fmt.Sprintf("%s%s: %s", where, lineSuffix(yamlErr.Line), strings.TrimRight(message, ". ")), true
	}
	var schemaErr *config.V8SchemaError
	if errors.As(err, &schemaErr) && schemaErr.Keyword == "enum" && strings.HasPrefix(schemaErr.Expected, "one of ") {
		var choices []any
		if json.Unmarshal([]byte(strings.TrimPrefix(schemaErr.Expected, "one of ")), &choices) != nil || len(choices) == 0 {
			return "", false
		}
		names := make([]string, len(choices))
		for i, choice := range choices {
			names[i] = fmt.Sprint(choice)
		}
		if schemaErr.Path == "$.deployment_mode" {
			names = []string{"managed_enterprise"}
		}
		is := "is not an allowed value"
		if value, ok := yamlScalarAt(raw, schemaErr.Line, schemaErr.Column); ok {
			is = fmt.Sprintf("is %q", value)
		}
		return fmt.Sprintf("%s%s: %s %s; allowed values: %s. The settings reference: %s",
			where, lineSuffix(schemaErr.Line), configField(schemaErr.Path), is, strings.Join(names, ", "), settingsReferenceURL), true
	}
	if errors.As(err, &schemaErr) {
		field := configField(schemaErr.Path)
		reason := "has an invalid value"
		if schemaErr.Keyword == "additionalProperties" {
			reason = "is an unknown setting"
		} else if schemaErr.Keyword == "pattern" {
			switch {
			case strings.HasSuffix(field, ".rule_pack"), strings.Contains(field, ".custom_packs.") && !strings.HasSuffix(field, ".digest"):
				reason = "must start with a lowercase letter or digit and use only lowercase letters, digits, - or _ (at most 64 characters)"
			case strings.HasSuffix(field, ".digest"):
				reason = "must be sha256: followed by 64 lowercase hexadecimal characters"
			case strings.HasSuffix(field, ".block_at"), strings.HasSuffix(field, ".alert_at"):
				reason = "must be one of CRITICAL, HIGH, MEDIUM, LOW"
			default:
				reason = "does not match the setting's required format"
			}
		} else if schemaErr.Expected != "" {
			reason = "must be " + schemaErr.Expected
		}
		return fmt.Sprintf("%s%s: %s %s. The settings reference: %s", where, lineSuffix(schemaErr.Line), field, reason, settingsReferenceURL), true
	}
	var secretErr *config.V8SecretReferenceError
	var semanticErr *config.V8SemanticError
	if errors.As(err, &secretErr) && secretErr.Credential && errors.As(err, &semanticErr) {
		name := secretErr.Reference
		subject := "the field " + configField(secretErr.Path)
		if match := configHeaderPattern.FindStringSubmatch(secretErr.Path); match != nil {
			subject = "the header " + match[1] + match[2]
			if secretErr.Destination != "" {
				subject = fmt.Sprintf("the %s destination's header %s", secretErr.Destination, match[1]+match[2])
			}
		}
		state := "which is not stored"
		if _, statErr := os.Lstat(e.P(filepath.Join(e.Layout.SecretsDir, name))); statErr == nil {
			state = "which is stored but failed the permission check (it must be a regular root-owned file only root can read)"
		}
		// secret set refuses without a value source (GAP-2241).
		store := "`printf '%s' \"$VALUE\" | " + filepath.Join(e.Layout.BinDir, binGateway) + " enterprise secret set --name " + name +
			" --from-stdin` (or --from-file <root-only file>)"
		return fmt.Sprintf("%s%s: %s uses protected credential %q, %s; store it with %s, or remove the reference",
			where, lineSuffix(semanticErr.Line), subject, name, state, store), true
	}
	if errors.As(err, &semanticErr) {
		reason := strings.TrimRight(semanticErr.Summary, ". ")
		if semanticErr.Action != "" && !strings.Contains(semanticErr.Action, "defenseclaw config reference") {
			reason += "; " + strings.TrimRight(semanticErr.Action, ". ")
		}
		return fmt.Sprintf("%s%s: %s: %s. The settings reference: %s", where, lineSuffix(semanticErr.Line), configField(semanticErr.Path), reason, settingsReferenceURL), true
	}
	return "", false
}

func lineSuffix(line int) string {
	if line <= 0 {
		return ""
	}
	return fmt.Sprintf(" line %d", line)
}

func configField(path string) string {
	field := strings.TrimPrefix(strings.TrimPrefix(path, "$"), ".")
	if field == "" {
		return "the document"
	}
	return field
}

// yamlScalarAt returns the scalar at line:column of raw, at most 60 bytes.
func yamlScalarAt(raw []byte, line, column int) (string, bool) {
	if line <= 0 || column <= 0 {
		return "", false
	}
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil {
		return "", false
	}
	var found *yaml.Node
	var walk func(*yaml.Node)
	walk = func(node *yaml.Node) {
		if node == nil || found != nil {
			return
		}
		if node.Kind == yaml.ScalarNode && node.Line == line && node.Column == column {
			found = node
			return
		}
		for _, child := range node.Content {
			walk(child)
		}
	}
	walk(&doc)
	if found == nil {
		return "", false
	}
	value := found.Value
	if len(value) > 60 {
		value = strings.ToValidUTF8(value[:57], "") + "..."
	}
	return value, true
}
