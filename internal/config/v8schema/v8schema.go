// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package v8schema is the JSON Schema check of a v8 config document. Every
// program that loads or validates a config imports it, and it registers
// itself with internal/config. The hook does not import it, so the hook does
// not link the validator library or run its init.
package v8schema

import (
	"bytes"
	"errors"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/config"
	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

// The schema file keeps its v8 directory; its $id names the version it
// describes, config_version 9 (GAP-1651).
const configSchemaID = "https://schemas.defenseclaw.dev/config/v9/defenseclaw-config.schema.json"

func init() {
	config.RegisterV8SchemaCheck(check)
}

var compiled = sync.OnceValues(func() (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource(configSchemaID, bytes.NewReader(publicschemas.DefenseClawConfigV8Schema())); err != nil {
		return nil, err
	}
	return compiler.Compile(configSchemaID)
})

func check(document any) (*config.V8SchemaViolation, bool, error) {
	schema, err := compiled()
	if err != nil {
		return nil, false, err
	}
	err = schema.Validate(document)
	if err == nil {
		return nil, false, nil
	}
	var validation *jsonschema.ValidationError
	if !errors.As(err, &validation) {
		return nil, true, nil
	}
	return violation(validation), true, nil
}

func violation(source *jsonschema.ValidationError) *config.V8SchemaViolation {
	result := &config.V8SchemaViolation{
		KeywordLocation:         source.KeywordLocation,
		AbsoluteKeywordLocation: source.AbsoluteKeywordLocation,
		InstanceLocation:        source.InstanceLocation,
		Message:                 source.Message,
	}
	if len(source.Causes) > 0 {
		result.Causes = make([]*config.V8SchemaViolation, len(source.Causes))
		for index, cause := range source.Causes {
			result.Causes[index] = violation(cause)
		}
	}
	return result
}
