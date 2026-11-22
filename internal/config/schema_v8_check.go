// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"sync/atomic"
)

// V8SchemaViolation is one node of a failed v8 schema check: the fields of
// the JSON Schema validator's error tree that the config messages read. It
// keeps the validator library out of this package, so a program that never
// checks a v8 document (cmd/defenseclaw-hook) does not link it or run its
// init.
type V8SchemaViolation struct {
	KeywordLocation         string
	AbsoluteKeywordLocation string
	InstanceLocation        string
	Message                 string
	Causes                  []*V8SchemaViolation
}

// V8SchemaCheck checks a decoded v8 document against the embedded schema.
// err is a schema that does not compile. invalid is a document that fails
// the schema; violation is its error tree, nil when the failure has none.
type V8SchemaCheck func(document any) (violation *V8SchemaViolation, invalid bool, err error)

var v8SchemaCheck atomic.Pointer[V8SchemaCheck]

// errV8SchemaCheckNotLinked fails the v8 schema check of a program that does
// not link internal/config/v8schema (through internal/config/fullconfig): a
// missing check never passes a document. TestEveryConfigProgramLinksTheFullConfig pins the importers.
var errV8SchemaCheckNotLinked = errors.New("the v8 schema check is not linked into this program (import internal/config/fullconfig)")

// RegisterV8SchemaCheck installs the v8 schema check. internal/config/v8schema
// calls it from its init; a second registration panics.
func RegisterV8SchemaCheck(check V8SchemaCheck) {
	if check == nil {
		panic("config: RegisterV8SchemaCheck with a nil check")
	}
	if !v8SchemaCheck.CompareAndSwap(nil, &check) {
		panic("config: the v8 schema check is registered twice")
	}
}

func v8SchemaCheckFunc() (V8SchemaCheck, error) {
	if check := v8SchemaCheck.Load(); check != nil {
		return *check, nil
	}
	return nil, errV8SchemaCheckNotLinked
}
