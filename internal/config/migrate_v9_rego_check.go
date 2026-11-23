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

// V9RegoReads is the Rego side of the v8 to v9 migration's module refresh
// (planRegoRefresh): it parses a policy module and names the data documents
// the modules read. internal/config/fullconfig registers it, so the Rego
// parser stays out of internal/config and of the hook, which never migrates
// a config.
type V9RegoReads struct {
	// Parse parses one module (Rego v1). The module value is only passed
	// back to Reads.
	Parse func(name string, source []byte) (module any, err error)
	// Reads maps a module name to the data documents it reads outside
	// data.defenseclaw.admission and data.defenseclaw.guardrail, and a
	// vendor module that reads no such document to every data document it
	// reads, if any.
	Reads func(modules map[string]any, vendor []string) map[string][]string
}

var v9RegoReads atomic.Pointer[V9RegoReads]

// errV9RegoReadsNotLinked fails the v9 migration's Rego refresh in a program
// that does not link internal/config/fullconfig: the migration stops with an
// error instead of moving data.json without checking the modules that read
// it. TestEveryConfigProgramLinksTheFullConfig pins the importers.
var errV9RegoReadsNotLinked = errors.New("config: the v9 migration's Rego module check is not linked into this program (import internal/config/fullconfig)")

// RegisterV9RegoReads installs the Rego module check of the v9 migration.
// internal/config/fullconfig calls it from its init; a second registration
// panics.
func RegisterV9RegoReads(reads V9RegoReads) {
	if reads.Parse == nil || reads.Reads == nil {
		panic("config: RegisterV9RegoReads with a nil function")
	}
	if !v9RegoReads.CompareAndSwap(nil, &reads) {
		panic("config: the v9 Rego module check is registered twice")
	}
}

func v9RegoReadsCheck() (*V9RegoReads, error) {
	if reads := v9RegoReads.Load(); reads != nil {
		return reads, nil
	}
	return nil, errV9RegoReadsNotLinked
}
