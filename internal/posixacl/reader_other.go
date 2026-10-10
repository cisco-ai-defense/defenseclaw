//go:build !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package posixacl

import "os"

type systemReader struct{}

var System Reader = systemReader{}

func (systemReader) Read(string, os.FileMode) (View, error) { return View{}, nil }
