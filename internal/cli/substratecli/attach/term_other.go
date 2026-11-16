// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package attach

import (
	"os"
	"time"
)

func (t *terminal) watch(stop <-chan struct{}) <-chan struct{} {
	return t.pollSize(stop, 500*time.Millisecond)
}

func enableVT(in, out *os.File) func() { return func() {} }
