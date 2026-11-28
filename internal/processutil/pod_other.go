// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package processutil

import "os/exec"

// PodRunner is the Linux scanner sidecar's pod-contained mode (GAP-0828).
// It refuses every command on other platforms.
type PodRunner struct {
	// refusal is why this runner refuses; the caller checks it at run time
	// like the Linux runner's own refusals (GAP-1035).
	refusal error
}

// NewPodRunner returns a runner that refuses every command.
func NewPodRunner(string, ...string) *PodRunner {
	return &PodRunner{refusal: &podError{msg: "it runs only on Linux, in the chart's scanner sidecar"}}
}

// Check fails here.
func (p *PodRunner) Check() error { return p.refusal }

// Run never runs cmd here.
func (p *PodRunner) Run(*exec.Cmd) error { return p.refusal }

// RunJob never runs cmd here.
func (p *PodRunner) RunJob(*exec.Cmd, string) error { return p.refusal }

// Reset fails here.
func (p *PodRunner) Reset() error { return p.refusal }
