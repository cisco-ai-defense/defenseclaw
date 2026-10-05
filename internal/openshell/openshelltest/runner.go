// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package openshelltest

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// RunnerFunc answers one scripted command.
type RunnerFunc func(ctx context.Context, cmd openshell.Command) ([]byte, error)

// Runner is a scripted openshell.Runner. Commands are matched on their
// argv ("name arg1 arg2"): a rule matches the argv itself or any longer
// argv it is a word prefix of, and the most recently added matching rule
// answers. Unmatched commands fail with exec.ErrNotFound, as a missing
// binary would. Safe for concurrent use.
//
//	r := &openshelltest.Runner{}
//	r.On("docker version", `{"Server":{"Version":"29.4.0"}}`, nil)
type Runner struct {
	mu    sync.Mutex
	rules []runnerRule
	calls []openshell.Command
}

type runnerRule struct {
	prefix string
	fn     RunnerFunc
}

// On answers commands starting with prefix with a fixed output and error.
func (r *Runner) On(prefix, output string, err error) {
	r.OnFunc(prefix, func(context.Context, openshell.Command) ([]byte, error) { return []byte(output), err })
}

// OnFunc answers commands starting with prefix with fn.
func (r *Runner) OnFunc(prefix string, fn RunnerFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = append(r.rules, runnerRule{prefix: prefix, fn: fn})
}

// Calls returns every command run so far, in order.
func (r *Runner) Calls() []openshell.Command {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]openshell.Command(nil), r.calls...)
}

// Called reports whether a command starting with prefix was run.
func (r *Runner) Called(prefix string) bool {
	for _, c := range r.Calls() {
		if matchPrefix(Argv(c), prefix) {
			return true
		}
	}
	return false
}

// Argv renders a command as the string rules match against.
func Argv(c openshell.Command) string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}

func matchPrefix(argv, prefix string) bool {
	return argv == prefix || strings.HasPrefix(argv, prefix+" ")
}

func (r *Runner) answer(ctx context.Context, c openshell.Command) ([]byte, error) {
	r.mu.Lock()
	r.calls = append(r.calls, c)
	var fn RunnerFunc
	argv := Argv(c)
	for i := len(r.rules) - 1; i >= 0; i-- {
		if matchPrefix(argv, r.rules[i].prefix) {
			fn = r.rules[i].fn
			break
		}
	}
	r.mu.Unlock()
	if fn == nil {
		return nil, fmt.Errorf("openshelltest: unscripted command %q: %w", argv, exec.ErrNotFound)
	}
	return fn(ctx, c)
}

// Output implements openshell.Runner.
func (r *Runner) Output(ctx context.Context, c openshell.Command) ([]byte, error) {
	return r.answer(ctx, c)
}

// Run implements openshell.Runner; the scripted output is discarded.
func (r *Runner) Run(ctx context.Context, c openshell.Command) error {
	_, err := r.answer(ctx, c)
	return err
}
