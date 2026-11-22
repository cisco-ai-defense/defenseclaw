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

package controller

import (
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// SandboxClassLabel is the worker-pool label an actor template selects its
// isolation class on (`template build --class`, templatecli.ClassLabel).
const SandboxClassLabel = "defenseclaw.io/sandbox-class"

// WorkerClasses is the sandbox classes of the workers a selector matches
// (every worker for an empty one), sorted and without repeats. The pool
// decides the class (ActorTemplate.worker_selector), so this is the class
// an actor with that selector runs in, whatever labels the pools carry
// (GAP-0386: a template pinned with --worker-label names no class label).
// A worker that has not reported its class yet takes no actors; it counts
// as the class the other workers of its pool report, else as gvisor, the
// weakest.
func WorkerClasses(workers []*ateapi.Worker, sel map[string]string) []string {
	poolClass := map[string]string{}
	for _, w := range workers {
		if c := workerClass(w); c != "" {
			poolClass[w.GetWorkerNamespace()+"/"+w.GetWorkerPool()] = c
		}
	}
	set := map[string]bool{}
	for _, w := range workers {
		if !selectorMatches(sel, w.GetLabels()) {
			continue
		}
		c := workerClass(w)
		if c == "" {
			c = poolClass[w.GetWorkerNamespace()+"/"+w.GetWorkerPool()]
		}
		if c == "" {
			c = config.SubstrateSandboxGVisor
		}
		set[c] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// ClassesMeet reports whether an actor that may land on any of classes
// meets required: there is a class, and every one meets it.
func ClassesMeet(classes []string, required string) bool {
	for _, c := range classes {
		if !config.SandboxClassSatisfies(c, required) {
			return false
		}
	}
	return len(classes) > 0
}

// workerClass is the class a worker reports (one entry today), "" before
// it reports.
func workerClass(w *ateapi.Worker) string {
	for _, sc := range w.GetStatus().GetSandboxClasses() {
		if c := strings.ToLower(strings.TrimSpace(sc.GetSandboxClass())); c != "" {
			return c
		}
	}
	return ""
}

func selectorMatches(sel, labels map[string]string) bool {
	for k, v := range sel {
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// placementSelector is the selector the scheduler places an actor with: the
// AND of its own and its template's (Actor.worker_selector). ok is false
// when they ask one label for two values, which no pool matches.
func placementSelector(a *ateapi.Actor, tmpl *ateapi.ActorTemplate) (map[string]string, bool) {
	out := maps.Clone(tmpl.GetWorkerSelector().GetMatchLabels())
	if out == nil {
		out = map[string]string{}
	}
	for k, v := range a.GetWorkerSelector().GetMatchLabels() {
		if have, ok := out[k]; ok && have != v {
			return nil, false
		}
		out[k] = v
	}
	return out, true
}

// classRefusal is why an actor does not meet the profile's sandbox_class
// (PLAN §7.3), "" when it does. The class Substrate recorded for the
// actor's worker assignment is the fact once it has one. Before that, a
// SandboxClassLabel on the placement selector names the class (`template
// build --class`); otherwise the workers the selector matches do. A
// template that cannot be read is admit's refusal, not this one.
func (c *Controller) classRefusal(ctx context.Context, a *ateapi.Actor, required string) string {
	required = strings.ToLower(required)
	if required == "" || required == config.SubstrateSandboxGVisor {
		return ""
	}
	refusal := "the profile requires sandbox_class " + required + "; "
	if rt := strings.ToLower(a.GetStatus().GetWorkerAssignment().GetSandboxRuntime().GetSandboxClass()); rt != "" {
		if config.SandboxClassSatisfies(rt, required) {
			return ""
		}
		return refusal + "the actor runs on " + rt
	}
	tmpl, _, err := c.template(ctx, a.GetActorTemplate(), false)
	if err != nil {
		return ""
	}
	sel, ok := placementSelector(a, tmpl)
	if !ok {
		return refusal + "the actor's worker selector contradicts its template's, so no worker matches it"
	}
	if class := strings.ToLower(sel[SandboxClassLabel]); class != "" {
		if config.SandboxClassSatisfies(class, required) {
			return ""
		}
		return refusal + "the actor's template runs on " + class
	}
	workers, err := ateapi.AllWorkers(ctx, c.o.Client, c.o.PageSize)
	if err != nil {
		return refusal + "the workers could not be read to check it: " + err.Error()
	}
	classes := WorkerClasses(workers, sel)
	if ClassesMeet(classes, required) {
		return ""
	}
	have := strings.Join(classes, ", ")
	if have == "" {
		have = config.SubstrateSandboxGVisor + " (no worker matches it and it has no " + SandboxClassLabel + " label)"
	}
	return refusal + "the actor's template runs on " + have
}

// idleAfter is the actor's idle suspend delay: the profile's, else def.
func (r Resolution) idleAfter(def time.Duration) time.Duration {
	if r.IdleSuspendAfter != nil {
		return *r.IdleSuspendAfter
	}
	return def
}
