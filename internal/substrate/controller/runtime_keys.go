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
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// SandboxClassLabel is the worker-pool label an actor template selects its
// isolation class on (`template build --class`, templatecli.ClassLabel).
const SandboxClassLabel = "defenseclaw.io/sandbox-class"

// actorSandboxClass is the isolation class an actor runs in: its own worker
// selector's SandboxClassLabel, else its template's, "" when neither names
// one. Every Substrate actor is at least gVisor-isolated, so "" counts as
// gvisor.
func actorSandboxClass(a *ateapi.Actor, tmpl *ateapi.ActorTemplate) string {
	if v := a.GetWorkerSelector().GetMatchLabels()[SandboxClassLabel]; v != "" {
		return strings.ToLower(v)
	}
	return strings.ToLower(tmpl.GetWorkerSelector().GetMatchLabels()[SandboxClassLabel])
}

// classRefusal is why an actor does not meet the profile's sandbox_class
// (PLAN §7.3), "" when it does. A microvm requirement refuses an actor
// whose worker selector names no class or gvisor; a template that cannot be
// read is admit's refusal, not this one.
func (c *Controller) classRefusal(ctx context.Context, a *ateapi.Actor, required string) string {
	required = strings.ToLower(required)
	if required == "" || required == config.SubstrateSandboxGVisor {
		return ""
	}
	tmpl, _, err := c.template(ctx, a.GetActorTemplate(), false)
	if err != nil {
		return ""
	}
	class := actorSandboxClass(a, tmpl)
	if config.SandboxClassSatisfies(class, required) {
		return ""
	}
	if class == "" {
		class = config.SubstrateSandboxGVisor + " (no " + SandboxClassLabel + " label)"
	}
	return "the profile requires sandbox_class " + required + "; the actor's template runs on " + class
}

// idleAfter is the actor's idle suspend delay: the profile's, else def.
func (r Resolution) idleAfter(def time.Duration) time.Duration {
	if r.IdleSuspendAfter != nil {
		return *r.IdleSuspendAfter
	}
	return def
}
