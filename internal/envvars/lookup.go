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

package envvars

import (
	"os"
	"sort"
	"sync"
	"sync/atomic"
)

// Managed-mode environment policy. On a managed standalone enterprise host
// (config.Config.StandaloneEnterprise) the admin config is the policy, so a
// variable whose registry entry says managed: ignore is treated as unset:
// a user's shell or .env can not weaken the host. Everywhere else, and
// under the Secure Client profile, Lookup returns the raw environment.
//
// Behaviour-changing reads of DEFENSECLAW_* variables go through Lookup or
// Getenv; registry_test.go fails on new direct reads of the security opt-out
// variables.

var (
	managedValue atomic.Bool

	ignoredMu sync.Mutex
	ignored   = map[string]struct{}{}
)

// SetManagedStandalone records whether this process runs on a managed
// standalone host. The command pre-run calls it with
// Config.StandaloneEnterprise() once the active config is loaded; until
// then (and in tests) the raw environment applies.
func SetManagedStandalone(on bool) { managedValue.Store(on) }

// ManagedStandalone reports whether managed-mode policy applies.
func ManagedStandalone() bool { return managedValue.Load() }

// ManagedPolicy returns the registry's managed policy for name; an
// undeclared name is ManagedAllow (the coverage test keeps that set empty).
func ManagedPolicy(name string) string {
	r, err := Load()
	if err != nil {
		return ManagedAllow
	}
	if e, ok := r.Get(name); ok && e.Managed != "" {
		return e.Managed
	}
	return ManagedAllow
}

// IgnoredByManagedPolicy reports whether a set value of name is ignored on
// this host, and records it for doctor when it is.
func IgnoredByManagedPolicy(name string) bool {
	if !ManagedStandalone() || ManagedPolicy(name) != ManagedIgnore {
		return false
	}
	ignoredMu.Lock()
	ignored[name] = struct{}{}
	ignoredMu.Unlock()
	return true
}

// Lookup is os.LookupEnv under the managed-mode policy.
func Lookup(name string) (string, bool) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", false
	}
	if IgnoredByManagedPolicy(name) {
		return "", false
	}
	return value, true
}

// Getenv is os.Getenv under the managed-mode policy.
func Getenv(name string) string {
	value, _ := Lookup(name)
	return value
}

// IgnoredNames lists the variables this process saw set and ignored under
// the managed-mode policy (names only, never values).
func IgnoredNames() []string {
	ignoredMu.Lock()
	defer ignoredMu.Unlock()
	out := make([]string, 0, len(ignored))
	for name := range ignored {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
