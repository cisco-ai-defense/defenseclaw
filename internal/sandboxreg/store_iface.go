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

package sandboxreg

import "github.com/defenseclaw/defenseclaw/internal/sandboxrelay"

// Store keeps registrations per uid: <DataDir>/sandbox/registrations/<uid>.json,
// directory 0700 and files 0600 owned by the service account, written
// atomically. Every lookup is scoped to uid: another uid's id is not found.
type Store interface {
	// Create adds a pending registration. A binding id or sandbox id that
	// matches a tombstone is refused.
	Create(uid int, r Registration) error
	// Get returns uid's registration id; ok is false for an unknown id or
	// another uid's.
	Get(uid int, id string) (r Registration, ok bool, err error)
	// Bind turns a pending, unexpired registration live for b's sandbox.
	Bind(uid int, id string, b sandboxrelay.BindRequest) (Registration, error)
	// Revoke keeps the registration as a tombstone, never registered again.
	Revoke(uid int, id, reason string) error
	// Deleted removes a tombstone or a pending entry.
	Deleted(uid int, id string) error
	// List returns uid's registrations.
	List(uid int) ([]Registration, error)
	// ListAll returns every uid's registrations (admin views, re-match).
	ListAll() ([]Registration, error)
	// Update rewrites a registration in place (re-match: profile, match,
	// digests, provisional).
	Update(uid int, r Registration) error
	// Purge removes the whole store.
	Purge() error
}

// DecisionStore keeps saved decisions per uid:
// <DataDir>/sandbox/decisions/<uid>.json, same modes as Store.
type DecisionStore interface {
	// Add stores d for uid.
	Add(uid int, d Decision) error
	// List returns uid's decisions; registration "" lists all of them.
	List(uid int, registration string) ([]Decision, error)
	// Purge removes the whole store.
	Purge() error
}
