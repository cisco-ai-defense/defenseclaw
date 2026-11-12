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

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// The launcher create flow over the Substrate control API (PLAN 5.3
// "Create and resume"):
//
//  1. CreateActor in the launcher atespace: the actor is SUSPENDED and
//     makes no call;
//  2. the registration is written (substrateCreateActor) so the actor's
//     first call is attributed;
//  3. the controller's EnsurePolicy writes its egress policy;
//  4. ResumeActor.
//
// A policy refusal (an unattested template, a kit too old, a profile that
// allows no sandbox) deletes the actor: nothing runs without a policy.

// ErrSubstrateTemplateNotFound is a create that names no template.
var ErrSubstrateTemplateNotFound = errors.New("the template does not exist in the launcher atespace")

// ErrSubstrateActorExists is a create whose name is taken.
var ErrSubstrateActorExists = errors.New("an actor with this name exists")

// ErrSubstrateActorRefused is an actor the controller gives no policy.
var ErrSubstrateActorRefused = errors.New("the controller refused the actor")

// SubstratePolicyEnsurer writes an actor's egress policy before its first
// resume (controller.Controller.EnsurePolicy). An error wrapping
// ErrSubstrateActorRefused means the actor gets no policy.
type SubstratePolicyEnsurer func(ctx context.Context, atespace, name string) error

// SubstrateATEActions implements SubstrateActorActions over ateapi.
type SubstrateATEActions struct {
	Client ateapi.Client
	Ensure SubstratePolicyEnsurer
}

var substrateActorNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// Create implements SubstrateActorActions.
func (s *SubstrateATEActions) Create(ctx context.Context, req SubstrateCreate) (SubstrateCreated, error) {
	tmplSpace, tmplName := req.Atespace, strings.TrimSpace(req.Template)
	if a, n, ok := strings.Cut(tmplName, "/"); ok {
		tmplSpace, tmplName = a, n
	}
	if !substrateActorNameRE.MatchString(tmplName) || tmplSpace != req.Atespace {
		// Templates come from the launcher atespace only: a template in
		// another atespace is not one this profile's admin published.
		return SubstrateCreated{}, ErrSubstrateTemplateNotFound
	}
	tref := ateapi.Ref(tmplSpace, tmplName)
	if _, err := s.Client.GetActorTemplate(ctx, tref); err != nil {
		if ateapi.IsNotFound(err) {
			return SubstrateCreated{}, ErrSubstrateTemplateNotFound
		}
		return SubstrateCreated{}, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = substrateActorName(req.Owner.Principal, req.Owner.Subject)
	}
	if !substrateActorNameRE.MatchString(name) {
		return SubstrateCreated{}, fmt.Errorf("%w: %q is not a valid actor name", ErrSubstrateActorExists, name)
	}
	a, err := s.Client.CreateActor(ctx, &ateapi.Actor{
		Metadata:      &ateapi.ResourceMetadata{Atespace: req.Atespace, Name: name},
		ActorTemplate: tref,
	})
	if ateapi.IsAlreadyExists(err) {
		return SubstrateCreated{}, ErrSubstrateActorExists
	}
	if err != nil {
		return SubstrateCreated{}, err
	}
	return SubstrateCreated{
		Atespace: req.Atespace, Name: name, UID: a.GetMetadata().GetUid(),
		Template: ateapi.Key(tref), Connector: req.Connector,
	}, nil
}

// Resume writes the policy, then resumes. It runs after the registration
// is written, so the controller attributes the actor to its person.
func (s *SubstrateATEActions) Resume(ctx context.Context, atespace, name string) error {
	if s.Ensure == nil {
		return fmt.Errorf("%w: no policy writer", ErrSubstrateActorRefused)
	}
	if err := s.Ensure(ctx, atespace, name); err != nil {
		return err
	}
	_, _, err := s.Client.ResumeActor(ctx, ateapi.Ref(atespace, name))
	return err
}

// Delete implements SubstrateActorActions.
func (s *SubstrateATEActions) Delete(ctx context.Context, atespace, name string) error {
	_, err := s.Client.DeleteActor(ctx, ateapi.Ref(atespace, name), nil)
	if ateapi.IsNotFound(err) {
		return nil
	}
	return err
}

// substrateActorName is "<person>-<6 hex>": the local part of the
// principal (or the subject), lowercased to the DNS label alphabet.
func substrateActorName(principal, subject string) string {
	base := principal
	if base == "" {
		base = subject
	}
	if at := strings.IndexByte(base, '@'); at > 0 {
		base = base[:at]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(base) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '.' || r == '_':
			b.WriteByte('-')
		}
		if b.Len() >= 40 {
			break
		}
	}
	prefix := strings.Trim(b.String(), "-")
	if prefix == "" {
		prefix = "actor"
	}
	buf := make([]byte, 3)
	_, _ = rand.Read(buf)
	return prefix + "-" + hex.EncodeToString(buf)
}
