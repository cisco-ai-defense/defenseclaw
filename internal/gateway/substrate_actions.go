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
	"net/http"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
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

// ErrSubstrateTemplateAttestation is a template whose attestation could not
// be read (the attestor failed), so its connector label is unknown. A
// managed create refuses it; an open-source one warns and goes on with the
// launcher's connector (GAP-0181).
var ErrSubstrateTemplateAttestation = errors.New("template attestation could not be read")

// SubstrateTemplateAttestation is a template the attestor did not positively
// attest with a connector label (GAP-0181): it refused the template (Reason;
// Retryable when the cause may pass, such as a registry or log outage), or
// attested it without a label (Unlabeled). It wraps
// ErrSubstrateTemplateAttestation: a managed create refuses it, an open
// source one warns and goes on with the launcher's connector.
type SubstrateTemplateAttestation struct {
	Reason    string
	Retryable bool
	Unlabeled bool
}

func (e *SubstrateTemplateAttestation) Error() string {
	code, msg, _, _ := substrateAttestationRefusal(e)
	if e.Reason == "" {
		return code + ": " + msg
	}
	return code + ": " + msg + ": " + e.Reason
}

func (e *SubstrateTemplateAttestation) Unwrap() error { return ErrSubstrateTemplateAttestation }

// substrateAttestationRefusal is the create answer for a template that is
// not positively attested with a label: the reason code, the message (it
// says "retryable" when the cause may pass), a short detail and whether a
// retry may succeed.
func substrateAttestationRefusal(err error) (code, message, detail string, retryable bool) {
	var e *SubstrateTemplateAttestation
	if !errors.As(err, &e) {
		return "template_attestation_unreadable", "template attestation could not be read", "", false
	}
	detail = substrateAttestationDetail(e.Reason)
	switch {
	case e.Unlabeled:
		return "template_connector_unlabeled", "the template attestation names no connector", detail, false
	case e.Retryable:
		return "template_attestation_unreadable", "template attestation could not be checked now (retryable)", detail, true
	default:
		return "template_not_attested", "the template is not attested", detail, false
	}
}

// substrateAttestationDetail keeps the attestor's reason to one short line.
func substrateAttestationDetail(s string) string {
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }), " ")
	if r := []rune(strings.TrimSpace(s)); len(r) > 240 {
		return string(r[:240]) + "..."
	}
	return strings.TrimSpace(s)
}

// SubstratePolicyEnsurer writes an actor's egress policy before its first
// resume (controller.Controller.EnsurePolicy). An error wrapping
// ErrSubstrateActorRefused means the actor gets no policy.
type SubstratePolicyEnsurer func(ctx context.Context, atespace, name string) error

// SubstrateATEActions implements SubstrateActorActions over ateapi.
type SubstrateATEActions struct {
	Client ateapi.Client
	Ensure SubstratePolicyEnsurer
	// ConnectorOf reads the connector a template was built for (its attested
	// label, GAP-0160). It answers a label only for a template positively
	// attested with one; anything else (an attestor error, a refusal,
	// retryable or not, an attestation without a label) is an error wrapping
	// ErrSubstrateTemplateAttestation (*SubstrateTemplateAttestation), never
	// "" (GAP-0181). Nil reads no label: a managed create refuses then.
	ConnectorOf func(ctx context.Context, tmpl *ateapi.ActorTemplate) (string, error)
}

// SubstrateTemplateConnector is the optional part of an Actions that tells
// the create route which connector a template carries.
type SubstrateTemplateConnector interface {
	TemplateConnector(ctx context.Context, atespace, template string) (string, error)
}

// TemplateConnector implements SubstrateTemplateConnector.
func (s *SubstrateATEActions) TemplateConnector(ctx context.Context, atespace, template string) (string, error) {
	if s.ConnectorOf == nil {
		return "", nil
	}
	tmplSpace, tmplName := atespace, strings.TrimSpace(template)
	if a, n, ok := strings.Cut(tmplName, "/"); ok {
		tmplSpace, tmplName = a, n
	}
	if !substrateActorNameRE.MatchString(tmplName) || tmplSpace != atespace {
		return "", ErrSubstrateTemplateNotFound
	}
	t, err := s.Client.GetActorTemplate(ctx, ateapi.Ref(tmplSpace, tmplName))
	if ateapi.IsNotFound(err) {
		return "", ErrSubstrateTemplateNotFound
	}
	if err != nil {
		return "", err
	}
	return s.ConnectorOf(ctx, t)
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
	tmpl, err := s.Client.GetActorTemplate(ctx, tref)
	if err != nil {
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
		Metadata:       &ateapi.ResourceMetadata{Atespace: req.Atespace, Name: name},
		ActorTemplate:  tref,
		WorkerSelector: substrateClassSelector(tmpl, req.SandboxClass),
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

// substrateClassSelector is the worker selector an actor needs to run in
// class: nil when the template already meets it (its own selector applies),
// else the template's labels with the class label set (PLAN 7.3,
// controller.SandboxClassLabel), so the actor lands on a pool of that class
// and the controller's class check passes.
func substrateClassSelector(tmpl *ateapi.ActorTemplate, class string) *ateapi.Selector {
	class = strings.ToLower(strings.TrimSpace(class))
	labels := tmpl.GetWorkerSelector().GetMatchLabels()
	have := strings.ToLower(labels[controller.SandboxClassLabel])
	if have == "" {
		have = config.SubstrateSandboxGVisor // every actor is at least gVisor (D7), as the controller counts it
	}
	if class == "" || config.SandboxClassSatisfies(have, class) {
		return nil
	}
	out := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		out[k] = v
	}
	out[controller.SandboxClassLabel] = class
	return &ateapi.Selector{MatchLabels: out}
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
	if ateapi.IsResourceExhausted(err) {
		return fmt.Errorf("%w: %v", ErrSubstrateNoWorker, err)
	}
	return err
}

// ErrSubstrateNoWorker is a resume that no worker of the pool has room for
// (RESOURCE_EXHAUSTED, GAP-0167).
var ErrSubstrateNoWorker = errors.New("no worker has room for the actor")

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

// maxRefusalDetail bounds the refusal reason sent to the launcher.
const maxRefusalDetail = 300

// writeSubstrateActorRefusal answers a create the controller refused: the closed
// reason actor_refused, the refusal code and its reason in words, and the
// actor with its UID, so the launcher says why and the administrator finds
// the controller's log line by that UID (GAP-0182).
func writeSubstrateActorRefusal(w http.ResponseWriter, atespace, name, uid string, err error) {
	out := map[string]any{"error": http.StatusText(http.StatusForbidden), "reason": "actor_refused",
		"actor": atespace + "/" + name, "actor_uid": uid}
	var re *controller.RefusedError
	if errors.As(err, &re) {
		detail := re.Reason
		if len(detail) > maxRefusalDetail {
			detail = detail[:maxRefusalDetail] + "..."
		}
		out["refusal"], out["detail"] = re.Code, detail
	} else {
		out["refusal"], out["detail"] = controller.RefusalNoPolicy, "the controller gave the actor no egress policy"
	}
	writeSubstrateJSON(w, http.StatusForbidden, out)
}
