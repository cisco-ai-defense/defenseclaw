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
	"maps"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

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
	// TemplateKit reads what a template's signed statement says it carries:
	// the connector (GAP-0160), the agent version and the hook contract
	// (GAP-0201), the kit version and the image digest. It answers only for a
	// template positively attested with a connector label; anything else (an
	// attestor error, a refusal, retryable or not, an attestation without a
	// label) is an error wrapping ErrSubstrateTemplateAttestation
	// (*SubstrateTemplateAttestation), never a zero kit (GAP-0181). Nil reads
	// no label: a managed create refuses then.
	TemplateKit func(ctx context.Context, tmpl *ateapi.ActorTemplate) (SubstrateTemplateKit, error)
}

// SubstrateTemplateKit is what an attested template carries.
type SubstrateTemplateKit struct {
	Connector    string
	AgentVersion string
	HookContract string
	KitVersion   string
	Digest       string
	// RelayStreams are the signed kit's relay features (registry.JoinStreams).
	RelayStreams string
}

func (s *SubstrateATEActions) templateKit(ctx context.Context, tmpl *ateapi.ActorTemplate) (SubstrateTemplateKit, error) {
	if s.TemplateKit == nil {
		return SubstrateTemplateKit{}, nil
	}
	return s.TemplateKit(ctx, tmpl)
}

// SubstrateTemplateConnector is the optional part of an Actions that tells
// the create route which connector a template carries.
type SubstrateTemplateConnector interface {
	TemplateConnector(ctx context.Context, atespace, template string) (string, error)
}

// SubstrateTemplateKitReader is the optional part of an Actions that reads
// a template's attested kit once: the create route takes the connector from
// it and hands the same kit to Create (SubstrateCreate.Kit), so the
// connector, the agent version and the digest of one create come from one
// attestation read, not two (GAP-0201 residual).
type SubstrateTemplateKitReader interface {
	ReadTemplateKit(ctx context.Context, atespace, template string) (SubstrateTemplateKit, error)
}

// ReadTemplateKit implements SubstrateTemplateKitReader. With no TemplateKit
// reader it answers no kit and no error. A template that does not exist is
// ErrSubstrateTemplateNotFound; anything the attestor did not positively
// attest with a label is an error wrapping ErrSubstrateTemplateAttestation.
func (s *SubstrateATEActions) ReadTemplateKit(ctx context.Context, atespace, template string) (SubstrateTemplateKit, error) {
	if s.TemplateKit == nil {
		return SubstrateTemplateKit{}, nil
	}
	tmplSpace, tmplName := atespace, strings.TrimSpace(template)
	if a, n, ok := strings.Cut(tmplName, "/"); ok {
		tmplSpace, tmplName = a, n
	}
	if !substrateActorNameRE.MatchString(tmplName) || tmplSpace != atespace {
		return SubstrateTemplateKit{}, ErrSubstrateTemplateNotFound
	}
	t, err := s.Client.GetActorTemplate(ctx, ateapi.Ref(tmplSpace, tmplName))
	if ateapi.IsNotFound(err) {
		return SubstrateTemplateKit{}, ErrSubstrateTemplateNotFound
	}
	if err != nil {
		return SubstrateTemplateKit{}, err
	}
	return s.TemplateKit(ctx, t)
}

// TemplateConnector implements SubstrateTemplateConnector.
func (s *SubstrateATEActions) TemplateConnector(ctx context.Context, atespace, template string) (string, error) {
	kit, err := s.ReadTemplateKit(ctx, atespace, template)
	return kit.Connector, err
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
	// The registration names the agent version and the hook contract the
	// signed statement gives: the hook profile, and so the actor's chain
	// window, is resolved from them (GAP-0201). The create route reads the
	// attestation once and passes it in req.Kit; reading it again here
	// could answer from a different read than the connector it decided on.
	// A template whose attestation cannot be read records no agent version,
	// so its steps are reported as unrecorded (GAP-0201): the create route
	// decided by mode already (GAP-0181), managed refused before this call,
	// open source warned.
	var kit SubstrateTemplateKit
	if req.Kit != nil {
		kit = *req.Kit
	} else if k, kerr := s.templateKit(ctx, tmpl); kerr != nil {
		fmt.Fprintf(os.Stderr, "[substrate] template %s/%s: %v\n", tmplSpace, tmplName, kerr)
	} else {
		kit = k
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = substrateActorName(req.Owner.Principal, req.Owner.Subject)
	}
	if !substrateActorNameRE.MatchString(name) {
		return SubstrateCreated{}, fmt.Errorf("%w: %q is not a valid actor name", ErrSubstrateActorExists, name)
	}
	sel, err := s.classSelector(ctx, tmpl, req.SandboxClass)
	if err != nil {
		return SubstrateCreated{}, err
	}
	a, err := s.Client.CreateActor(ctx, &ateapi.Actor{
		Metadata:       &ateapi.ResourceMetadata{Atespace: req.Atespace, Name: name},
		ActorTemplate:  tref,
		WorkerSelector: sel,
	})
	if ateapi.IsAlreadyExists(err) {
		return SubstrateCreated{}, ErrSubstrateActorExists
	}
	if err != nil {
		return SubstrateCreated{}, err
	}
	return SubstrateCreated{
		Atespace: req.Atespace, Name: name, UID: a.GetMetadata().GetUid(),
		Template: ateapi.Key(tref), Connector: req.Connector, SandboxClass: s.createdClass(ctx, tmpl, sel, req.SandboxClass),
		HarnessVersion: kit.AgentVersion, HookContract: kit.HookContract,
		KitVersion: kit.KitVersion, TemplateDigest: kit.Digest, RelayStreams: kit.RelayStreams,
	}, nil
}

// SubstrateClassUnavailable is a create whose template runs on no worker
// of the sandbox class the profile requires (substrate.default_sandbox_class
// or the profile's sandbox_class), and that no pool label narrows to one:
// nothing is created, rather than an actor no worker can take (GAP-0386).
type SubstrateClassUnavailable struct {
	Template string
	Class    string
	// Have is the classes of the workers the template selects, "" for none.
	Have string
}

func (e *SubstrateClassUnavailable) Error() string {
	have := e.Have
	if have == "" {
		have = "no worker"
	}
	return "template " + e.Template + " runs on " + have + "; sandbox_class " + e.Class + " is required"
}

// maxSelectorLabels is the Substrate bound on a selector's labels.
const maxSelectorLabels = 10

// substrateEffectiveClass is the class an actor created from tmpl for class
// runs in: the template's own when it meets class, else class
// (classSelector moves the actor to a pool of that class, or the create is
// refused with SubstrateClassUnavailable).
func substrateEffectiveClass(tmpl *ateapi.ActorTemplate, class string) string {
	class = strings.ToLower(strings.TrimSpace(class))
	have := strings.ToLower(tmpl.GetWorkerSelector().GetMatchLabels()[controller.SandboxClassLabel])
	if have == "" {
		have = config.SubstrateSandboxGVisor
	}
	if class == "" || config.SandboxClassSatisfies(have, class) {
		return have
	}
	return class
}

// createdClass is the class an actor created from tmpl with the extra
// selector sel runs in. A template with a class label names it
// (substrateEffectiveClass). One without is placed by its pool, so the
// workers its selector and sel match say the class: the weakest of them,
// as the scheduler may pick any (GAP-0630: a template pinned to a microVM
// pool with --worker-label recorded gvisor). When no worker answers, the
// label rule stands.
func (s *SubstrateATEActions) createdClass(ctx context.Context, tmpl *ateapi.ActorTemplate, sel *ateapi.Selector, class string) string {
	labels := tmpl.GetWorkerSelector().GetMatchLabels()
	if labels[controller.SandboxClassLabel] != "" {
		return substrateEffectiveClass(tmpl, class)
	}
	workers, err := ateapi.AllWorkers(ctx, s.Client, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] template %s: read the workers for the sandbox class on records: %v\n", ateapi.Key(ateapi.RefOf(tmpl.GetMetadata())), err)
		return substrateEffectiveClass(tmpl, class)
	}
	merged := maps.Clone(labels)
	if merged == nil {
		merged = map[string]string{}
	}
	maps.Copy(merged, sel.GetMatchLabels())
	have := controller.WorkerClasses(workers, merged)
	for _, c := range have {
		if controller.ClassesMeet(have, c) {
			return c
		}
	}
	return substrateEffectiveClass(tmpl, class)
}

// classSelector is the worker selector an actor needs to run in class, on
// top of its template's (the scheduler ANDs the two): nil when the template
// already lands only on workers of that class, else one pool label that
// narrows the template's workers to that class. The pool decides the class,
// so the workers say which class a selector lands on: a template pinned to
// a microVM pool with --worker-label carries no class label (GAP-0386).
func (s *SubstrateATEActions) classSelector(ctx context.Context, tmpl *ateapi.ActorTemplate, class string) (*ateapi.Selector, error) {
	class = strings.ToLower(strings.TrimSpace(class))
	labels := tmpl.GetWorkerSelector().GetMatchLabels()
	named := strings.ToLower(labels[controller.SandboxClassLabel])
	if class == "" || config.SandboxClassSatisfies(orDefaultClass(named), class) {
		// Every actor is at least gVisor (D7), as the controller counts it;
		// a template built with --class names its class.
		return nil, nil
	}
	workers, err := ateapi.AllWorkers(ctx, s.Client, 0)
	if err != nil {
		return nil, fmt.Errorf("read the workers to place a %s actor: %w", class, err)
	}
	have := controller.WorkerClasses(workers, labels)
	if named == "" && controller.ClassesMeet(have, class) {
		return nil, nil
	}
	if len(labels) < maxSelectorLabels {
		for _, extra := range substrateClassLabels(workers, labels, class) {
			sel := maps.Clone(labels)
			if sel == nil {
				sel = map[string]string{}
			}
			sel[extra[0]] = extra[1]
			if controller.ClassesMeet(controller.WorkerClasses(workers, sel), class) {
				return &ateapi.Selector{MatchLabels: map[string]string{extra[0]: extra[1]}}, nil
			}
		}
	}
	return nil, &SubstrateClassUnavailable{Template: ateapi.Key(ateapi.RefOf(tmpl.GetMetadata())), Class: class, Have: strings.Join(have, ", ")}
}

func orDefaultClass(class string) string {
	if class == "" {
		return config.SubstrateSandboxGVisor
	}
	return class
}

// substrateClassLabels are the pool labels that may narrow labels to class,
// each a {key, value} the template does not set: SandboxClassLabel first,
// then the labels of the workers of that class that labels matches, in
// order.
func substrateClassLabels(workers []*ateapi.Worker, labels map[string]string, class string) [][2]string {
	var out [][2]string
	seen := map[[2]string]bool{}
	add := func(k, v string) {
		if _, set := labels[k]; set || seen[[2]string{k, v}] {
			return
		}
		seen[[2]string{k, v}] = true
		out = append(out, [2]string{k, v})
	}
	add(controller.SandboxClassLabel, class)
	var more [][2]string
	for _, w := range workers {
		// A worker labels selects that reports class (one that has not
		// reported counts as gvisor here).
		if !controller.ClassesMeet(controller.WorkerClasses([]*ateapi.Worker{w}, labels), class) {
			continue
		}
		for k, v := range w.GetLabels() {
			more = append(more, [2]string{k, v})
		}
	}
	slices.SortFunc(more, func(a, b [2]string) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return strings.Compare(a[1], b[1])
	})
	for _, kv := range more {
		add(kv[0], kv[1])
	}
	return out
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
	// A resume restores the actor's snapshot on a worker: seconds on an
	// idle node, a minute or more while one node restores many microVMs at
	// once. The control API client's default call deadline (10 s) cut those
	// resumes off and the actor was deleted (GAP-0468), so a resume gets
	// its own deadline.
	rctx, cancel := context.WithTimeout(ctx, substrateResumeTimeout)
	defer cancel()
	_, _, err := s.Client.ResumeActor(rctx, ateapi.Ref(atespace, name))
	switch {
	case ateapi.IsResourceExhausted(err):
		return fmt.Errorf("%w: %v", ErrSubstrateNoWorker, err)
	case err != nil && ctx.Err() == nil && substrateResumeBusy(err):
		return fmt.Errorf("%w: %v", ErrSubstrateResumeBusy, err)
	}
	return err
}

// substrateResumeTimeout bounds one resume (GAP-0468).
const substrateResumeTimeout = 3 * time.Minute

// substrateResumeBusy is a resume the control plane could not finish now
// (deadline, unavailable, aborted): the node or the control plane is busy,
// not broken.
func substrateResumeBusy(err error) bool {
	return ateapi.IsBusy(err) || errors.Is(err, context.DeadlineExceeded)
}

// ErrSubstrateNoWorker is a resume that no worker of the pool has room for
// (RESOURCE_EXHAUSTED, GAP-0167).
var ErrSubstrateNoWorker = errors.New("no worker has room for the actor")

// ErrSubstrateResumeBusy is a resume that did not finish in time because
// the node or the control plane is busy (GAP-0468): a retry can work.
var ErrSubstrateResumeBusy = errors.New("the cluster is busy starting other agents")

// Snapshots implements SubstrateSnapshotCounter: how many snapshots the
// cluster holds for the actor (ActorStatus.snapshots), which a delete
// removes with it (GAP-0474).
func (s *SubstrateATEActions) Snapshots(ctx context.Context, atespace, name string) (int, error) {
	a, err := s.Client.GetActor(ctx, ateapi.Ref(atespace, name))
	if err != nil {
		return 0, err
	}
	return len(a.GetStatus().GetSnapshots()), nil
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
