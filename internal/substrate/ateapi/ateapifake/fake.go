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

// Package ateapifake is an in-memory ateapi.Client for tests. It keeps the
// server behaviour DefenseClaw depends on: uid/version guards that fail with
// ABORTED, ALREADY_EXISTS on a repeated create, NOT_FOUND, paginated lists,
// singleton "default" egress policies, and tags that seed new actors (forks).
// Helpers set up state, inject failures, simulate a foreign policy writer
// and record every policy write with the actor's state at that moment.
package ateapifake

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// DefaultPageSize is the page size when a caller asks for none.
const DefaultPageSize = 50

// PolicyWrite is one change to an actor's egress policy.
type PolicyWrite struct {
	// Method is "create", "update", "delete" or "foreign" (ForeignSetPolicy).
	Method string
	// Key is "<atespace>/<actor>".
	Key string
	// ActorUID and ActorState are the actor's at the time of the write.
	ActorUID   string
	ActorState ateapi.ActorState
	// Version is the policy version after the write (0 for delete).
	Version int64
	Rules   int
	At      time.Time
}

// Fake is an in-memory Substrate control plane. The zero value is not
// usable; call New.
type Fake struct {
	// Err, when set, runs before every call with the method name (as in
	// the Client interface, e.g. "UpdateActorEgressPolicy") and the target
	// key; a non-nil result fails the call unchanged.
	Err func(method, key string) error
	// PageSize overrides DefaultPageSize.
	PageSize int
	// Now overrides time.Now.
	Now func() time.Time

	mu        sync.Mutex
	atespaces map[string]*ateapi.Atespace
	templates map[string]*ateapi.ActorTemplate
	actors    map[string]*ateapi.Actor
	policies  map[string]*ateapi.EgressPolicy
	tags      map[string]*ateapi.Tag
	access    map[string]*ateapi.AccessPolicy // by atespace, "" global
	calls     map[string]int
	writes    []PolicyWrite
	closed    bool
	// epoch numbers the worker processes actors run under.
	epoch int64
}

var _ ateapi.Client = (*Fake)(nil)

// New returns an empty Fake.
func New() *Fake {
	return &Fake{
		atespaces: map[string]*ateapi.Atespace{},
		templates: map[string]*ateapi.ActorTemplate{},
		actors:    map[string]*ateapi.Actor{},
		policies:  map[string]*ateapi.EgressPolicy{},
		tags:      map[string]*ateapi.Tag{},
		access:    map[string]*ateapi.AccessPolicy{},
		calls:     map[string]int{},
	}
}

func (f *Fake) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func clone[T proto.Message](m T) T { return proto.Clone(m).(T) }

func key(r *ateapi.ObjectRef) string { return ateapi.Key(r) }

// enter counts the call and runs Err. The caller holds no lock.
func (f *Fake) enter(method, k string) error {
	f.mu.Lock()
	f.calls[method]++
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return status.Error(codes.Canceled, "ateapifake: client is closed")
	}
	if f.Err != nil {
		return f.Err(method, k)
	}
	return nil
}

func (f *Fake) newMeta(atespace, name string) *ateapi.ResourceMetadata {
	ts := timestamppb.New(f.now())
	return &ateapi.ResourceMetadata{Atespace: atespace, Name: name, Uid: uuid.NewString(), Version: 1, CreateTime: ts, UpdateTime: ts}
}

func (f *Fake) bump(m *ateapi.ResourceMetadata) {
	m.Version++
	m.UpdateTime = timestamppb.New(f.now())
}

// ---- setup helpers ----

// PutAtespace creates or keeps an atespace.
func (f *Fake) PutAtespace(name string) *ateapi.Atespace {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.atespaces[name]; ok {
		return clone(a)
	}
	a := &ateapi.Atespace{Metadata: f.newMeta("", name)}
	f.atespaces[name] = a
	return clone(a)
}

// PutTemplate stores a template (its atespace is created if missing) and
// returns it with server metadata.
func (f *Fake) PutTemplate(t *ateapi.ActorTemplate) *ateapi.ActorTemplate {
	ns := t.GetMetadata().GetAtespace()
	f.PutAtespace(ns)
	f.mu.Lock()
	defer f.mu.Unlock()
	t = clone(t)
	k := ns + "/" + t.GetMetadata().GetName()
	if old, ok := f.templates[k]; ok {
		t.Metadata = old.GetMetadata()
		f.bump(t.Metadata)
	} else {
		t.Metadata = f.newMeta(ns, t.GetMetadata().GetName())
	}
	f.templates[k] = t
	return clone(t)
}

// PutActor stores a new actor (state SUSPENDED unless set) and returns it
// with server metadata.
func (f *Fake) PutActor(a *ateapi.Actor) *ateapi.Actor {
	ns := a.GetMetadata().GetAtespace()
	f.PutAtespace(ns)
	f.mu.Lock()
	defer f.mu.Unlock()
	a = clone(a)
	a.Metadata = f.newMeta(ns, a.GetMetadata().GetName())
	if a.Status == nil {
		a.Status = &ateapi.ActorStatus{}
	}
	if a.Status.State == ateapi.ActorStateUnspecified {
		a.Status.State = ateapi.ActorStateSuspended
	}
	f.actors[key(ateapi.RefOf(a.Metadata))] = a
	return clone(a)
}

// SetState moves an actor to state, as a resume, suspend or crash would.
func (f *Fake) SetState(ref *ateapi.ObjectRef, state ateapi.ActorState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.actors[key(ref)]
	if !ok {
		return status.Errorf(codes.NotFound, "actor %s not found", key(ref))
	}
	switch {
	case state == a.Status.State:
	case state == ateapi.ActorStateSuspended && a.Status.State == ateapi.ActorStateRunning:
		// A suspend takes a new snapshot generation, as SuspendActor does.
		f.suspendLocked(a)
	case state == ateapi.ActorStateRunning:
		f.runLocked(a)
	default:
		if state == ateapi.ActorStateCrashed || state == ateapi.ActorStateSuspended {
			a.Status.WorkerAssignment = nil
		}
		a.Status.State = state
	}
	f.bump(a.Metadata)
	return nil
}

// fakeNode is the node that holds the fake's node-local snapshots.
const fakeNode = "fake-node-1"

// suspendLocked takes a new snapshot generation, as an async SuspendActor
// does on a real cluster (E1, substrate-1 f8): the newest snapshot is
// last_assigned_generation, its files stay on the node (locality and
// assigned_node) and its upload is PENDING.
func (f *Fake) suspendLocked(a *ateapi.Actor) {
	s := a.Status
	s.LastAssignedGeneration++
	s.Snapshots = append(s.Snapshots, &ateapi.Snapshot{Uuid: uuid.NewString(), Generation: s.LastAssignedGeneration,
		Owner: ateapi.SnapshotOwnerActor, Fidelity: ateapi.SnapshotFidelityMemory, Locality: fakeNode,
		DurableSnapshot: &ateapi.SnapshotStorage{State: ateapi.SnapshotStoragePending}})
	s.AssignedNode, s.WorkerAssignment = fakeNode, nil
	s.State = ateapi.ActorStateSuspended
}

// runLocked places the actor on a new worker process (worker_epoch), as a
// resume does. A resume keeps the snapshot files on the node.
func (f *Fake) runLocked(a *ateapi.Actor) {
	f.epoch++
	a.Status.AssignedNode = fakeNode
	a.Status.WorkerAssignment = &ateapi.WorkerAssignment{WorkerPod: "worker-" + strconv.FormatInt(f.epoch, 10),
		WorkerPodUid: uuid.NewString(), NodeName: fakeNode, WorkerEpoch: f.epoch}
	a.Status.State = ateapi.ActorStateRunning
}

// head is the actor's newest snapshot, nil for none.
func head(s *ateapi.ActorStatus) *ateapi.Snapshot {
	var h *ateapi.Snapshot
	for _, sn := range s.GetSnapshots() {
		if h == nil || sn.GetGeneration() > h.GetGeneration() {
			h = sn
		}
	}
	return h
}

// Revert moves an actor back to SUSPENDED at its durable snapshot, as
// RevertActor does on a real cluster (E1, substrate-1 f8): no new snapshot
// generation; a newest snapshot not yet uploaded becomes stale and leaves
// the list, an uploaded one loses its node-local files; assigned_node is
// cleared. A SUSPENDED actor needs a node-local snapshot to revert.
func (f *Fake) Revert(ref *ateapi.ObjectRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.actors[key(ref)]
	if !ok {
		return status.Errorf(codes.NotFound, "actor %s not found", key(ref))
	}
	s := a.Status
	h := head(s)
	switch s.State {
	case ateapi.ActorStateRunning, ateapi.ActorStateCrashed:
	case ateapi.ActorStateSuspended:
		if h.GetLocality() == "" {
			return status.Errorf(codes.FailedPrecondition, "actor %s is already at its durable snapshot", key(ref))
		}
	default:
		return status.Errorf(codes.FailedPrecondition, "actor %s is %s", key(ref), s.State)
	}
	switch {
	case h == nil:
	case h.GetDurableSnapshot().GetState() == ateapi.SnapshotStorageCompleted:
		h.Locality = ""
	default:
		s.Snapshots = slices.DeleteFunc(s.Snapshots, func(x *ateapi.Snapshot) bool { return x == h })
	}
	s.State, s.AssignedNode, s.WorkerAssignment = ateapi.ActorStateSuspended, "", nil
	f.bump(a.Metadata)
	return nil
}

// CompleteUpload marks the actor's newest snapshot uploaded, as a sync
// suspend or a finished async upload leaves it (the files stay on the node).
func (f *Fake) CompleteUpload(ref *ateapi.ObjectRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.actors[key(ref)]
	if !ok {
		return status.Errorf(codes.NotFound, "actor %s not found", key(ref))
	}
	h := head(a.Status)
	if h == nil {
		return status.Errorf(codes.FailedPrecondition, "actor %s has no snapshot", key(ref))
	}
	h.DurableSnapshot = &ateapi.SnapshotStorage{State: ateapi.SnapshotStorageCompleted}
	f.bump(a.Metadata)
	return nil
}

// RemoveActor deletes an actor and its policy, as DeleteActor would.
func (f *Fake) RemoveActor(ref *ateapi.ObjectRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.actors, key(ref))
	delete(f.policies, key(ref))
}

// Recreate deletes an actor and creates another under the same name, with a
// new UID and no policy.
func (f *Fake) Recreate(ref *ateapi.ObjectRef) (*ateapi.Actor, error) {
	f.mu.Lock()
	old, ok := f.actors[key(ref)]
	f.mu.Unlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "actor %s not found", key(ref))
	}
	f.RemoveActor(ref)
	return f.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: ref.GetAtespace(), Name: ref.GetName()}, ActorTemplate: old.GetActorTemplate()}), nil
}

// Fork tags the suspended actor src as tagName and creates actor newName
// from that tag, as `kubectl ate fork` does. The child has a new UID and no
// policy.
func (f *Fake) Fork(src *ateapi.ObjectRef, tagName, newName string) (*ateapi.Actor, error) {
	tag, err := f.CreateTag(context.Background(), &ateapi.Tag{
		Metadata:    &ateapi.ResourceMetadata{Atespace: src.GetAtespace(), Name: tagName},
		SourceActor: src,
	})
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	parent := f.actors[key(src)]
	tmpl := clone(parent.GetActorTemplate())
	f.mu.Unlock()
	return f.PutActor(&ateapi.Actor{
		Metadata:      &ateapi.ResourceMetadata{Atespace: src.GetAtespace(), Name: newName},
		ActorTemplate: tmpl,
		SourceTag:     ateapi.RefOf(tag.GetMetadata()),
	}), nil
}

// ForeignSetPolicy replaces (or creates) an actor's policy as another writer
// would (kubectl ate, GitOps), bumping its version.
func (f *Fake) ForeignSetPolicy(ref *ateapi.ObjectRef, rules []*ateapi.EgressRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.actors[key(ref)]
	if !ok {
		return status.Errorf(codes.NotFound, "actor %s not found", key(ref))
	}
	p, ok := f.policies[key(ref)]
	if !ok {
		p = &ateapi.EgressPolicy{Metadata: f.newMeta(ref.GetAtespace(), ateapi.PolicyName)}
		f.policies[key(ref)] = p
	} else {
		f.bump(p.Metadata)
	}
	p.Rules = cloneRules(rules)
	f.record("foreign", ref, a, p.Metadata.Version, len(rules))
	return nil
}

// Policy returns a copy of an actor's policy, or nil.
func (f *Fake) Policy(ref *ateapi.ObjectRef) *ateapi.EgressPolicy {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.policies[key(ref)]; ok {
		return clone(p)
	}
	return nil
}

// Calls is how often method was called.
func (f *Fake) Calls(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

// PolicyWrites is every policy change so far, in order.
func (f *Fake) PolicyWrites() []PolicyWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.writes)
}

func (f *Fake) record(method string, ref *ateapi.ObjectRef, a *ateapi.Actor, version int64, rules int) {
	f.writes = append(f.writes, PolicyWrite{
		Method: method, Key: key(ref), ActorUID: a.GetMetadata().GetUid(), ActorState: a.GetStatus().GetState(),
		Version: version, Rules: rules, At: f.now(),
	})
}

func cloneRules(rules []*ateapi.EgressRule) []*ateapi.EgressRule {
	out := make([]*ateapi.EgressRule, len(rules))
	for i, r := range rules {
		out[i] = clone(r)
	}
	return out
}

// ---- Client ----

// Close marks the fake closed; later calls fail with CANCELED.
func (f *Fake) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *Fake) GetActor(_ context.Context, ref *ateapi.ObjectRef) (*ateapi.Actor, error) {
	if err := f.enter("GetActor", key(ref)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.actors[key(ref)]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "actor %s not found", key(ref))
	}
	return clone(a), nil
}

func (f *Fake) ListActors(_ context.Context, atespace string, opts ateapi.ListOptions) (ateapi.Page[*ateapi.Actor], error) {
	if err := f.enter("ListActors", atespace); err != nil {
		return ateapi.Page[*ateapi.Actor]{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return page(f.actors, atespace, opts, f.pageSize())
}

func (f *Fake) SuspendActor(_ context.Context, ref *ateapi.ObjectRef) (*ateapi.Actor, error) {
	if err := f.enter("SuspendActor", key(ref)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.actors[key(ref)]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "actor %s not found", key(ref))
	}
	switch a.Status.State {
	case ateapi.ActorStateSuspended:
	case ateapi.ActorStateRunning:
		f.suspendLocked(a)
		f.bump(a.Metadata)
	default:
		return nil, status.Errorf(codes.FailedPrecondition, "actor %s is %s", key(ref), a.Status.State)
	}
	return clone(a), nil
}

// CreateActor creates a SUSPENDED actor from an existing template, as
// ate-api-server does.
func (f *Fake) CreateActor(_ context.Context, a *ateapi.Actor) (*ateapi.Actor, error) {
	ref := ateapi.RefOf(a.GetMetadata())
	if err := f.enter("CreateActor", key(ref)); err != nil {
		return nil, err
	}
	if ref.GetAtespace() == "" || ref.GetName() == "" || a.GetActorTemplate().GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "atespace, name and template are required")
	}
	f.mu.Lock()
	_, exists := f.actors[key(ref)]
	_, tmpl := f.templates[key(a.GetActorTemplate())]
	f.mu.Unlock()
	switch {
	case exists:
		return nil, status.Errorf(codes.AlreadyExists, "actor %s already exists", key(ref))
	case !tmpl:
		return nil, status.Errorf(codes.NotFound, "actor template %s not found", key(a.GetActorTemplate()))
	}
	a = clone(a)
	a.Status = &ateapi.ActorStatus{State: ateapi.ActorStateSuspended}
	return f.PutActor(a), nil
}

// ResumeActor moves a SUSPENDED actor to RUNNING.
func (f *Fake) ResumeActor(_ context.Context, ref *ateapi.ObjectRef) (*ateapi.Actor, bool, error) {
	if err := f.enter("ResumeActor", key(ref)); err != nil {
		return nil, false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.actors[key(ref)]
	if !ok {
		return nil, false, status.Errorf(codes.NotFound, "actor %s not found", key(ref))
	}
	switch a.Status.State {
	case ateapi.ActorStateRunning:
		return clone(a), false, nil
	case ateapi.ActorStateSuspended:
		f.runLocked(a)
		f.bump(a.Metadata)
		return clone(a), true, nil
	}
	return nil, false, status.Errorf(codes.FailedPrecondition, "actor %s is %s", key(ref), a.Status.State)
}

// DeleteActor removes an actor and its policy; opts.Uid and opts.Version
// are preconditions.
func (f *Fake) DeleteActor(_ context.Context, ref *ateapi.ObjectRef, opts *ateapi.DeleteOptions) (*ateapi.Actor, error) {
	if err := f.enter("DeleteActor", key(ref)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.actors[key(ref)]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "actor %s not found", key(ref))
	}
	if u := opts.GetUid(); u != "" && u != a.GetMetadata().GetUid() {
		return nil, status.Errorf(codes.Aborted, "actor %s has another uid", key(ref))
	}
	if v := opts.GetVersion(); v != 0 && v != a.GetMetadata().GetVersion() {
		return nil, status.Errorf(codes.Aborted, "actor %s has another version", key(ref))
	}
	out := clone(a)
	out.Status.State = ateapi.ActorStateDeleting
	delete(f.actors, key(ref))
	delete(f.policies, key(ref))
	return out, nil
}

func (f *Fake) GetActorEgressPolicy(_ context.Context, ref *ateapi.ObjectRef) (*ateapi.EgressPolicy, error) {
	if err := f.enter("GetActorEgressPolicy", key(ref)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.policies[key(ref)]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "egress policy of %s not found", key(ref))
	}
	return clone(p), nil
}

func (f *Fake) checkPolicy(ref *ateapi.ObjectRef, p *ateapi.EgressPolicy) (*ateapi.Actor, error) {
	a, ok := f.actors[key(ref)]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "actor %s not found", key(ref))
	}
	if a.Status.State == ateapi.ActorStateDeleting {
		return nil, status.Errorf(codes.FailedPrecondition, "actor %s is being deleted", key(ref))
	}
	if n := p.GetMetadata().GetName(); n != "" && n != ateapi.PolicyName {
		return nil, status.Errorf(codes.InvalidArgument, "egress_policy.metadata.name: must be %q", ateapi.PolicyName)
	}
	if ns := p.GetMetadata().GetAtespace(); ns != "" && ns != ref.GetAtespace() {
		return nil, status.Error(codes.InvalidArgument, "egress_policy.metadata.atespace: must match actor.atespace")
	}
	if len(p.GetRules()) > 256 {
		return nil, status.Error(codes.InvalidArgument, "egress_policy.rules: must have at most 256 items")
	}
	return a, nil
}

func (f *Fake) CreateActorEgressPolicy(_ context.Context, ref *ateapi.ObjectRef, p *ateapi.EgressPolicy) (*ateapi.EgressPolicy, error) {
	if err := f.enter("CreateActorEgressPolicy", key(ref)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a, err := f.checkPolicy(ref, p)
	if err != nil {
		return nil, err
	}
	if _, ok := f.policies[key(ref)]; ok {
		return nil, status.Errorf(codes.AlreadyExists, "egress policy of %s already exists", key(ref))
	}
	np := &ateapi.EgressPolicy{Metadata: f.newMeta(ref.GetAtespace(), ateapi.PolicyName), Rules: cloneRules(p.GetRules())}
	f.policies[key(ref)] = np
	f.record("create", ref, a, np.Metadata.Version, len(np.Rules))
	return clone(np), nil
}

func (f *Fake) UpdateActorEgressPolicy(_ context.Context, ref *ateapi.ObjectRef, p *ateapi.EgressPolicy) (*ateapi.EgressPolicy, error) {
	if err := f.enter("UpdateActorEgressPolicy", key(ref)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a, err := f.checkPolicy(ref, p)
	if err != nil {
		return nil, err
	}
	cur, ok := f.policies[key(ref)]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "egress policy of %s not found", key(ref))
	}
	m := p.GetMetadata()
	if m.GetUid() == "" || m.GetVersion() == 0 {
		return nil, status.Error(codes.InvalidArgument, "egress_policy.metadata: uid and version are required")
	}
	if m.GetUid() != cur.Metadata.Uid || m.GetVersion() != cur.Metadata.Version {
		return nil, status.Errorf(codes.Aborted, "egress policy of %s changed (version %d)", key(ref), cur.Metadata.Version)
	}
	cur.Rules = cloneRules(p.GetRules())
	f.bump(cur.Metadata)
	f.record("update", ref, a, cur.Metadata.Version, len(cur.Rules))
	return clone(cur), nil
}

func (f *Fake) DeleteActorEgressPolicy(_ context.Context, ref *ateapi.ObjectRef, opts *ateapi.DeleteOptions) (*ateapi.EgressPolicy, error) {
	if err := f.enter("DeleteActorEgressPolicy", key(ref)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.policies[key(ref)]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "egress policy of %s not found", key(ref))
	}
	if (opts.GetUid() != "" && opts.GetUid() != cur.Metadata.Uid) || (opts.GetVersion() != 0 && opts.GetVersion() != cur.Metadata.Version) {
		return nil, status.Errorf(codes.Aborted, "egress policy of %s changed", key(ref))
	}
	delete(f.policies, key(ref))
	f.record("delete", ref, f.actors[key(ref)], 0, 0)
	return clone(cur), nil
}

func (f *Fake) CreateTag(_ context.Context, t *ateapi.Tag) (*ateapi.Tag, error) {
	ref := ateapi.RefOf(t.GetMetadata())
	if err := f.enter("CreateTag", key(ref)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.tags[key(ref)]; ok {
		return nil, status.Errorf(codes.AlreadyExists, "tag %s already exists", key(ref))
	}
	if t.GetSourceActor().GetAtespace() != ref.GetAtespace() {
		return nil, status.Error(codes.InvalidArgument, "tag.metadata.atespace: must match source_actor")
	}
	src, ok := f.actors[key(t.GetSourceActor())]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "actor %s not found", key(t.GetSourceActor()))
	}
	if src.Status.State != ateapi.ActorStateSuspended {
		return nil, status.Errorf(codes.FailedPrecondition, "actor %s is %s, not suspended", key(t.GetSourceActor()), src.Status.State)
	}
	nt := clone(t)
	nt.Metadata = f.newMeta(ref.GetAtespace(), ref.GetName())
	tmplUID := ""
	if tm, ok := f.templates[key(src.GetActorTemplate())]; ok {
		tmplUID = tm.GetMetadata().GetUid()
	}
	nt.Status = &ateapi.TagStatus{ActorTemplateUid: tmplUID}
	f.tags[key(ref)] = nt
	return clone(nt), nil
}

func (f *Fake) GetTag(_ context.Context, ref *ateapi.ObjectRef) (*ateapi.Tag, error) {
	if err := f.enter("GetTag", key(ref)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tags[key(ref)]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "tag %s not found", key(ref))
	}
	return clone(t), nil
}

func (f *Fake) GetActorTemplate(_ context.Context, ref *ateapi.ObjectRef) (*ateapi.ActorTemplate, error) {
	if err := f.enter("GetActorTemplate", key(ref)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.templates[key(ref)]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "actor template %s not found", key(ref))
	}
	return clone(t), nil
}

// CreateActorTemplate stores a new template the way ate-api-server admits one:
// the atespace must exist, the name must be unused, there must be at least one
// container, every container image must be pinned by digest, and the template
// must set both a cpu and a memory limit. Server metadata is assigned and any
// status is dropped.
func (f *Fake) CreateActorTemplate(_ context.Context, t *ateapi.ActorTemplate) (*ateapi.ActorTemplate, error) {
	ns, name := t.GetMetadata().GetAtespace(), t.GetMetadata().GetName()
	if err := f.enter("CreateActorTemplate", ns+"/"+name); err != nil {
		return nil, err
	}
	if ns == "" || name == "" {
		return nil, status.Error(codes.InvalidArgument, "actor_template.metadata: atespace and name are required")
	}
	if len(t.GetContainers()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "actor_template.containers: at least one container is required")
	}
	for _, c := range t.GetContainers() {
		if !strings.Contains(c.GetImage(), "@sha256:") {
			return nil, status.Errorf(codes.InvalidArgument, "actor_template.containers[%s].image: must be pinned by digest", c.GetName())
		}
	}
	if lim := t.GetResources().GetLimits(); lim.GetCpuMillicores() <= 0 || lim.GetMemoryBytes() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "actor_template.resources: cpu and memory limits are both required")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.atespaces[ns]; !ok {
		return nil, status.Errorf(codes.NotFound, "atespace %s not found", ns)
	}
	k := ns + "/" + name
	if _, ok := f.templates[k]; ok {
		return nil, status.Errorf(codes.AlreadyExists, "actor template %s already exists", k)
	}
	nt := clone(t)
	nt.Metadata = f.newMeta(ns, name)
	nt.Status = nil
	f.templates[k] = nt
	return clone(nt), nil
}

func (f *Fake) ListActorTemplates(_ context.Context, atespace string, opts ateapi.ListOptions) (ateapi.Page[*ateapi.ActorTemplate], error) {
	if err := f.enter("ListActorTemplates", atespace); err != nil {
		return ateapi.Page[*ateapi.ActorTemplate]{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return page(f.templates, atespace, opts, f.pageSize())
}

func (f *Fake) CreateAtespace(_ context.Context, name string) (*ateapi.Atespace, error) {
	if err := f.enter("CreateAtespace", name); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.atespaces[name]; ok {
		return nil, status.Errorf(codes.AlreadyExists, "atespace %s exists", name)
	}
	a := &ateapi.Atespace{Metadata: f.newMeta("", name)}
	f.atespaces[name] = a
	return clone(a), nil
}

func (f *Fake) GetAccessPolicy(_ context.Context, atespace string) (*ateapi.AccessPolicy, error) {
	if err := f.enter("GetAccessPolicy", atespace); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.access[atespace]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "access policy of %q not found", atespace)
	}
	return clone(p), nil
}

func (f *Fake) CreateAccessPolicy(_ context.Context, atespace string, p *ateapi.AccessPolicy) (*ateapi.AccessPolicy, error) {
	if err := f.enter("CreateAccessPolicy", atespace); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.access[atespace]; ok {
		return nil, status.Errorf(codes.AlreadyExists, "access policy of %q exists", atespace)
	}
	if p.GetMetadata().GetAtespace() != "" {
		return nil, status.Error(codes.InvalidArgument, "access policy metadata must not name an atespace")
	}
	np := clone(p)
	np.Metadata = f.newMeta("", ateapi.AccessPolicyName)
	f.access[atespace] = np
	return clone(np), nil
}

func (f *Fake) UpdateAccessPolicy(_ context.Context, atespace string, p *ateapi.AccessPolicy) (*ateapi.AccessPolicy, error) {
	if err := f.enter("UpdateAccessPolicy", atespace); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.access[atespace]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "access policy of %q not found", atespace)
	}
	if p.GetMetadata().GetUid() != cur.Metadata.Uid || p.GetMetadata().GetVersion() != cur.Metadata.Version {
		return nil, status.Errorf(codes.Aborted, "access policy of %q changed", atespace)
	}
	cur.Bindings = clone(p).Bindings
	f.bump(cur.Metadata)
	return clone(cur), nil
}

func (f *Fake) GetAtespace(_ context.Context, name string) (*ateapi.Atespace, error) {
	if err := f.enter("GetAtespace", name); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.atespaces[name]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "atespace %s not found", name)
	}
	return clone(a), nil
}

func (f *Fake) ListAtespaces(_ context.Context, opts ateapi.ListOptions) (ateapi.Page[*ateapi.Atespace], error) {
	if err := f.enter("ListAtespaces", ""); err != nil {
		return ateapi.Page[*ateapi.Atespace]{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return page(f.atespaces, "", opts, f.pageSize())
}

func (f *Fake) pageSize() int {
	if f.PageSize > 0 {
		return f.PageSize
	}
	return DefaultPageSize
}

// page returns one page of m's values whose key starts with "<atespace>/"
// (every value when atespace is empty), ordered by key. The token is an
// opaque offset.
func page[T proto.Message](m map[string]T, atespace string, opts ateapi.ListOptions, def int) (ateapi.Page[T], error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		if atespace == "" || strings.HasPrefix(k, atespace+"/") {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	off := 0
	if opts.PageToken != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(opts.PageToken, "o"))
		if err != nil || !strings.HasPrefix(opts.PageToken, "o") || n < 0 || n > len(keys) {
			return ateapi.Page[T]{}, status.Error(codes.InvalidArgument, "options.page_token: invalid")
		}
		off = n
	}
	size := int(opts.PageSize)
	if size <= 0 {
		size = def
	}
	size = min(size, ateapi.MaxPageSize)
	end := min(off+size, len(keys))
	out := ateapi.Page[T]{Items: make([]T, 0, end-off)}
	for _, k := range keys[off:end] {
		out.Items = append(out.Items, clone(m[k]))
	}
	if end < len(keys) {
		out.NextPageToken = fmt.Sprintf("o%d", end)
	}
	return out, nil
}
