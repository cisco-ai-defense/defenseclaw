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

package bundle

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// ConfigMap names and limits.
const (
	StateConfigMap    = "defenseclaw-bundles"
	ReceiptsConfigMap = "defenseclaw-bundle-receipts"
	stateKey          = "state.json"
	receiptsKey       = "receipts.jsonl"
	// StageAll applies to every atespace no other stage names.
	StageAll     = "all"
	MaxStages    = 8
	MaxAtespaces = 256
	MaxReceipts  = 200
	// StateSchemaVersion is the state.json schema.
	StateSchemaVersion = 1
)

// Sources of a change.
const (
	SourceCLI   = "cli"
	SourceInbox = "inbox"
	SourceAdmin = "admin"
)

// Actions and results of a receipt.
const (
	ActionApply    = "apply"
	ActionRollback = "rollback"

	ResultApplied        = "applied"
	ResultAlreadyApplied = "already_applied"
	ResultRolledBack     = "rolled_back"
	ResultRefused        = "refused"
)

var (
	stageNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	atespaceNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Record is a bundle a stage applied.
type Record struct {
	BundleID       string    `json:"bundle_id"`
	Version        uint64    `json:"version"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	ArchiveSHA256  string    `json:"archive_sha256"`
	KeyID          string    `json:"key_id"`
	CreatedBy      string    `json:"created_by"`
	ChangeSummary  string    `json:"change_summary,omitempty"`
	AppliedAt      time.Time `json:"applied_at"`
	Source         string    `json:"source"`
}

// Stage is one rollout stage: the atespaces it covers and its bundles.
type Stage struct {
	// Atespaces are exact atespace names; ["*"] for the all stage.
	Atespaces []string `json:"atespaces"`
	Active    *Record  `json:"active,omitempty"`
	Previous  *Record  `json:"previous,omitempty"`
	// Floor is the highest version the stage ever applied; a new bundle
	// must be above it (a rollback does not lower it).
	Floor uint64 `json:"floor"`
}

// State is state.json.
type State struct {
	SchemaVersion int               `json:"schema_version"`
	Stages        map[string]*Stage `json:"stages"`
	// InboxSeen is the SHA-256 of the inbox entry last processed per stage,
	// so an unchanged inbox is not re-applied or re-receipted.
	InboxSeen map[string]string `json:"inbox_seen,omitempty"`
}

// Receipt records one apply or rollback, refused or not.
type Receipt struct {
	Time           time.Time `json:"time"`
	Action         string    `json:"action"`
	Source         string    `json:"source"`
	Stage          string    `json:"stage"`
	Atespaces      []string  `json:"atespaces,omitempty"`
	Result         string    `json:"result"`
	Code           string    `json:"code,omitempty"`
	Error          string    `json:"error,omitempty"`
	BundleID       string    `json:"bundle_id,omitempty"`
	Version        uint64    `json:"version,omitempty"`
	ManifestSHA256 string    `json:"manifest_sha256,omitempty"`
	KeyID          string    `json:"key_id,omitempty"`
	// Previous is the manifest SHA-256 of the bundle the stage had before.
	Previous string `json:"previous_manifest_sha256,omitempty"`
}

// Store reads and writes bundle state through ConfigMaps.
type Store struct {
	CM ConfigMaps
	// Anchors loads the current trust anchors (nil, err when missing or
	// invalid).
	Anchors func() (*eb.Anchors, error)
	// AnchorsFile, when set, is summarized in Status (key ids and
	// validity, never the keys).
	AnchorsFile string
	// Base is config.yaml; bundles are verified as layered over it.
	Base *config.Config
	Now  func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func archiveKey(sha string) string { return sha + ".dcbundle" }

type stateDoc struct {
	cm    *ConfigMap
	state *State
}

func (s *Store) read(ctx context.Context) (*stateDoc, error) {
	cm, err := s.CM.Get(ctx, StateConfigMap)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", StateConfigMap, err)
	}
	st := &State{SchemaVersion: StateSchemaVersion, Stages: map[string]*Stage{}}
	if cm == nil {
		return &stateDoc{state: st}, nil
	}
	if raw := cm.Data[stateKey]; raw != "" {
		if err := json.Unmarshal([]byte(raw), st); err != nil {
			return nil, refuse(CodeStateInvalid, StateConfigMap, "state.json is not readable: %v", err)
		}
		if st.SchemaVersion != StateSchemaVersion {
			return nil, refuse(CodeStateInvalid, StateConfigMap, "state.json schema %d (this build reads %d)", st.SchemaVersion, StateSchemaVersion)
		}
		if st.Stages == nil {
			st.Stages = map[string]*Stage{}
		}
	}
	return &stateDoc{cm: cm, state: st}, nil
}

// write stores the state with the archives it references (and no other).
// add holds new archives by SHA-256.
func (s *Store) write(ctx context.Context, d *stateDoc, add map[string][]byte) error {
	raw, err := json.MarshalIndent(d.state, "", "  ")
	if err != nil {
		return err
	}
	cm := &ConfigMap{Name: StateConfigMap, Data: map[string]string{stateKey: string(raw)}, BinaryData: map[string][]byte{}}
	keep := map[string]bool{}
	for _, st := range d.state.Stages {
		for _, r := range []*Record{st.Active, st.Previous} {
			if r != nil {
				keep[r.ArchiveSHA256] = true
			}
		}
	}
	for sha := range keep {
		if b, ok := add[sha]; ok {
			cm.BinaryData[archiveKey(sha)] = b
		} else if d.cm != nil {
			if b, ok := d.cm.BinaryData[archiveKey(sha)]; ok {
				cm.BinaryData[archiveKey(sha)] = b
			}
		}
		if _, ok := cm.BinaryData[archiveKey(sha)]; !ok {
			return refuse(CodeStateInvalid, StateConfigMap, "archive %s is missing", sha[:12])
		}
	}
	if d.cm == nil {
		return s.CM.Create(ctx, cm)
	}
	cm.ResourceVersion = d.cm.ResourceVersion
	return s.CM.Update(ctx, cm)
}

func (s *Store) archive(d *stateDoc, r *Record) ([]byte, error) {
	if d.cm == nil {
		return nil, refuse(CodeStateInvalid, StateConfigMap, "no state")
	}
	b, ok := d.cm.BinaryData[archiveKey(r.ArchiveSHA256)]
	if !ok {
		return nil, refuse(CodeStateInvalid, StateConfigMap, "the kept archive of %s version %d is missing", r.BundleID, r.Version)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != r.ArchiveSHA256 {
		return nil, refuse(CodeStateInvalid, StateConfigMap, "the kept archive of %s version %d was changed", r.BundleID, r.Version)
	}
	return b, nil
}

// normalizeStage checks a stage name and its atespaces.
func normalizeStage(stage string, atespaces []string) (string, []string, error) {
	stage = strings.TrimSpace(stage)
	if !stageNameRe.MatchString(stage) {
		return "", nil, refuse(CodeStageInvalid, "stage", "%q is not a stage name (lower-case letters, digits and '-')", stage)
	}
	if stage == StageAll {
		if len(atespaces) > 0 && !(len(atespaces) == 1 && atespaces[0] == "*") {
			return "", nil, refuse(CodeStageInvalid, "atespaces", "the all stage covers every atespace; name no atespaces")
		}
		return stage, []string{"*"}, nil
	}
	if len(atespaces) == 0 {
		return "", nil, refuse(CodeStageInvalid, "atespaces", "stage %s needs atespaces (or use the all stage)", stage)
	}
	if len(atespaces) > MaxAtespaces {
		return "", nil, refuse(CodeStageInvalid, "atespaces", "more than %d atespaces", MaxAtespaces)
	}
	out := make([]string, 0, len(atespaces))
	for _, a := range atespaces {
		a = strings.TrimSpace(a)
		if !atespaceNameRe.MatchString(a) {
			return "", nil, refuse(CodeStageInvalid, "atespaces", "%q is not an atespace name (globs are not allowed in a stage)", a)
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return stage, out, nil
}

// Apply verifies archive and makes it the active bundle of stage. Every
// outcome, refused or not, is returned as a receipt and recorded; err is
// the refusal or a storage error.
func (s *Store) Apply(ctx context.Context, archive []byte, stage string, atespaces []string, source string) (*Receipt, error) {
	rc := &Receipt{Time: s.now(), Action: ActionApply, Source: source, Stage: stage, Atespaces: atespaces}
	err := s.retry(ctx, func() error { return s.apply(ctx, archive, stage, atespaces, source, rc) })
	return s.finish(ctx, rc, err)
}

func (s *Store) apply(ctx context.Context, archive []byte, stage string, atespaces []string, source string, rc *Receipt) error {
	stage, atespaces, err := normalizeStage(stage, atespaces)
	if err != nil {
		return err
	}
	rc.Stage, rc.Atespaces = stage, atespaces
	d, err := s.read(ctx)
	if err != nil {
		return err
	}
	for name, st := range d.state.Stages {
		if name == stage || name == StageAll {
			continue
		}
		for _, a := range atespaces {
			if slices.Contains(st.Atespaces, a) {
				return refuse(CodeStageInvalid, "atespaces", "atespace %s is already in stage %s; remove it there first", a, name)
			}
		}
	}
	cur := d.state.Stages[stage]
	if cur == nil {
		if len(d.state.Stages) >= MaxStages {
			return refuse(CodeStageInvalid, "stage", "at most %d stages", MaxStages)
		}
		cur = &Stage{}
	}
	anchors, err := s.Anchors()
	if err != nil {
		return err
	}
	v, err := Verify(archive, anchors, s.Base, s.now(), Check{Active: cur.Active, Floor: cur.Floor})
	if v != nil {
		rc.BundleID, rc.Version, rc.ManifestSHA256, rc.KeyID = v.Manifest.BundleID, v.Manifest.Version, v.ManifestSHA256, v.KeyID
	} else if b, rerr := eb.ReadArchive(bytes.NewReader(archive)); rerr == nil {
		if m, merr := eb.DecodeManifest(b.Manifest); merr == nil {
			rc.BundleID, rc.Version = m.BundleID, m.Version
		}
		if sig, serr := eb.DecodeSignature(b.Signature); serr == nil {
			rc.KeyID = sig.KeyID
		}
	}
	if cur.Active != nil {
		rc.Previous = cur.Active.ManifestSHA256
	}
	if err != nil {
		return err
	}
	if v.AlreadyApplied && slices.Equal(cur.Atespaces, atespaces) {
		rc.Result = ResultAlreadyApplied
		return nil
	}
	if !v.AlreadyApplied {
		cur.Previous = cur.Active
		cur.Active = v.Record(s.now(), source)
		cur.Floor = max(cur.Floor, v.Manifest.Version)
	}
	cur.Atespaces = atespaces
	d.state.Stages[stage] = cur
	if err := s.write(ctx, d, map[string][]byte{v.ArchiveSHA256: archive}); err != nil {
		return err
	}
	rc.Result = ResultApplied
	return nil
}

// Rollback re-activates the stage's previous bundle, re-verified against
// the current anchors. The bundle it replaces becomes the previous one.
func (s *Store) Rollback(ctx context.Context, stage, source string) (*Receipt, error) {
	rc := &Receipt{Time: s.now(), Action: ActionRollback, Source: source, Stage: stage}
	err := s.retry(ctx, func() error { return s.rollback(ctx, stage, source, rc) })
	return s.finish(ctx, rc, err)
}

func (s *Store) rollback(ctx context.Context, stage, source string, rc *Receipt) error {
	d, err := s.read(ctx)
	if err != nil {
		return err
	}
	cur := d.state.Stages[stage]
	if cur == nil || cur.Previous == nil {
		return refuse(CodeNoPrevious, "stage", "stage %s has no previous bundle to roll back to", stage)
	}
	rc.Atespaces = cur.Atespaces
	if cur.Active != nil {
		rc.Previous = cur.Active.ManifestSHA256
	}
	prev := cur.Previous
	rc.BundleID, rc.Version, rc.ManifestSHA256, rc.KeyID = prev.BundleID, prev.Version, prev.ManifestSHA256, prev.KeyID
	archive, err := s.archive(d, prev)
	if err != nil {
		return err
	}
	anchors, err := s.Anchors()
	if err != nil {
		return err
	}
	v, err := Verify(archive, anchors, s.Base, s.now(), Check{Reactivate: true})
	if err != nil {
		return err
	}
	rec := v.Record(s.now(), source)
	cur.Previous, cur.Active = cur.Active, rec
	if err := s.write(ctx, d, nil); err != nil {
		return err
	}
	rc.Result = ResultRolledBack
	return nil
}

func (s *Store) retry(ctx context.Context, op func() error) error {
	var err error
	for range 4 {
		if err = op(); !errors.Is(err, ErrConflict) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return err
}

// finish fills the refusal into the receipt and records it.
func (s *Store) finish(ctx context.Context, rc *Receipt, err error) (*Receipt, error) {
	if err != nil {
		rc.Result = ResultRefused
		rc.Code = string(eb.CodeOf(err))
		if rc.Code == "" {
			rc.Code = string(eb.CodeApplyFailed)
		}
		rc.Error = bounded(err.Error())
	}
	if werr := s.appendReceipt(ctx, rc); werr != nil {
		return rc, errors.Join(err, fmt.Errorf("record the receipt: %w", werr))
	}
	return rc, err
}

func (s *Store) appendReceipt(ctx context.Context, rc *Receipt) error {
	line, err := json.Marshal(rc)
	if err != nil {
		return err
	}
	return s.retry(ctx, func() error {
		cm, err := s.CM.Get(ctx, ReceiptsConfigMap)
		if err != nil {
			return err
		}
		var lines []string
		if cm != nil {
			for l := range strings.SplitSeq(strings.TrimSpace(cm.Data[receiptsKey]), "\n") {
				if l != "" {
					lines = append(lines, l)
				}
			}
		}
		lines = append(lines, string(line))
		if len(lines) > MaxReceipts {
			lines = lines[len(lines)-MaxReceipts:]
		}
		out := &ConfigMap{Name: ReceiptsConfigMap, Data: map[string]string{receiptsKey: strings.Join(lines, "\n") + "\n"}}
		if cm == nil {
			return s.CM.Create(ctx, out)
		}
		out.ResourceVersion = cm.ResourceVersion
		return s.CM.Update(ctx, out)
	})
}

// Receipts returns the recorded receipts, oldest first, at most limit (0:
// all).
func (s *Store) Receipts(ctx context.Context, limit int) ([]Receipt, error) {
	cm, err := s.CM.Get(ctx, ReceiptsConfigMap)
	if err != nil || cm == nil {
		return nil, err
	}
	var out []Receipt
	sc := bufio.NewScanner(strings.NewReader(cm.Data[receiptsKey]))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var r Receipt
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			out = append(out, r)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// Applied is a stage's active bundle, verified, as the controller uses it.
type Applied struct {
	Stage  string
	Record Record
	Policy Policy
	// Config is config.yaml with the policy layered over it.
	Config *config.Config
}

// Snapshot is every stage's verified active bundle, by atespace.
type Snapshot struct {
	byAtespace map[string]*Applied
	all        *Applied
	// Atespaces are the atespaces stages name, sorted.
	Atespaces []string
	// failed are the stages whose active bundle no longer verifies, by
	// atespace (failedAll for stage all). In a managed install their
	// atespaces get deny-only until a trusted bundle is applied (D8).
	failed    map[string]Problem
	failedAll *Problem
}

// Failed reports the problem of the stage that covers atespace when its
// bundle no longer verifies (a stage naming the atespace wins over all).
func (s *Snapshot) Failed(atespace string) (Problem, bool) {
	if s == nil {
		return Problem{}, false
	}
	if _, ok := s.byAtespace[atespace]; ok {
		return Problem{}, false // a verified named stage covers it
	}
	if p, ok := s.failed[atespace]; ok {
		return p, true
	}
	if s.all == nil && s.failedAll != nil {
		return *s.failedAll, true
	}
	return Problem{}, false
}

// For returns the bundle that applies to atespace, nil for none.
func (s *Snapshot) For(atespace string) *Applied {
	if s == nil {
		return nil
	}
	if a, ok := s.byAtespace[atespace]; ok {
		return a
	}
	return s.all
}

// Problem is a stage whose active bundle no longer verifies: its atespaces
// fall back to config.yaml.
type Problem struct {
	Stage string `json:"stage"`
	Code  string `json:"code"`
	Error string `json:"error"`
}

// Load verifies every stage's active bundle against the current anchors
// and returns the snapshot. A stage that does not verify (the key was
// revoked, the anchors are gone, the kept archive was changed) is left out
// and reported, so its atespaces fall back to config.yaml.
func (s *Store) Load(ctx context.Context) (*Snapshot, []Problem, error) {
	d, err := s.read(ctx)
	if err != nil {
		return nil, nil, err
	}
	snap := &Snapshot{byAtespace: map[string]*Applied{}, failed: map[string]Problem{}}
	var problems []Problem
	anchors, aerr := s.Anchors()
	for _, name := range sortedStageNames(d.state.Stages) {
		st := d.state.Stages[name]
		if st.Active == nil {
			continue
		}
		fail := func(err error) {
			p := Problem{Stage: name, Code: string(eb.CodeOf(err)), Error: bounded(err.Error())}
			problems = append(problems, p)
			if name == StageAll {
				snap.failedAll = &p
				return
			}
			for _, a := range st.Atespaces {
				snap.failed[a] = p
				snap.Atespaces = append(snap.Atespaces, a)
			}
		}
		if aerr != nil {
			fail(aerr)
			continue
		}
		archive, err := s.archive(d, st.Active)
		if err != nil {
			fail(err)
			continue
		}
		v, err := Verify(archive, anchors, s.Base, s.now(), Check{Reactivate: true})
		if err != nil {
			fail(err)
			continue
		}
		if v.ManifestSHA256 != st.Active.ManifestSHA256 {
			fail(refuse(CodeStateInvalid, StateConfigMap, "the kept bundle of stage %s is not the recorded one", name))
			continue
		}
		ap := &Applied{Stage: name, Record: *st.Active, Policy: v.Policy, Config: v.Policy.Overlay(s.Base)}
		if name == StageAll {
			snap.all = ap
			continue
		}
		for _, a := range st.Atespaces {
			snap.byAtespace[a] = ap
			snap.Atespaces = append(snap.Atespaces, a)
		}
	}
	sort.Strings(snap.Atespaces)
	return snap, problems, nil
}

func sortedStageNames(m map[string]*Stage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Status is what bundle status shows.
type Status struct {
	Stages   map[string]*Stage  `json:"stages"`
	Problems []Problem          `json:"problems,omitempty"`
	Anchors  *eb.AnchorsSummary `json:"anchors,omitempty"`
	// AnchorsError says why the anchors could not be read.
	AnchorsError string    `json:"anchors_error,omitempty"`
	Receipts     []Receipt `json:"receipts,omitempty"`
}

// Status reads the state, re-verifies it and lists the last receipts.
func (s *Store) Status(ctx context.Context, receipts int) (*Status, error) {
	d, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	_, problems, err := s.Load(ctx)
	if err != nil {
		return nil, err
	}
	out := &Status{Stages: d.state.Stages, Problems: problems}
	if _, err := s.Anchors(); err != nil {
		out.AnchorsError = bounded(err.Error())
	} else if s.AnchorsFile != "" {
		if a, raw, err := ReadAnchorsFile(s.AnchorsFile); err == nil {
			out.Anchors = eb.SummarizeAnchors(a, raw)
		}
	}
	if out.Receipts, err = s.Receipts(ctx, receipts); err != nil {
		return nil, err
	}
	return out, nil
}

// Inbox keys: <stage>.dcbundle (binaryData) and <stage>.atespaces (data,
// comma or newline separated; ignored for the all stage).
const (
	inboxBundleSuffix    = ".dcbundle"
	inboxAtespacesSuffix = ".atespaces"
)

// SyncInbox applies every inbox entry that changed since it was last
// processed (GitOps). A refused entry is receipted once and leaves the
// stage as it was.
func (s *Store) SyncInbox(ctx context.Context, inbox string) ([]Receipt, error) {
	cm, err := s.CM.Get(ctx, inbox)
	if err != nil || cm == nil {
		return nil, err
	}
	d, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	var out []Receipt
	keys := make([]string, 0, len(cm.BinaryData))
	for k := range cm.BinaryData {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		stage, ok := strings.CutSuffix(k, inboxBundleSuffix)
		if !ok {
			continue
		}
		archive := cm.BinaryData[k]
		var atespaces []string
		for a := range strings.FieldsFuncSeq(cm.Data[stage+inboxAtespacesSuffix], func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
			atespaces = append(atespaces, a)
		}
		h := sha256.New()
		h.Write(archive)
		h.Write([]byte{0})
		h.Write([]byte(strings.Join(atespaces, ",")))
		seen := hex.EncodeToString(h.Sum(nil))
		if d.state.InboxSeen[stage] == seen {
			continue
		}
		rc, aerr := s.Apply(ctx, archive, stage, atespaces, SourceInbox)
		if rc != nil {
			out = append(out, *rc)
		}
		if aerr != nil && eb.CodeOf(aerr) == "" {
			return out, aerr // storage error: retry next pass
		}
		if err := s.retry(ctx, func() error { return s.markSeen(ctx, stage, seen) }); err != nil {
			return out, err
		}
		if d, err = s.read(ctx); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (s *Store) markSeen(ctx context.Context, stage, seen string) error {
	d, err := s.read(ctx)
	if err != nil {
		return err
	}
	if d.state.InboxSeen == nil {
		d.state.InboxSeen = map[string]string{}
	}
	d.state.InboxSeen[stage] = seen
	return s.write(ctx, d, nil)
}
