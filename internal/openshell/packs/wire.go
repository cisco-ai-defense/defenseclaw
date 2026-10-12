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

package packs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"gopkg.in/yaml.v3"
)

// EffectiveWireVersion is the "v" of an Effective's wire form.
const EffectiveWireVersion = 1

// errViewOnly refuses a runtime decision on a policy view (UnmarshalJSON).
var errViewOnly = errors.New("sandbox policy: a policy view decides no runtime action; resolve the run")

// effectiveFields is Effective without its methods, so the wire form can
// embed its exported fields without recursing into MarshalJSON.
type effectiveFields Effective

// effectiveWire is an Effective's JSON wire form (the managed gateway's
// sandboxrelay.ResolveResponse.Effective): every exported field, which
// holds the pack's content, plus what Floor, AllowYolo, MaxResources,
// Explain and Digest answer from. "floor" uses openshell.admin's key names
// (floorJSON), so a reader that only needs F decodes that member as
// configuration.
type effectiveWire struct {
	V int `json:"v"`
	effectiveFields
	Floor            json.RawMessage `json:"floor"`
	RequiredPack     bool            `json:"required_pack"`
	HookSilenceAfter string          `json:"hook_silence_after,omitempty"`
	Settings         []Setting       `json:"settings,omitempty"`
	Digest           string          `json:"digest"`
}

// MarshalJSON writes the wire form (effectiveWire). It leaves out the
// host's facts the resolution used (its names, reserved ports, policy
// file paths), as Digest does.
func (e Effective) MarshalJSON() ([]byte, error) {
	floor, err := floorJSON(e.admin)
	if err != nil {
		return nil, err
	}
	w := effectiveWire{
		V: EffectiveWireVersion, effectiveFields: effectiveFields(e), Floor: floor,
		RequiredPack: e.requiredPack, Settings: e.Explain(), Digest: e.digest,
	}
	if e.HookSilenceAfter > 0 {
		w.HookSilenceAfter = e.HookSilenceAfter.String()
	}
	return json.Marshal(w)
}

// UnmarshalJSON reads the wire form into a policy view: its accessors,
// Explain and the exported posture answer as the resolved Effective did,
// and the content must reproduce the digest it carries. A view decides no
// runtime action (Allow, the egress decider): those need the host facts
// the wire form leaves out, so they fail closed and the caller resolves
// the run itself.
func (e *Effective) UnmarshalJSON(data []byte) error {
	var w effectiveWire
	if err := json.Unmarshal(data, &w); err != nil {
		return fmt.Errorf("sandbox policy: decode the policy: %w", err)
	}
	if w.V != EffectiveWireVersion {
		return fmt.Errorf("sandbox policy: policy wire version %d, want %d", w.V, EffectiveWireVersion)
	}
	floor, err := floorFromJSON(w.Floor)
	if err != nil {
		return err
	}
	out := Effective(w.effectiveFields)
	out.admin, out.requiredPack, out.digest, out.view = floor, w.RequiredPack, w.Digest, true
	if w.HookSilenceAfter != "" {
		if out.HookSilenceAfter, err = time.ParseDuration(w.HookSilenceAfter); err != nil {
			return fmt.Errorf("sandbox policy: hook_silence_after %q is not a duration", w.HookSilenceAfter)
		}
	}
	out.settings = make(map[string]Setting, len(w.Settings))
	for _, s := range w.Settings {
		out.settings[s.Key] = s
	}
	if out.AllowedHarnesses == nil {
		out.AllowedHarnesses = []string{}
	}
	digest, err := out.computeDigest()
	if err != nil {
		return err
	}
	if w.Digest == "" || digest != w.Digest {
		return errors.New("sandbox policy: the policy does not match its digest")
	}
	*e = out
	return nil
}

// floorJSON is a floor's wire form: a JSON object with openshell.admin's
// key names, in key order, unset keys left out. Digest covers this form,
// so a floor that round-trips through it keeps its digest.
func floorJSON(f config.OpenShellAdminConfig) (json.RawMessage, error) {
	doc, err := yaml.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("sandbox policy: encode the floor: %w", err)
	}
	keys := map[string]any{}
	if err := yaml.Unmarshal(doc, &keys); err != nil {
		return nil, fmt.Errorf("sandbox policy: encode the floor: %w", err)
	}
	data, err := json.Marshal(keys)
	if err != nil {
		return nil, fmt.Errorf("sandbox policy: encode the floor: %w", err)
	}
	return data, nil
}

// floorFromJSON decodes floorJSON's form. An unknown key fails: a floor
// this build cannot read in full is not applied.
func floorFromJSON(data json.RawMessage) (config.OpenShellAdminConfig, error) {
	var f config.OpenShellAdminConfig
	if len(bytes.TrimSpace(data)) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return f, errors.New("sandbox policy: the policy has no organization floor")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return config.OpenShellAdminConfig{}, fmt.Errorf("sandbox policy: decode the organization floor: %w", err)
	}
	return f, nil
}
