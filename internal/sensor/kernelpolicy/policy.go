// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// The typed TracingPolicy below is the subset of Tetragon's
// cilium.io/v1alpha1 schema (lowest supported release, 1.7.0) that
// DefenseClaw ever renders. Rendering through types, and reading rendered
// text back through the same types with unknown fields refused, is the
// round trip of lint rule 8: a field the controls do not use cannot appear.

type tracingPolicy struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   tpMeta `yaml:"metadata"`
	Spec       tpSpec `yaml:"spec"`
}

type tpMeta struct {
	Name string `yaml:"name"`
}

type tpSpec struct {
	Options  []tpOption `yaml:"options,omitempty"`
	Kprobes  []tpKprobe `yaml:"kprobes,omitempty"`
	LsmHooks []tpLsm    `yaml:"lsmhooks,omitempty"`
}

type tpOption struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type tpKprobe struct {
	Call      string       `yaml:"call"`
	Syscall   bool         `yaml:"syscall"`
	Args      []tpArg      `yaml:"args"`
	Selectors []tpSelector `yaml:"selectors"`
}

type tpLsm struct {
	Hook      string       `yaml:"hook"`
	Args      []tpArg      `yaml:"args"`
	Selectors []tpSelector `yaml:"selectors"`
}

type tpArg struct {
	Index   int    `yaml:"index"`
	Type    string `yaml:"type"`
	Resolve string `yaml:"resolve,omitempty"`
	Label   string `yaml:"label,omitempty"`
}

type tpSelector struct {
	MatchBinaries   []tpBinaries  `yaml:"matchBinaries,omitempty"`
	MatchPIDs       []tpPIDs      `yaml:"matchPIDs,omitempty"`
	MatchNamespaces []tpNamespace `yaml:"matchNamespaces,omitempty"`
	MatchArgs       []tpMatchArg  `yaml:"matchArgs,omitempty"`
	MatchActions    []tpAction    `yaml:"matchActions,omitempty"`
}

type tpBinaries struct {
	Operator       string   `yaml:"operator"`
	Values         []string `yaml:"values"`
	FollowChildren bool     `yaml:"followChildren,omitempty"`
}

type tpPIDs struct {
	Operator       string `yaml:"operator"`
	FollowForks    bool   `yaml:"followForks"`
	IsNamespacePID bool   `yaml:"isNamespacePID"`
	Values         []int  `yaml:"values"`
}

type tpNamespace struct {
	Namespace string   `yaml:"namespace"`
	Operator  string   `yaml:"operator"`
	Values    []string `yaml:"values"`
}

type tpMatchArg struct {
	Index    int      `yaml:"index"`
	Operator string   `yaml:"operator"`
	Values   []string `yaml:"values"`
}

type tpAction struct {
	Action         string `yaml:"action"`
	ArgError       *int   `yaml:"argError,omitempty"`
	RateLimit      string `yaml:"rateLimit,omitempty"`
	RateLimitScope string `yaml:"rateLimitScope,omitempty"`
}

const (
	apiVersion = "cilium.io/v1alpha1"
	kindPolicy = "TracingPolicy"
	modeOption = "policy-mode"
)

// marshalPolicy renders tp deterministically.
func marshalPolicy(tp tracingPolicy) ([]byte, error) {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(tp); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodePolicy reads rendered text back, refusing unknown fields and extra
// documents.
func decodePolicy(data []byte) (tracingPolicy, error) {
	var tp tracingPolicy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&tp); err != nil {
		return tracingPolicy{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return tracingPolicy{}, fmt.Errorf("more than one YAML document")
	}
	return tp, nil
}

// stripComments removes the leading comment header lines of a rendered
// policy, leaving exactly what marshalPolicy produced.
func stripComments(data []byte) []byte {
	for len(data) > 0 && data[0] == '#' {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return nil
		}
		data = data[i+1:]
	}
	return data
}

// bodyHash is the first 8 hex of the sha256 of the policy with its name and
// its mode option left out. Two renders that differ only in the mode (which
// Tetragon changes in place) keep one name; any change to scope, anchors or
// paths is a new name, added before the old one is deleted.
func bodyHash(tp tracingPolicy) (string, []byte, error) {
	tp.Metadata.Name = ""
	tp.Spec.Options = nil
	body, err := marshalPolicy(tp)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])[:8], body, nil
}

func policyName(family Family, hash string) string {
	return "defenseclaw-" + string(family) + "-" + hash
}

// Policy is one rendered policy, ready to load.
type Policy struct {
	Family Family
	Name   string
	// Mode is the mode the policy is loaded in (controls families); the
	// other families carry no Override and are reported as monitor.
	Mode PolicyMode
	// YAML is the text given to Tetragon: header, options and body.
	YAML []byte
	UIDs []int
	PIDs []int
	// BinaryUID is the sole uid covered by the binaries anchor. Zero means
	// that no native binary was selected.
	BinaryUID int
	// Binaries are the binaries-anchor values of the controls families.
	Binaries []string
	// Paths maps a matched path back to the control it belongs to.
	Paths PathIndex

	tp tracingPolicy
}

// withMode returns p rendered in mode. The name is unchanged: the mode is
// not part of the name, so Tetragon flips it in place.
func (p Policy) withMode(mode PolicyMode) (Policy, error) {
	data, err := render(p.Family, p.tp, mode)
	if err != nil {
		return p, err
	}
	p.YAML, p.Mode = data, mode
	return p, nil
}

// PathIndex maps opened paths to control ids, for attributing hits.
type PathIndex struct {
	Exact    map[string]string
	Prefixes map[string]string
}

// ControlOf returns the control id a path belongs to, or "".
func (p PathIndex) ControlOf(path string) string {
	if id, ok := p.Exact[path]; ok {
		return id
	}
	for prefix, id := range p.Prefixes {
		if strings.HasPrefix(path, prefix) {
			return id
		}
	}
	return ""
}

func header(family Family) []byte {
	return []byte(fmt.Sprintf("# defenseclaw-derived: tetragon-policy family=%s kernel_policy=%s\n"+
		"# Written by defenseclaw-sensor-helper. Do not edit: the helper reconciles this policy.\n",
		family, Digest()))
}

// render returns the text for tp in mode: the header, the mode option (the
// Post-only families carry none) and the body.
func render(family Family, tp tracingPolicy, mode PolicyMode) ([]byte, error) {
	if mode != "" {
		tp.Spec.Options = []tpOption{{Name: modeOption, Value: string(mode)}}
	}
	body, err := marshalPolicy(tp)
	if err != nil {
		return nil, err
	}
	return append(header(family), body...), nil
}
