// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// The SubstrateInstall document ate-setup reads (Agent Substrate v1.0.0,
// cmd/ate-setup/internal/config/file.go).
const (
	InstallAPIVersion = "install.ate.dev/v1alpha1"
	InstallKind       = "SubstrateInstall"
	// installRecordKey is the metadata ate-setup writes into its install
	// records; it is not a setting and is carried through unchanged.
	installRecordKey = "cluster"
)

// The settings the overlay reads or writes. The ones marked with an upstream
// change exist only on a Substrate that has it; ate-setup rejects a setting
// it does not know, so they are written only when Capabilities lists them.
const (
	KeyDataplane      = "atenet.dataplane"
	KeyExtprocService = "atenet.egress.additionalExtprocService"
	KeyIngressClients = "ingressAllowedSPIFFEIDs"
	KeyActorJWTIssuer = "actorJWT.issuer"
	// KeyOpenAPPA deploys OpenAPPA into the additional callout slot (#3817).
	KeyOpenAPPA = "openappa.enabled"
	// KeyExtprocBodyOptIn lets the callout ask for bodies per request with a
	// mode_override (#3817, D9).
	KeyExtprocBodyOptIn = "atenet.egress.additionalExtprocAllowModeOverride"
	// KeyExtprocTimeout is Envoy's wait for each callout response (#3817).
	KeyExtprocTimeout = "atenet.egress.additionalExtprocTimeout"
	// KeyRouteTimeout is the router's route timeout for long streams (#2560, E21).
	KeyRouteTimeout = "atenet.router.routeTimeout"
)

// DataplaneEnvoy is the only dataplane with an additional callout.
const DataplaneEnvoy = "envoy"

// Capabilities are the settings the target Substrate's ate-setup knows
// beyond v1.0.0. The CLI fills it from the installed ate-setup; the zero
// value is stock v1.0.0.
type Capabilities struct {
	Settings map[string]bool
}

// Has reports whether the target knows setting key.
func (c Capabilities) Has(key string) bool { return c.Settings[key] }

// OverlayOptions say what DefenseClaw needs from Substrate.
type OverlayOptions struct {
	// Namespace is the DefenseClaw release namespace.
	Namespace string
	// CalloutPort is the callout Service port (chart callout.port).
	CalloutPort int
	// IngressClient is the SPIFFE ID the gateway presents to the router to
	// attach launchers to actors (IngressClientID).
	IngressClient string
	// Issuer, when set, becomes actorJWT.issuer: a unique issuer per cluster
	// (E13). Empty leaves the setting alone.
	Issuer string
	// BodyInspection asks for the body opt-in (D9) when the target has it.
	BodyInspection bool
	// CalloutTimeout and RouteTimeout are written when the target has the
	// settings (E21); empty means DefaultCalloutTimeout and DefaultRouteTimeout.
	CalloutTimeout string
	RouteTimeout   string
	Capabilities   Capabilities
}

// The timeouts the overlay asks for when the target supports them: the
// callout gets time for an MCP body check, and the router keeps interactive
// sessions and long model streams open past the hour (E21, J28).
const (
	DefaultCalloutTimeout = "5s"
	DefaultRouteTimeout   = "4h"
)

// CalloutService is the additionalExtprocService value for the DefenseClaw
// callout: NS/SVC:PORT.
func CalloutService(namespace string, port int) string {
	return fmt.Sprintf("%s/defenseclaw-callout:%d", namespace, port)
}

// IngressClientID is the SPIFFE ID of the DefenseClaw gateway pods (the
// podidentity signer issues spiffe://cluster.local/ns/<ns>/sa/<sa>).
func IngressClientID(namespace string) string {
	return "spiffe://cluster.local/ns/" + namespace + "/sa/defenseclaw-gateway"
}

// ErrCalloutTaken is the D10 refusal: Substrate already sends egress to
// another additional callout, and DefenseClaw never replaces one.
type ErrCalloutTaken struct {
	// Current is the callout already set (a service, or "OpenAPPA").
	Current string
}

func (e *ErrCalloutTaken) Error() string {
	return fmt.Sprintf("Substrate already sends egress to another callout (%s). "+
		"Agent Substrate runs one additional egress callout, and DefenseClaw does not replace another one. "+
		"Remove it from the SubstrateInstall document and run ate-setup first, "+
		"or keep it and set substrate.extproc.enabled: false (DefenseClaw then has no egress checks; "+
		"`defenseclaw substrate doctor` lists what that turns off)", e.Current)
}

// ErrDataplane is returned when the install uses a dataplane without the
// additional callout.
var ErrDataplane = errors.New("the DefenseClaw egress callout needs atenet.dataplane: envoy; " +
	"this install uses another dataplane, which has no additional ext_proc callout")

// Change is one setting the overlay set or removed.
type Change struct {
	Key string `json:"key"`
	Old string `json:"old,omitempty"`
	New string `json:"new,omitempty"`
}

// OverlayReport is what the overlay changed and what the admin should know.
type OverlayReport struct {
	Changes []Change `json:"changes"`
	Notes   []string `json:"notes"`
}

// installDoc is a parsed SubstrateInstall document: settings flattened to
// dotted keys with their text kept as written, as ate-setup does.
type installDoc struct {
	settings map[string]string
	record   *yaml.Node
}

func parseInstall(raw []byte) (*installDoc, error) {
	doc := &installDoc{settings: map[string]string{}}
	if len(bytes.TrimSpace(raw)) == 0 {
		return doc, nil
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("SubstrateInstall document: %w", err)
	}
	if len(root.Content) == 0 {
		return doc, nil
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, errors.New("SubstrateInstall document: must be a mapping")
	}
	var apiVersion, kind string
	for i := 0; i+1 < len(top.Content); i += 2 {
		name, value := top.Content[i].Value, top.Content[i+1]
		switch name {
		case "apiVersion":
			apiVersion = value.Value
		case "kind":
			kind = value.Value
		case installRecordKey:
			doc.record = value
		default:
			if err := flattenInto(name, value, doc.settings); err != nil {
				return nil, err
			}
		}
	}
	if apiVersion != InstallAPIVersion || kind != InstallKind {
		return nil, fmt.Errorf("SubstrateInstall document: want apiVersion %s and kind %s, got %q and %q",
			InstallAPIVersion, InstallKind, apiVersion, kind)
	}
	return doc, nil
}

func flattenInto(key string, node *yaml.Node, out map[string]string) error {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			if err := flattenInto(key+"."+node.Content[i].Value, node.Content[i+1], out); err != nil {
				return err
			}
		}
		return nil
	case yaml.ScalarNode:
		if _, dup := out[key]; dup {
			return fmt.Errorf("SubstrateInstall document: setting %q is set twice", key)
		}
		if node.Tag == "!!null" {
			out[key] = ""
		} else {
			out[key] = node.Value
		}
		return nil
	default:
		return fmt.Errorf("SubstrateInstall document: setting %q is not a scalar", key)
	}
}

// encode writes the document with its settings nested and sorted, so the
// same settings always give the same bytes.
func (d *installDoc) encode() ([]byte, error) {
	top := &yaml.Node{Kind: yaml.MappingNode}
	top.HeadComment = "Written by `defenseclaw substrate setup`; pass it to ate-setup with --config."
	addScalar(top, "apiVersion", InstallAPIVersion)
	addScalar(top, "kind", InstallKind)
	keys := make([]string, 0, len(d.settings))
	for k := range d.settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parent := top
		parts := strings.Split(k, ".")
		for _, part := range parts[:len(parts)-1] {
			parent = childMapping(parent, part)
		}
		addScalar(parent, parts[len(parts)-1], d.settings[k])
	}
	if d.record != nil {
		top.Content = append(top.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: installRecordKey}, d.record)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{top}}); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func addScalar(m *yaml.Node, key, value string) {
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
}

func childMapping(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key && m.Content[i+1].Kind == yaml.MappingNode {
			return m.Content[i+1]
		}
	}
	child := &yaml.Node{Kind: yaml.MappingNode}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, child)
	return child
}

func (d *installDoc) set(report *OverlayReport, key, value string) {
	old, had := d.settings[key]
	if had && old == value {
		return
	}
	d.settings[key] = value
	report.Changes = append(report.Changes, Change{Key: key, Old: old, New: value})
}

func (d *installDoc) unset(report *OverlayReport, key string) {
	old, had := d.settings[key]
	if !had {
		return
	}
	delete(d.settings, key)
	report.Changes = append(report.Changes, Change{Key: key, Old: old})
}

// isOurCallout reports whether service names the DefenseClaw callout of
// namespace, on any port.
func isOurCallout(service, namespace string) bool {
	return strings.HasPrefix(service, namespace+"/defenseclaw-callout:")
}

func splitList(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// RenderOverlay returns the SubstrateInstall document existing (empty for
// a new one) with DefenseClaw's settings added: the callout, the router
// client the launcher attaches through, and, when the target Substrate has
// them, the body opt-in and the long-stream timeouts. It refuses (D10) when
// another callout or OpenAPPA holds the callout slot.
func RenderOverlay(existing []byte, opts OverlayOptions) ([]byte, OverlayReport, error) {
	report := OverlayReport{Changes: []Change{}, Notes: []string{}}
	if opts.Namespace == "" || opts.CalloutPort < 1 || opts.CalloutPort > 65535 {
		return nil, report, errors.New("overlay: the DefenseClaw namespace and callout port are required")
	}
	doc, err := parseInstall(existing)
	if err != nil {
		return nil, report, err
	}
	if dp := doc.settings[KeyDataplane]; dp != "" && dp != DataplaneEnvoy {
		return nil, report, ErrDataplane
	}
	if v := strings.ToLower(doc.settings[KeyOpenAPPA]); v == "true" || v == "1" {
		return nil, report, &ErrCalloutTaken{Current: "OpenAPPA (openappa.enabled)"}
	}
	if current := doc.settings[KeyExtprocService]; current != "" && !isOurCallout(current, opts.Namespace) {
		return nil, report, &ErrCalloutTaken{Current: current}
	}
	doc.set(&report, KeyExtprocService, CalloutService(opts.Namespace, opts.CalloutPort))

	client := opts.IngressClient
	if client == "" {
		client = IngressClientID(opts.Namespace)
	}
	clients := splitList(doc.settings[KeyIngressClients])
	if !slices.Contains(clients, client) {
		clients = append(clients, client)
	}
	doc.set(&report, KeyIngressClients, strings.Join(clients, ","))
	if others := len(clients) - 1; others > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"%d other router client(s) stay listed in %s; any listed client reaches every actor, also in launcher atespaces. "+
				"Remove the ones you do not need.", others, KeyIngressClients))
	}

	if opts.Issuer != "" {
		doc.set(&report, KeyActorJWTIssuer, opts.Issuer)
	} else if doc.settings[KeyActorJWTIssuer] == "" {
		report.Notes = append(report.Notes, "actorJWT.issuer is the Substrate default; give each cluster its own issuer "+
			"(--issuer, and the same value in substrate.identity.issuer) before you add a second cluster.")
	}

	caps := opts.Capabilities
	if opts.BodyInspection && caps.Has(KeyExtprocBodyOptIn) {
		doc.set(&report, KeyExtprocBodyOptIn, "true")
	} else if opts.BodyInspection {
		report.Notes = append(report.Notes, "This Substrate has no callout body opt-in (agent-substrate#3817): "+
			"the callout checks request headers only, and MCP body checks run in the hooks.")
	}
	if caps.Has(KeyExtprocTimeout) {
		doc.set(&report, KeyExtprocTimeout, orDefault(opts.CalloutTimeout, DefaultCalloutTimeout))
	}
	if caps.Has(KeyRouteTimeout) {
		doc.set(&report, KeyRouteTimeout, orDefault(opts.RouteTimeout, DefaultRouteTimeout))
	} else {
		report.Notes = append(report.Notes, "This Substrate has no router route-timeout setting (agent-substrate#2560): "+
			"sessions and model streams use the router default.")
	}

	out, err := doc.encode()
	return out, report, err
}

// RemoveOverlay takes DefenseClaw's settings out of existing: the callout
// (only when it is DefenseClaw's), the body opt-in and callout timeout that
// need it, and the gateway's router client. Other settings stay.
func RemoveOverlay(existing []byte, opts OverlayOptions) ([]byte, OverlayReport, error) {
	report := OverlayReport{Changes: []Change{}, Notes: []string{}}
	if opts.Namespace == "" {
		return nil, report, errors.New("overlay: the DefenseClaw namespace is required")
	}
	doc, err := parseInstall(existing)
	if err != nil {
		return nil, report, err
	}
	switch current := doc.settings[KeyExtprocService]; {
	case current == "":
	case isOurCallout(current, opts.Namespace):
		doc.unset(&report, KeyExtprocService)
		doc.unset(&report, KeyExtprocBodyOptIn)
		doc.unset(&report, KeyExtprocTimeout)
	default:
		report.Notes = append(report.Notes, fmt.Sprintf("The callout %s is not DefenseClaw's; it stays.", current))
	}
	client := opts.IngressClient
	if client == "" {
		client = IngressClientID(opts.Namespace)
	}
	if clients := splitList(doc.settings[KeyIngressClients]); slices.Contains(clients, client) {
		clients = slices.DeleteFunc(clients, func(c string) bool { return c == client })
		if len(clients) == 0 {
			doc.unset(&report, KeyIngressClients)
		} else {
			doc.set(&report, KeyIngressClients, strings.Join(clients, ","))
		}
	}
	if _, ok := doc.settings[KeyRouteTimeout]; ok {
		report.Notes = append(report.Notes, KeyRouteTimeout+" stays; remove it too if nothing else needs long routes.")
	}
	out, err := doc.encode()
	return out, report, err
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
