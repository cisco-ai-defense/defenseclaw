// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Discovery signals for Agent Substrate. They have the fields of an
// inventory ai_signals row (internal/inventory.AISignal: fingerprint,
// signal_id, signature_id, name, vendor, product, category, detector, state,
// confidence, source, first_seen, last_seen), so the controller's inventory
// events and the gateway's ai_discovery export can carry them unchanged;
// what is specific to Substrate is in Attributes.

// Signal sources, detectors and categories.
const (
	SignalSource           = "substrate"
	DetectorTemplate       = "substrate_template"
	DetectorActor          = "substrate_actor"
	CategoryConnector      = "supported_connector"
	CategoryUnknownAgent   = "ai_cli"
	StateNew               = "new"
	StateSeen              = "seen"
	StateChanged           = "changed"
	StateGone              = "gone"
	ShadowUnattested       = "unattested_template"
	ShadowForeignActor     = "foreign_actor"
	ShadowUnmanagedAtespac = "unmanaged_atespace"
)

// Signal is one discovery event.
type Signal struct {
	Fingerprint string  `json:"fingerprint"`
	SignalID    string  `json:"signal_id"`
	SignatureID string  `json:"signature_id"`
	Name        string  `json:"name"`
	Vendor      string  `json:"vendor"`
	Product     string  `json:"product"`
	Category    string  `json:"category"`
	Connector   string  `json:"supported_connector,omitempty"`
	Confidence  float64 `json:"confidence"`
	State       string  `json:"state"`
	Detector    string  `json:"detector"`
	Source      string  `json:"source"`
	Version     string  `json:"version,omitempty"`
	// SandboxID and SandboxName carry the actor's UID and atespace/name, the
	// fields the inventory uses for OpenShell sandboxes.
	SandboxID   string            `json:"sandbox_id,omitempty"`
	SandboxName string            `json:"sandbox_name,omitempty"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	Attributes  map[string]string `json:"attributes"`
}

// TemplateObservation is a template the controller listed.
type TemplateObservation struct {
	Atespace string
	Name     string
	// Image is the template's image reference as Substrate holds it.
	Image string
	// FirstSeen is when the controller first listed it (zero: now).
	FirstSeen time.Time
}

// TemplateSignal describes a template. v is the verification result and rej
// the reason it was not admitted; exactly one is set.
func TemplateSignal(t TemplateObservation, v *Verified, rej *Rejection, now time.Time) Signal {
	s := Signal{
		Fingerprint: fp("template", t.Atespace, t.Name, t.Image),
		Category:    CategoryUnknownAgent, Confidence: 0.9, State: StateSeen,
		Detector: DetectorTemplate, Source: SignalSource, LastSeen: now.UTC(), FirstSeen: t.FirstSeen.UTC(),
		SandboxName: t.Atespace + "/" + t.Name,
		Name:        "Agent Substrate template " + t.Name, Vendor: "unknown", Product: t.Name,
		Attributes: map[string]string{"atespace": t.Atespace, "template": t.Name, "image": t.Image},
	}
	if s.FirstSeen.IsZero() {
		s.FirstSeen, s.State = now.UTC(), StateNew
	}
	s.SignalID = "substrate-template-" + s.Fingerprint[:12]
	s.SignatureID = "substrate-template"
	if v != nil {
		p := v.Statement.Predicate
		s.Category, s.Connector, s.Confidence = CategoryConnector, p.Template.Connector, 0.98
		s.SignatureID, s.Version = p.Template.Connector, p.Template.AgentVersion
		s.Product, s.Vendor = p.Template.Connector, "DefenseClaw"
		s.Name = "Agent Substrate template " + t.Name + " (" + p.Template.Connector + ")"
		a := s.Attributes
		a["attested"], a["shadow"] = "true", "false"
		a["digest"], a["key_id"] = v.Digest, v.KeyID
		a["kit_version"], a["hook_contract"] = p.Kit.Version, p.Kit.HookContract
		a["scan_verdict"] = p.Scan.Verdict
		a["scan_skills"], a["scan_mcp_servers"] = strconv.Itoa(p.Scan.Skills), strconv.Itoa(p.Scan.MCPServers)
		a["scan_findings_high"] = strconv.Itoa(p.Scan.Findings["high"] + p.Scan.Findings["critical"])
		a["policy_generation"] = strconv.Itoa(int(p.Policy.Generation))
		a["base_trust"] = p.Base.Trust
		a["providers"] = strings.Join(p.Template.Providers, ",")
		return s
	}
	a := s.Attributes
	a["attested"], a["shadow"] = "false", "true"
	a["shadow_reason"] = ShadowUnattested
	if rej != nil {
		a["reject_code"], a["reject_detail"] = rej.Code, rej.Detail
	}
	return s
}

// ActorObservation is an actor the controller listed.
type ActorObservation struct {
	Atespace string
	Name     string
	UID      string
	State    string
	// Owner is the person DefenseClaw registered for the actor; empty when
	// DefenseClaw has no registration for it.
	Owner string
	// Template is "<atespace>/<name>" of its ActorTemplate.
	Template string
	// Managed is true when the actor was created through the launcher in a
	// DefenseClaw atespace (it has a registration).
	Managed bool
	// TemplateAttested is the controller's admission result for its template.
	TemplateAttested bool
	// ForkedBy names who forked it ("unknown" outside launcher atespaces).
	ForkedBy  string
	FirstSeen time.Time
}

// ActorSignal describes an actor. A foreign actor is one DefenseClaw did not
// create or register; an actor of an unattested template is shadow AI too.
func ActorSignal(a ActorObservation, now time.Time) Signal {
	s := Signal{
		Fingerprint: fp("actor", a.Atespace, a.Name, a.UID),
		SignalID:    "substrate-actor-" + a.UID, SignatureID: "substrate-actor",
		Name: "Agent Substrate actor " + a.Name, Vendor: "unknown", Product: a.Name,
		Category: CategoryUnknownAgent, Confidence: 0.95, State: StateSeen, Detector: DetectorActor, Source: SignalSource,
		SandboxID: a.UID, SandboxName: a.Atespace + "/" + a.Name,
		FirstSeen: a.FirstSeen.UTC(), LastSeen: now.UTC(),
		Attributes: map[string]string{"atespace": a.Atespace, "actor": a.Name, "actor_state": a.State, "template": a.Template},
	}
	if a.FirstSeen.IsZero() {
		s.FirstSeen, s.State = now.UTC(), StateNew
	}
	if a.State == "DELETED" || a.State == "GONE" {
		s.State = StateGone
	}
	at := s.Attributes
	if a.Owner != "" {
		at["owner"] = a.Owner
	}
	if a.ForkedBy != "" {
		at["forked_by"] = a.ForkedBy
	}
	at["managed"] = boolStr(a.Managed)
	at["template_attested"] = boolStr(a.TemplateAttested)
	switch {
	case !a.Managed:
		at["shadow"], at["shadow_reason"] = "true", ShadowForeignActor
	case !a.TemplateAttested:
		at["shadow"], at["shadow_reason"] = "true", ShadowUnattested
	default:
		at["shadow"] = "false"
	}
	return s
}

func fp(parts ...string) string {
	h := sha256.Sum256([]byte("substrate|" + strings.Join(parts, "|")))
	return hex.EncodeToString(h[:16])
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TemplateUnverifiedEvent is the event the controller emits when it does not
// admit a template (and so writes no EgressPolicy).
type TemplateUnverifiedEvent struct {
	Type      string    `json:"type"` // template_unverified
	Atespace  string    `json:"atespace"`
	Template  string    `json:"template"`
	Image     string    `json:"image"`
	Code      string    `json:"code"`
	Reason    string    `json:"reason"`
	Retryable bool      `json:"retryable"`
	Network   string    `json:"network"` // denied
	At        time.Time `json:"at"`
}

// NewTemplateUnverified builds the event for a rejection.
func NewTemplateUnverified(t TemplateObservation, rej *Rejection, now time.Time) TemplateUnverifiedEvent {
	return TemplateUnverifiedEvent{Type: "template_unverified", Atespace: t.Atespace, Template: t.Name, Image: t.Image,
		Code: rej.Code, Reason: rej.Detail, Retryable: rej.Retryable, Network: "denied", At: now.UTC()}
}
