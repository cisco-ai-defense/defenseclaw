// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package attest builds, scans, signs and verifies Agent Substrate actor
// templates (PLAN 6.6).
//
// A template is a container image: a base image (the OpenShell harness image
// of a connector, or any image the admin trusts) plus the DefenseClaw actor
// kit layer. "template build" adds the kit, scans every skill, plugin and MCP
// server definition in the image, checks that the hook files are root-owned
// and the phone-home switches are set, and signs an in-toto statement about
// the result. The statement is a DSSE envelope signed with the cluster
// attestation key (ECDSA P-256), stored next to the image in its registry the
// way cosign stores attestations, so cosign verify-attestation reads it with
// the public key. The controller admits a template only when Verifier
// accepts the statement against the trust anchors.
//
// Nothing here trusts a tag: an image is resolved to its digest first, and
// the statement's subject must be that digest.
package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	// StatementType is the in-toto statement layer this package emits.
	StatementType = "https://in-toto.io/Statement/v1"
	// PredicateType names the template predicate (Predicate).
	PredicateType = "https://github.com/cisco-ai-defense/defenseclaw/substrate/template/v1"
	// PayloadType is the DSSE payload type of an in-toto statement.
	PayloadType = "application/vnd.in-toto+json"

	// Trust levels of a template's base image.
	BaseTrustAttested    = "attested"    // the base carries an attestation that verified
	BaseTrustAllowlisted = "allowlisted" // the base digest is on the admin's trusted list
	BaseTrustUnverified  = "unverified"  // neither; admitted only when a profile allows it

	// Scan verdicts (the scanner package's vocabulary).
	VerdictClean = "clean"
	VerdictWarn  = "warn"
	VerdictBlock = "block"
)

// Subject is one attested artifact.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is an in-toto v1 statement about a template image.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Predicate is what DefenseClaw states about the image.
type Predicate struct {
	Template TemplateInfo `json:"template"`
	Base     BaseInfo     `json:"base"`
	Kit      KitInfo      `json:"kit"`
	Hooks    HookChecks   `json:"hooks"`
	Scan     ScanSummary  `json:"scan"`
	Policy   PolicyInfo   `json:"policy"`
	Builder  BuilderInfo  `json:"builder"`
}

// TemplateInfo says what the template is for.
type TemplateInfo struct {
	// Connector is the DefenseClaw connector name (claudecode, codex, ...).
	Connector string `json:"connector"`
	// AgentVersion is the pinned agent version, when the build knew it.
	AgentVersion string `json:"agentVersion,omitempty"`
	// Name is the template's logical name.
	Name string `json:"name,omitempty"`
	// Providers are the model providers the settings layer routes to.
	Providers []string `json:"providers,omitempty"`
}

// BaseInfo records the image the kit layer sits on.
type BaseInfo struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
	// Trust is one of the BaseTrust* values.
	Trust string `json:"trust"`
	// AttestedBy is the key id that signed the base's own attestation.
	AttestedBy string `json:"attestedBy,omitempty"`
}

// KitInfo identifies the actor kit in the image.
type KitInfo struct {
	Version      string `json:"version"`
	HookContract string `json:"hookContract"`
	// LayerDigest is the compressed digest of the kit layer; LayerDiffID the
	// uncompressed one. The verifier checks both against the image.
	LayerDigest string `json:"layerDigest"`
	LayerDiffID string `json:"layerDiffID"`
	// LayerIndex is the layer's position in the image manifest.
	LayerIndex int `json:"layerIndex"`
}

// HookChecks is the result of the file and switch checks of the build.
type HookChecks struct {
	// RootOwned is true when every hook and settings file is owned by root
	// and writable by root only.
	RootOwned bool       `json:"rootOwned"`
	Files     []HookFile `json:"files,omitempty"`
	// PhoneHomeOff is true when every per-connector phone-home and
	// auto-update switch is set in the image environment.
	PhoneHomeOff bool `json:"phoneHomeOff"`
	// EnvClean is true when the image environment sets none of the variables
	// that load code into every process (LD_PRELOAD, NODE_OPTIONS, BASH_ENV ...).
	EnvClean  bool          `json:"envClean"`
	UnsafeEnv []string      `json:"unsafeEnv,omitempty"`
	Switches  []SwitchCheck `json:"switches,omitempty"`
}

// HookFile is one checked hook or settings file.
type HookFile struct {
	Path string `json:"path"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	Mode string `json:"mode"`
	OK   bool   `json:"ok"`
	Note string `json:"note,omitempty"`
}

// SwitchCheck is one phone-home switch.
type SwitchCheck struct {
	Name string `json:"name"`
	Want string `json:"want"`
	Got  string `json:"got,omitempty"`
	OK   bool   `json:"ok"`
}

// ScanSummary is the outcome of the build-time scans.
type ScanSummary struct {
	Scanners   []ScannerInfo  `json:"scanners"`
	Skills     int            `json:"skills"`
	MCPServers int            `json:"mcpServers"`
	Plugins    int            `json:"plugins"`
	Findings   map[string]int `json:"findings"`
	// Verdict is the worst admission verdict over all items: clean, warn or
	// block. A block never gets an attestation from the build.
	Verdict string     `json:"verdict"`
	Items   []ScanItem `json:"items,omitempty"`
	// Accepted are the admin's audited acceptances of findings that the
	// build floor would have blocked (template build --accept-finding).
	Accepted []AcceptedFinding `json:"acceptedFindings,omitempty"`
	// ScannedAt is the build's clock.
	ScannedAt time.Time `json:"scannedAt"`
}

// ScannerInfo names a scanner that ran.
type ScannerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// ScanItem is one scanned skill, plugin or MCP server.
type ScanItem struct {
	// Kind is skill, mcp or plugin.
	Kind string `json:"kind"`
	Name string `json:"name"`
	// Path is the item's path in the image.
	Path        string `json:"path"`
	Scanner     string `json:"scanner"`
	Verdict     string `json:"verdict"`
	MaxSeverity string `json:"maxSeverity,omitempty"`
	Findings    int    `json:"findings"`
	Reason      string `json:"reason,omitempty"`
	// Accepted are rule ids whose findings were accepted for this item:
	// without them the build floor blocked it.
	Accepted []string `json:"accepted,omitempty"`
	// Digest is the content digest of an admitted skill folder as the actor
	// kit attaches it (SkillFolderDigest); the gateway trusts a folder with
	// this digest without scanning it again (GAP-0164). Empty when the folder
	// cannot be matched (too many files, entries the scan could not read).
	Digest string `json:"digest,omitempty"`
}

// AcceptedFinding is an admin's audited acceptance of one finding rule at
// the template build floor (a known false positive). It lifts only the
// build floor; host admission rules (block lists, rejected verdicts) still
// block, and the run-time scan is unchanged. The HIGH floor stays the
// default.
type AcceptedFinding struct {
	RuleID string    `json:"ruleId"`
	Reason string    `json:"reason"`
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at"`
	// Items are the scanned items (kind:path) whose block it lifted.
	Items []string `json:"items"`
}

// PolicyInfo says which admission policy the scan used.
type PolicyInfo struct {
	// Generation is the policy generation of the build host's config; the
	// verifier can demand a minimum, so tightening policy forces a rescan.
	Generation int64 `json:"generation"`
}

// BuilderInfo says who and when.
type BuilderInfo struct {
	ID      string    `json:"id,omitempty"`
	BuiltAt time.Time `json:"builtAt"`
}

// NewStatement returns a statement for one image digest ("sha256:...").
func NewStatement(name, digest string, p Predicate) (*Statement, error) {
	hexDigest, err := sha256Hex(digest)
	if err != nil {
		return nil, err
	}
	return &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: name, Digest: map[string]string{"sha256": hexDigest}}},
		PredicateType: PredicateType,
		Predicate:     p,
	}, nil
}

// SubjectDigest returns the statement's one subject digest as "sha256:...".
func (s *Statement) SubjectDigest() (string, error) {
	if len(s.Subject) != 1 {
		return "", fmt.Errorf("statement has %d subjects, want 1", len(s.Subject))
	}
	h, ok := s.Subject[0].Digest["sha256"]
	if !ok || len(s.Subject[0].Digest) != 1 {
		return "", errors.New("statement subject needs exactly a sha256 digest")
	}
	if _, err := hex.DecodeString(h); err != nil || len(h) != sha256.Size*2 {
		return "", errors.New("statement subject digest is not a sha256")
	}
	return "sha256:" + h, nil
}

// Marshal encodes the statement as the DSSE payload.
func (s *Statement) Marshal() ([]byte, error) {
	canon := *s
	canon.Predicate.Scan.Findings = normalizeFindings(canon.Predicate.Scan.Findings)
	return json.Marshal(&canon)
}

// ParseStatement decodes a DSSE payload. Unknown fields are refused, so a
// statement is never read more loosely than it was written.
func ParseStatement(data []byte) (*Statement, error) {
	var s Statement
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("statement: %w", err)
	}
	if dec.More() {
		return nil, errors.New("statement: trailing data")
	}
	if s.Type != StatementType {
		return nil, fmt.Errorf("statement: type %q, want %q", s.Type, StatementType)
	}
	return &s, nil
}

func normalizeFindings(m map[string]int) map[string]int {
	out := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}
	return out
}

// SortedKeys is a helper for stable output of the findings map.
func SortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sha256Hex validates "sha256:<64 hex>" and returns the hex part.
func sha256Hex(digest string) (string, error) {
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexPart) != sha256.Size*2 {
		return "", fmt.Errorf("digest %q is not sha256:<64 hex>", digest)
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return "", fmt.Errorf("digest %q is not sha256:<64 hex>", digest)
	}
	return hexPart, nil
}

// DigestOf returns "sha256:<hex>" of data.
func DigestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
