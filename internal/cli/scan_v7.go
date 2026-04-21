// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

//go:embed embed/scan-result.json
var scanResultSchemaJSON []byte

// scanResultV7 is the wire shape for `defenseclaw scan code --json` (v7 contract).
type scanResultV7 struct {
	Scanner           string          `json:"scanner"`
	Target            string          `json:"target"`
	Timestamp         time.Time       `json:"timestamp"`
	Findings          []scanFindingV7 `json:"findings"`
	Duration          *string         `json:"duration"`
	ScanID            *string         `json:"scan_id"`
	SchemaVersion     *int            `json:"schema_version"`
	ContentHash       *string         `json:"content_hash"`
	Generation        *uint64         `json:"generation"`
	BinaryVersion     *string         `json:"binary_version"`
	AgentID           *string         `json:"agent_id"`
	AgentInstanceID   *string         `json:"agent_instance_id"`
	SidecarInstanceID *string         `json:"sidecar_instance_id"`
}

type scanFindingV7 struct {
	ID          string    `json:"id"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description *string   `json:"description"`
	Location    *string   `json:"location"`
	Remediation *string   `json:"remediation"`
	Scanner     string    `json:"scanner"`
	Tags        *[]string `json:"tags"`
	RuleID      *string   `json:"rule_id"`
	LineNumber  *int      `json:"line_number"`
	Category    *string   `json:"category"`
	Confidence  *float64  `json:"confidence"`
}

func marshalScanResultV7(r *scanner.ScanResult, binaryVer string) ([]byte, error) {
	prov := version.Current()
	sv := version.SchemaVersion
	gen := prov.Generation
	ch := prov.ContentHash
	bv := prov.BinaryVersion
	if binaryVer != "" {
		bv = binaryVer
	}

	sid := uuid.New().String()
	dur := r.Duration.String()
	agentID := getenvOrNil("DEFENSECLAW_AGENT_ID")
	agentInst := getenvOrNil("DEFENSECLAW_AGENT_INSTANCE_ID")
	sidecarInst := getenvOrNil("DEFENSECLAW_SIDECAR_INSTANCE_ID")

	out := scanResultV7{
		Scanner:           r.Scanner,
		Target:            r.Target,
		Timestamp:         r.Timestamp.UTC(),
		Duration:          &dur,
		ScanID:            &sid,
		SchemaVersion:     &sv,
		ContentHash:       nilIfEmpty(ch),
		Generation:        &gen,
		BinaryVersion:     nilIfEmpty(bv),
		AgentID:           agentID,
		AgentInstanceID:   agentInst,
		SidecarInstanceID: sidecarInst,
		Findings:          make([]scanFindingV7, 0, len(r.Findings)),
	}
	for i := range r.Findings {
		out.Findings = append(out.Findings, findingToV7(&r.Findings[i], r.Scanner))
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("cli: marshal scan v7: %w", err)
	}
	return b, nil
}

func findingToV7(f *scanner.Finding, scannerName string) scanFindingV7 {
	rid := scanner.EnsureRuleID(f, scannerName)
	ln := lineNumberFromLocation(f.Location)
	var tags *[]string
	if len(f.Tags) > 0 {
		t := append([]string(nil), f.Tags...)
		tags = &t
	}
	return scanFindingV7{
		ID:          f.ID,
		Severity:    string(f.Severity),
		Title:       f.Title,
		Description: strPtrOrNil(f.Description),
		Location:    strPtrOrNil(f.Location),
		Remediation: strPtrOrNil(f.Remediation),
		Scanner:     scannerName,
		Tags:        tags,
		RuleID:      &rid,
		LineNumber:  ln,
		Category:    nil,
		Confidence:  nil,
	}
}

func lineNumberFromLocation(loc string) *int {
	if loc == "" {
		z := 0
		return &z
	}
	idx := strings.LastIndex(loc, ":")
	if idx < 0 || idx >= len(loc)-1 {
		z := 0
		return &z
	}
	n, err := strconv.Atoi(loc[idx+1:])
	if err != nil || n < 0 {
		z := 0
		return &z
	}
	return &n
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nilIfEmpty(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

func getenvOrNil(k string) *string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return nil
	}
	return &v
}
