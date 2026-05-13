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

// Package runtimecatalog provides resource metadata lookup for runtime AI-agent
// actions. It borrows the AIMS metadata-catalog pattern but keeps DefenseClaw's
// default behavior non-enforcing: callers can enrich audit evidence and Galileo
// Agent Control context without changing the local allow/block decision.
package runtimecatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ErrNotFound is returned when the catalog has no matching resource entry.
var ErrNotFound = errors.New("runtime catalog: resource not found")

// Entry is the authoritative metadata record for one runtime resource.
type Entry struct {
	ResourceID        string            `json:"resource_id" yaml:"resource_id"`
	ResourceType      string            `json:"resource_type,omitempty" yaml:"resource_type,omitempty"`
	ResourcePath      string            `json:"resource_path,omitempty" yaml:"resource_path,omitempty"`
	Owner             string            `json:"owner,omitempty" yaml:"owner,omitempty"`
	SensitivityDomain string            `json:"sensitivity_domain,omitempty" yaml:"sensitivity_domain,omitempty"`
	PIIFields         []string          `json:"pii_fields,omitempty" yaml:"pii_fields,omitempty"`
	AllowedAgents     []string          `json:"allowed_agents,omitempty" yaml:"allowed_agents,omitempty"`
	AllowedScopes     []string          `json:"allowed_scopes,omitempty" yaml:"allowed_scopes,omitempty"`
	RequiresApproval  bool              `json:"requires_approval,omitempty" yaml:"requires_approval,omitempty"`
	Tags              map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// Normalize fills derived identifiers and trims whitespace.
func (e Entry) Normalize() Entry {
	e.ResourceID = strings.TrimSpace(e.ResourceID)
	e.ResourceType = strings.TrimSpace(e.ResourceType)
	e.ResourcePath = strings.TrimSpace(e.ResourcePath)
	if e.ResourceID == "" && e.ResourceType != "" && e.ResourcePath != "" {
		e.ResourceID = e.ResourceType + ":" + e.ResourcePath
	}
	if e.ResourceID != "" && (e.ResourceType == "" || e.ResourcePath == "") {
		if typ, path, ok := SplitResourceID(e.ResourceID); ok {
			if e.ResourceType == "" {
				e.ResourceType = typ
			}
			if e.ResourcePath == "" {
				e.ResourcePath = path
			}
		}
	}
	e.Owner = strings.TrimSpace(e.Owner)
	e.SensitivityDomain = strings.TrimSpace(e.SensitivityDomain)
	e.PIIFields = trimStrings(e.PIIFields)
	e.AllowedAgents = trimStrings(e.AllowedAgents)
	e.AllowedScopes = trimStrings(e.AllowedScopes)
	return e
}

// Catalog is implemented by static and HTTP-backed catalog clients.
type Catalog interface {
	Lookup(ctx context.Context, resourceType, resourcePath string) (*Entry, error)
}

// StaticCatalog is an in-memory catalog loaded from JSON or tests.
type StaticCatalog struct {
	entries map[string]Entry
}

// NewStaticCatalog creates a static catalog from the supplied entries.
func NewStaticCatalog(entries []Entry) *StaticCatalog {
	m := make(map[string]Entry, len(entries))
	for _, raw := range entries {
		e := raw.Normalize()
		if e.ResourceID == "" {
			continue
		}
		m[strings.ToLower(e.ResourceID)] = e
	}
	return &StaticCatalog{entries: m}
}

// Lookup returns an exact entry first, then the longest prefix match.
func (s *StaticCatalog) Lookup(_ context.Context, resourceType, resourcePath string) (*Entry, error) {
	if s == nil {
		return nil, ErrNotFound
	}
	key := strings.ToLower(strings.TrimSpace(resourceType) + ":" + strings.TrimSpace(resourcePath))
	if key == ":" {
		return nil, ErrNotFound
	}
	if e, ok := s.entries[key]; ok {
		cp := e
		return &cp, nil
	}
	bestKey := ""
	var best Entry
	for k, e := range s.entries {
		if strings.HasPrefix(key, k) && len(k) > len(bestKey) {
			bestKey = k
			best = e
		}
	}
	if bestKey == "" {
		return nil, ErrNotFound
	}
	cp := best
	return &cp, nil
}

// LoadStaticCatalogFile reads JSON catalog entries from path. Supported shapes:
//   - [ { ...Entry... } ]
//   - { "resources": [ { ...Entry... } ] }
//   - { "entries": [ { ...Entry... } ] }
func LoadStaticCatalogFile(path string) (*StaticCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadStaticCatalog(data)
}

// LoadStaticCatalog parses a static JSON catalog.
func LoadStaticCatalog(data []byte) (*StaticCatalog, error) {
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err == nil {
		return NewStaticCatalog(entries), nil
	}
	var wrapped struct {
		Resources []Entry `json:"resources"`
		Entries   []Entry `json:"entries"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return nil, err
	}
	entries = wrapped.Resources
	if len(entries) == 0 {
		entries = wrapped.Entries
	}
	return NewStaticCatalog(entries), nil
}

// HTTPClient performs catalog lookups against a remote metadata catalog.
type HTTPClient struct {
	baseURL string
	client  *http.Client
}

// NewHTTPClient creates an HTTP catalog with a conservative timeout.
func NewHTTPClient(baseURL string) *HTTPClient {
	return &HTTPClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: 500 * time.Millisecond},
	}
}

// Lookup calls GET /metadata_catalog?resource_type=...&resource_path=...
func (c *HTTPClient) Lookup(ctx context.Context, resourceType, resourcePath string) (*Entry, error) {
	if c == nil || c.baseURL == "" {
		return nil, ErrNotFound
	}
	q := url.Values{}
	q.Set("resource_type", resourceType)
	q.Set("resource_path", resourcePath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/metadata_catalog?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("runtime catalog: http %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	entry = entry.Normalize()
	if entry.ResourceID == "" {
		entry.ResourceType = resourceType
		entry.ResourcePath = resourcePath
		entry.ResourceID = resourceType + ":" + resourcePath
	}
	return &entry, nil
}

// ResourceRef is the resource inferred from a tool invocation.
type ResourceRef struct {
	Type string `json:"type"`
	Path string `json:"path"`
	ID   string `json:"id"`
}

// SplitResourceID splits type:path resource identifiers.
func SplitResourceID(resourceID string) (string, string, bool) {
	parts := strings.SplitN(strings.TrimSpace(resourceID), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// InferResource derives a catalog lookup key from common tool arguments.
func InferResource(tool string, input any) ResourceRef {
	m := normalizeMap(input)
	if rid := firstMapString(m, "resource_id", "resourceId", "resource"); rid != "" {
		if typ, path, ok := SplitResourceID(rid); ok {
			return ResourceRef{Type: typ, Path: path, ID: typ + ":" + path}
		}
	}
	if typ := firstMapString(m, "resource_type", "resourceType", "type"); typ != "" {
		if path := firstMapString(m, "resource_path", "resourcePath", "path", "name", "id"); path != "" {
			return ref(typ, path)
		}
	}
	if table := firstMapString(m, "table", "collection", "index"); table != "" {
		return ref("database", table)
	}
	if query := firstMapString(m, "query", "sql"); query != "" {
		if table := tableFromSQL(query); table != "" {
			return ref("database", table)
		}
		return ref("database", "query")
	}
	if bucket := firstMapString(m, "bucket"); bucket != "" {
		key := firstMapString(m, "key", "object", "path")
		return ref("s3", "/"+strings.Trim(bucket+"/"+strings.TrimLeft(key, "/"), "/"))
	}
	if rawURL := firstMapString(m, "url", "endpoint", "href"); rawURL != "" {
		if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
			return ref("api", u.Path)
		}
		return ref("api", rawURL)
	}
	if path := firstMapString(m, "path", "file", "filename"); path != "" {
		return ref("file", filepath.Clean(path))
	}
	lt := strings.ToLower(strings.TrimSpace(tool))
	switch {
	case strings.Contains(lt, "sql"), strings.Contains(lt, "query"), strings.Contains(lt, "database"):
		return ref("database", "query")
	case strings.Contains(lt, "http"), strings.Contains(lt, "api"), strings.Contains(lt, "fetch"):
		return ref("api", "unknown")
	case strings.Contains(lt, "file"):
		return ref("file", "unknown")
	}
	return ResourceRef{}
}

func ref(typ, path string) ResourceRef {
	typ = strings.TrimSpace(typ)
	path = strings.TrimSpace(path)
	if typ == "" || path == "" {
		return ResourceRef{}
	}
	return ResourceRef{Type: typ, Path: path, ID: typ + ":" + path}
}

func normalizeMap(input any) map[string]any {
	switch v := input.(type) {
	case map[string]any:
		return v
	case []byte:
		var m map[string]any
		_ = json.Unmarshal(v, &m)
		return m
	case string:
		var m map[string]any
		_ = json.Unmarshal([]byte(v), &m)
		return m
	default:
		return nil
	}
}

func firstMapString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			s := strings.TrimSpace(fmt.Sprint(v))
			if s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

var sqlTableRE = regexp.MustCompile(`(?i)\b(?:from|join|update|into)\s+([a-zA-Z0-9_.-]+)`)

func tableFromSQL(query string) string {
	m := sqlTableRE.FindStringSubmatch(query)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func trimStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
