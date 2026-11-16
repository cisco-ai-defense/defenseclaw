// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package contracttest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

// ForwardDir holds the forward schemas (management-agent.md, "What to
// forward"), relative to a package directory under internal/.
const ForwardDir = Dir + "/forward"

// forwardOf names the forward schema that projects the documents of each
// contract schema. Validate projects every whole document of these schemas
// through it (CheckForward), so each contract test that validates a real
// document also checks what of it may leave the device.
var forwardOf = map[string]string{
	"lifecycle-result.schema.json": "lifecycle-result-forward.schema.json",
	"bundle-verify.schema.json":    "bundle-verify-forward.schema.json",
	"bundle-status.schema.json":    "bundle-status-forward.schema.json",
	"bundle-receipt.schema.json":   "bundle-receipt-forward.schema.json",
	"identity-refresh.schema.json": "identity-refresh-forward.schema.json",
}

// KeepOnDevice are the member names a forward schema drops on purpose: they
// name accounts, hold credential names, free text, paths, process details or
// tenant and key choices. management-agent.md ("What to forward") names each
// of them. A real document member a projection drops that is not one of
// these is a contradiction between the documents DefenseClaw prints and its
// forward schemas: list the member in the forward schema when it is safe to
// send, or add it here and to the guide when it is not (sidecar-r107
// GAP-0006: the guide said to forward session connector names that the
// forward schema dropped).
var KeepOnDevice = []string{
	// Account names, identifiers and free text.
	"accounts", "actor", "principal", "created_by", "change_summary", "changes", "entries", "message",
	"subject", "reason", "detail", "last_reload_error", "error_message", "excluded_users", "excluded_groups", "removed_connectors",
	// Credential names: secret_refs[].name, secret_refs_missing, secret_refs_mismatch.
	"name", "secret_refs_missing", "secret_refs_mismatch",
	// Local detail: services, machine policy, observability destinations,
	// the audit store, scanners, API port holders, paths.
	"services", "machine_policy", "destinations", "audit_store", "scanners", "api_port_holders",
	"log_path", "dir", "path", "package_path",
	// Account ids: identity refresh failures[].user_id and the accounts of
	// windows_token_groups_pending.
	"user_id", "user_name", "windows_token_groups_pending",
	// Tenant, device group and signing-key choices of the administrator.
	"anchors", "keys", "tenant_id", "device_group", "device_groups", "signer_key_id",
}

// forwardKeepGuideMembers are the KeepOnDevice members the guide names as
// written there (a qualified name for the ambiguous ones).
var forwardKeepGuideMembers = map[string]string{
	"accounts": "enrollment.accounts", "entries": "sessions_restart_required.entries",
	"message": "warning and error messages", "name": "secret_refs[].name",
}

// CheckForward projects document, a real document of the contract schema
// name, through its forward schema as forward/project.py does, requires the
// projection to validate against that forward schema, and fails for every
// member it drops that is not in KeepOnDevice. It returns the projection.
func (s Schemas) CheckForward(t testing.TB, name string, document any) map[string]any {
	t.Helper()
	forward, ok := forwardOf[name]
	if !ok {
		t.Fatalf("no forward schema projects %s", name)
	}
	root := s.forwardRoot(t, forward)
	var dropped []string
	projected, kept := project(document, root, root, "", &dropped)
	if !kept {
		projected = map[string]any{}
	}
	if err := s.schema(t, "forward/"+forward).Validate(projected); err != nil {
		t.Errorf("forward/%s rejects its own projection of a real %s document: %v", forward, name, err)
	}
	for _, path := range dropped {
		if !slices.Contains(KeepOnDevice, memberName(path)) {
			t.Errorf("forward/%s drops %s of a real %s document: list it in the forward schema when it is safe to send off the device, else add %q to contracttest.KeepOnDevice and to management-agent.md, What to forward",
				forward, path, name, memberName(path))
		}
	}
	object, _ := projected.(map[string]any)
	return object
}

// Project is the projection CheckForward makes, and the member paths it drops.
func (s Schemas) Project(t testing.TB, forward string, document any) (map[string]any, []string) {
	t.Helper()
	root := s.forwardRoot(t, forward)
	var dropped []string
	projected, _ := project(document, root, root, "", &dropped)
	object, _ := projected.(map[string]any)
	if object == nil {
		object = map[string]any{}
	}
	return object, dropped
}

func (s Schemas) forwardRoot(t testing.TB, forward string) map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if root, ok := s.forward[forward]; ok {
		return root
	}
	data, err := os.ReadFile(filepath.Join(filepath.FromSlash(ForwardDir), forward))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		t.Fatalf("forward/%s: %v", forward, err)
	}
	s.forward[forward] = root
	return root
}

// memberName is the last member name of a dropped path such as
// ".warnings[2].message" or ".sessions_restart_required.entries[0]".
func memberName(path string) string {
	path = strings.TrimRight(path, "]0123456789[")
	return path[strings.LastIndex(path, ".")+1:]
}

// forwardPatterns caches the compiled patterns of the forward schemas.
var forwardPatterns patternCache

type patternCache struct{ m sync.Map }

func (p *patternCache) match(pattern, value string) bool {
	re, ok := p.m.Load(pattern)
	if !ok {
		re, _ = p.m.LoadOrStore(pattern, regexp.MustCompile(pattern))
	}
	return re.(*regexp.Regexp).MatchString(value)
}

func resolve(schema, root map[string]any) map[string]any {
	for {
		ref, ok := schema["$ref"].(string)
		if !ok {
			return schema
		}
		name, local := strings.CutPrefix(ref, "#/$defs/")
		if !local {
			panic("forward schemas use local references only: " + ref)
		}
		schema = root["$defs"].(map[string]any)[name].(map[string]any)
	}
}

func sameJSON(a, b any) bool {
	x, errX := json.Marshal(a)
	y, errY := json.Marshal(b)
	return errX == nil && errY == nil && bytes.Equal(x, y)
}

func isInteger(value any) bool {
	switch v := value.(type) {
	case json.Number:
		_, err := v.Int64()
		return err == nil
	case float64:
		return v == float64(int64(v))
	case int, int64:
		return true
	}
	return false
}

// project mirrors project_value of forward/project.py: allowlist-and-drop.
// It reports false when nothing of value may be sent, and appends the paths
// of the members it drops to dropped.
func project(value any, schema, root map[string]any, path string, dropped *[]string) (any, bool) {
	schema = resolve(schema, root)
	if constant, ok := schema["const"]; ok {
		return value, sameJSON(value, constant)
	}
	kind, _ := schema["type"].(string)
	_, hasProperties := schema["properties"]
	switch {
	case kind == "object" || hasProperties:
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		properties, _ := schema["properties"].(map[string]any)
		extra, _ := schema["additionalProperties"].(map[string]any)
		names, _ := schema["propertyNames"].(map[string]any)
		namePattern, _ := names["pattern"].(string)
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := map[string]any{}
		for _, key := range keys {
			member := path + "." + key
			var projected any
			kept := false
			if child, listed := properties[key].(map[string]any); listed {
				projected, kept = project(object[key], child, root, member, dropped)
			} else if extra != nil && namePattern != "" && forwardPatterns.match(namePattern, key) {
				projected, kept = project(object[key], extra, root, member, dropped)
			}
			switch {
			case kept:
				out[key] = projected
			case object[key] != nil && object[key] != "":
				// A null or empty member carries nothing to forward.
				*dropped = append(*dropped, member)
			}
		}
		return out, true
	case kind == "array":
		list, ok := value.([]any)
		if !ok {
			return nil, false
		}
		items, _ := schema["items"].(map[string]any)
		out := []any{}
		for i, item := range list {
			if projected, kept := project(item, items, root, fmt.Sprintf("%s[%d]", path, i), dropped); kept {
				out = append(out, projected)
			} else {
				*dropped = append(*dropped, fmt.Sprintf("%s[%d]", path, i))
			}
		}
		if limit, ok := schema["maxItems"].(json.Number); ok {
			if n, err := limit.Int64(); err == nil && int64(len(out)) > n {
				for i := n; i < int64(len(out)); i++ {
					*dropped = append(*dropped, fmt.Sprintf("%s[%d]", path, i))
				}
				out = out[:n]
			}
		}
		return out, true
	case kind == "string":
		text, ok := value.(string)
		if !ok {
			return nil, false
		}
		enum, hasEnum := schema["enum"].([]any)
		pattern, hasPattern := schema["pattern"].(string)
		if !hasEnum && !hasPattern {
			return nil, false
		}
		if hasEnum && !slices.ContainsFunc(enum, func(e any) bool { return e == text }) {
			return nil, false
		}
		if hasPattern && !forwardPatterns.match(pattern, text) {
			return nil, false
		}
		return text, true
	case kind == "boolean":
		_, ok := value.(bool)
		return value, ok
	case kind == "integer":
		return value, isInteger(value)
	}
	if enum, ok := schema["enum"].([]any); ok {
		return value, slices.ContainsFunc(enum, func(e any) bool { return sameJSON(e, value) })
	}
	return nil, false
}
