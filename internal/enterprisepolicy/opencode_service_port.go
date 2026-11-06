// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// OpenCode V2 runs a background server per account on 127.0.0.1. On the
// release channel its port is 49374 for every account, so on a computer with
// several users only the first one's server starts (gas-ux-r1 GAP-0053). Each
// account gets a port of its own, written as "port" in OpenCode's own
// service.json. The CLI (cli/defenseclaw/opencode_service.py) uses the same
// scheme for per-user installs; the guardian uses it for managed ones.
const (
	// OpenCodeDefaultServicePort is OpenCode 2.2.5's port for the latest,
	// dev, beta and next channels.
	OpenCodeDefaultServicePort = 49374
	// OpenCodeAccountPortBase and OpenCodeAccountPortSpan: an account's port
	// is base + (id mod span), below Linux's ephemeral range.
	OpenCodeAccountPortBase = 24000
	OpenCodeAccountPortSpan = 8000
	// openCodeServiceConfigLimit bounds the service.json read.
	openCodeServiceConfigLimit = 64 * 1024
)

// OpenCodeServiceConfigPath is OpenCode's service.json under home: OpenCode
// keeps it in the XDG config folder, ~/.config/opencode on every OS.
func OpenCodeServiceConfigPath(home string) string {
	return filepath.Join(home, ".config", "opencode", "service.json")
}

// OpenCodeAccountPort is the first port tried for account id (a uid, or the
// RID of a Windows SID).
func OpenCodeAccountPort(id uint64) int {
	return OpenCodeAccountPortBase + int(id%OpenCodeAccountPortSpan)
}

// ReadOpenCodeServicePortAsUser is the port the service.json under home names
// as the account sees it (its worker: links in the path resolve, a
// root-squashed home reads): 0 with no file or no port; an error when the
// file is there but cannot be read or is not a JSON object.
func ReadOpenCodeServicePortAsUser(home string) (int, error) {
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return 0, fmt.Errorf("opencode service port: home %q is not absolute", home)
	}
	path := OpenCodeServiceConfigPath(filepath.Clean(home))
	data, exists, regular, err := readUserFile(path, openCodeServiceConfigLimit)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	if !exists {
		return 0, nil
	}
	if !regular {
		return 0, fmt.Errorf("%s is not a regular file", path)
	}
	var doc map[string]json.RawMessage
	if len(strings.TrimSpace(string(data))) == 0 {
		return 0, nil
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc == nil {
		return 0, fmt.Errorf("%s is not a JSON object", path)
	}
	raw, ok := doc["port"]
	if !ok {
		return 0, nil
	}
	var port int
	if err := json.Unmarshal(raw, &port); err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("%s names a port that is not a number", path)
	}
	return port, nil
}

// OpenCodeServicePortResult is what EnsureOpenCodeServicePort found or did.
type OpenCodeServicePortResult struct {
	// Port is the port the account's service.json names after the call (0
	// when it names none).
	Port int
	// Changed reports that this call wrote the port.
	Changed bool
	// CreatedDirs are the folders below home the write created.
	CreatedDirs []string
}

// EnsureOpenCodeServicePort writes port as "port" into the account's
// service.json, as the account (the guardian's per-user worker). A port the
// file already names is kept, whoever set it; the other keys (OpenCode's
// password) are kept. A missing file is created at 0600; OpenCode adds its
// password on the next start (checked with 2.2.5). A link, a non-regular
// file or a file that is not a JSON object is left alone with an error.
func EnsureOpenCodeServicePort(home string, port int) (OpenCodeServicePortResult, error) {
	var result OpenCodeServicePortResult
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return result, fmt.Errorf("opencode service port: home %q is not absolute", home)
	}
	home = filepath.Clean(home)
	if port <= 0 || port > 65535 {
		return result, fmt.Errorf("opencode service port: %d is not a port", port)
	}
	path := OpenCodeServiceConfigPath(home)
	current, exists, regular, err := readUserFile(path, openCodeServiceConfigLimit)
	if err != nil {
		return result, fmt.Errorf("opencode service port: read %s: %w", path, err)
	}
	doc := map[string]json.RawMessage{}
	if exists {
		if !regular {
			return result, fmt.Errorf("opencode service port: %s is not a regular file; left in place", path)
		}
		if len(strings.TrimSpace(string(current))) > 0 {
			if err := json.Unmarshal(current, &doc); err != nil || doc == nil {
				return result, fmt.Errorf("opencode service port: %s is not a JSON object; left in place", path)
			}
		}
		if raw, ok := doc["port"]; ok {
			var existing int
			if err := json.Unmarshal(raw, &existing); err != nil || existing <= 0 || existing > 65535 {
				return result, fmt.Errorf("opencode service port: %s names a port that is not a number; left in place", path)
			}
			result.Port = existing
			return result, nil
		}
	}
	encoded, _ := json.Marshal(port)
	doc["port"] = encoded
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return result, err
	}
	missing := missingDirsBelow(home, path)
	if err := writePrivateUserFile(path, append(data, '\n')); err != nil {
		return result, fmt.Errorf("opencode service port: write %s: %w", path, err)
	}
	result.Port, result.Changed, result.CreatedDirs = port, true, missing
	return result, nil
}

// OpenCodePortConflict is a port two accounts claim: Holder keeps it, UID is
// moved (or, with no new ports allowed, left alone and reported).
type OpenCodePortConflict struct {
	UID, Holder, Port int
}

// OpenCodePortPlan is one guardian pass's decision (PlanOpenCodeServicePorts).
type OpenCodePortPlan struct {
	// Ports is the port each eligible account ends the pass with.
	Ports map[int]int
	// Replace names the eligible accounts whose service.json names a port
	// another account holds: the worker replaces that port (the value) with
	// the one in Ports.
	Replace map[int]int
	// Record is the record after the pass: every eligible account's port and
	// every other recorded entry (never dropped).
	Record map[int]int
	// Conflicts are the ports two accounts claimed, for the log.
	Conflicts []OpenCodePortConflict
	// NoPort are eligible accounts that get no port this pass: the range is
	// full, or no new port may be given (allowNew false).
	NoPort []int
}

// PlanOpenCodeServicePorts decides every account's OpenCode service port so
// that no two accounts ever hold the same one (REVIEW-gx053-4). filePorts are
// the ports the eligible accounts' own service.json files name; recorded is
// the guardian's record (uid -> port, every account that ever had one).
// Precedence, earlier holder first:
//  1. an eligible account whose file names its own recorded port;
//  2. every other recorded entry (departed, excluded, directory accounts and
//     eligible accounts whose file names no port);
//  3. an eligible account's file port that nobody above holds;
//  4. a new port (allowNew only), the account's recorded port when it is
//     free, else the first free one from OpenCodeAccountPort.
//
// A file port that another account holds is a conflict: that account is
// moved to a port of its own (Replace) and the conflict is reported. With
// allowNew false (the record could not be read) nobody gets a new port and
// nobody is moved.
func PlanOpenCodeServicePorts(eligible []int, filePorts, recorded map[int]int, allowNew bool) OpenCodePortPlan {
	plan := OpenCodePortPlan{Ports: map[int]int{}, Replace: map[int]int{}, Record: map[int]int{}}
	sortedEligible := append([]int(nil), eligible...)
	sort.Ints(sortedEligible)
	isEligible := map[int]bool{}
	for _, uid := range sortedEligible {
		isEligible[uid] = true
	}
	recordedUIDs := make([]int, 0, len(recorded))
	for uid := range recorded {
		recordedUIDs = append(recordedUIDs, uid)
	}
	sort.Ints(recordedUIDs)
	holder := map[int]int{}
	hold := func(uid, port int) bool {
		if port <= 0 || port > 65535 {
			return false
		}
		if other, taken := holder[port]; taken && other != uid {
			return false
		}
		holder[port] = uid
		return true
	}
	// 1. Established: the file names the account's own recorded port.
	for _, uid := range sortedEligible {
		if port := filePorts[uid]; port > 0 && recorded[uid] == port && hold(uid, port) {
			plan.Ports[uid] = port
		}
	}
	// 2. Every other recorded entry, ascending uid.
	var superseded []int
	for _, uid := range recordedUIDs {
		if _, placed := plan.Ports[uid]; placed || (isEligible[uid] && filePorts[uid] > 0) {
			continue
		}
		port := recorded[uid]
		if hold(uid, port) {
			if isEligible[uid] {
				plan.Ports[uid] = port
			} else {
				plan.Record[uid] = port
			}
			continue
		}
		if isEligible[uid] {
			plan.Conflicts = append(plan.Conflicts, OpenCodePortConflict{UID: uid, Holder: holder[port], Port: port})
		} else {
			superseded = append(superseded, uid)
		}
	}
	// 3. File ports nobody above holds.
	var fresh []int
	for _, uid := range sortedEligible {
		if _, placed := plan.Ports[uid]; placed {
			continue
		}
		port := filePorts[uid]
		if port <= 0 {
			fresh = append(fresh, uid)
			continue
		}
		if hold(uid, port) {
			plan.Ports[uid] = port
			continue
		}
		plan.Conflicts = append(plan.Conflicts, OpenCodePortConflict{UID: uid, Holder: holder[port], Port: port})
		if allowNew {
			plan.Replace[uid] = port
		}
		fresh = append(fresh, uid)
	}
	// 4. New ports.
	next := func(uid int) int {
		if port := recorded[uid]; port > 0 && hold(uid, port) {
			return port
		}
		start := OpenCodeAccountPort(uint64(uid))
		for step := 0; step < OpenCodeAccountPortSpan; step++ {
			port := OpenCodeAccountPortBase + (start-OpenCodeAccountPortBase+step)%OpenCodeAccountPortSpan
			if hold(uid, port) {
				return port
			}
		}
		return 0
	}
	sort.Ints(fresh)
	for _, uid := range fresh {
		if _, placed := plan.Ports[uid]; placed {
			continue
		}
		port := 0
		if allowNew {
			port = next(uid)
		}
		if port == 0 {
			plan.NoPort = append(plan.NoPort, uid)
			delete(plan.Replace, uid)
			continue
		}
		plan.Ports[uid] = port
	}
	for _, uid := range superseded {
		port := 0
		if allowNew {
			port = next(uid)
		}
		if port == 0 {
			port = recorded[uid] // nothing free: the entry stays as it was
		}
		plan.Record[uid] = port
	}
	for uid, port := range plan.Ports {
		plan.Record[uid] = port
	}
	sort.Ints(plan.NoPort)
	return plan
}

// ReplaceOpenCodeServicePort is EnsureOpenCodeServicePort for an account whose
// service.json names a port another account holds: when the file still names
// stale, it is replaced with port; any other port the file names is kept.
func ReplaceOpenCodeServicePort(home string, port, stale int) (OpenCodeServicePortResult, error) {
	result, err := EnsureOpenCodeServicePort(home, port)
	if err != nil || result.Changed || result.Port != stale || stale == port {
		return result, err
	}
	path := OpenCodeServiceConfigPath(filepath.Clean(home))
	current, _, _, err := readUserFile(path, openCodeServiceConfigLimit)
	if err != nil {
		return result, fmt.Errorf("opencode service port: read %s: %w", path, err)
	}
	doc := map[string]json.RawMessage{}
	if err := json.Unmarshal(current, &doc); err != nil {
		return result, fmt.Errorf("opencode service port: %s is not a JSON object; left in place", path)
	}
	encoded, _ := json.Marshal(port)
	doc["port"] = encoded
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return result, err
	}
	if err := writePrivateUserFile(path, append(data, '\n')); err != nil {
		return result, fmt.Errorf("opencode service port: write %s: %w", path, err)
	}
	return OpenCodeServicePortResult{Port: port, Changed: true}, nil
}
