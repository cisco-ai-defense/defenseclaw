// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	// dev, beta and next channels; openCodeLocalChannelPort its local one.
	OpenCodeDefaultServicePort = 49374
	openCodeLocalChannelPort   = 49375
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

// ReadOpenCodeServicePortAsUser is ReadOpenCodeServicePortSealed without the
// list of folders it sealed (the Windows guardian seals none).
func ReadOpenCodeServicePortAsUser(home string) (int, error) {
	port, _, err := ReadOpenCodeServicePortSealed(home)
	return port, err
}

// ReadOpenCodeServicePortSealed is the port the service.json under home names
// as the account sees it (its worker: links in the path resolve, a
// root-squashed home reads): 0 with no file or no port; an error when the
// file is there but cannot be read or is not a JSON object.
//
// This read is the one-time import that can bind a port into the protected
// record, so it trusts only what no other account controls (GAP-0053
// REVIEW-5 MF1): it walks the same path the setter walks before it opens
// anything, which refuses a folder or entry of another account and makes a
// folder the group can write sticky (nobody but the owner of an entry can then
// rename it), and it reads a file only while the file it holds open is owned
// by the account or root and no group or other account can write it. A file
// that fails the second test names no port: it is not imported and the
// account gets a fresh one, which the setter then writes into a private copy.
// The folders it sealed are returned so the guardian can report them.
func ReadOpenCodeServicePortSealed(home string) (int, []string, error) {
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return 0, nil, fmt.Errorf("opencode service port: home %q is not absolute", home)
	}
	path := OpenCodeServiceConfigPath(filepath.Clean(home))
	sealed, err := checkOpenCodeServiceConfigFolders(filepath.Clean(home), path, true)
	if err != nil {
		return 0, sealed, fmt.Errorf("read %s: %w", path, err)
	}
	// This read runs under the account identity. Follow a final file link so
	// its existing port participates in the one-time import; the privileged
	// writer below still refuses a final link.
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, sealed, nil
	}
	if err != nil {
		return 0, sealed, fmt.Errorf("read %s: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 0, sealed, fmt.Errorf("%s is not a regular file: %v", path, err)
	}
	if !openCodeImportFileTrusted(path, file) {
		return 0, sealed, nil
	}
	data, err := io.ReadAll(io.LimitReader(file, openCodeServiceConfigLimit+1))
	if err != nil {
		return 0, sealed, fmt.Errorf("read %s: %w", path, err)
	}
	// The file was private when it was opened; it must still be when it has
	// been read, or what was read is not an input of this account.
	if !openCodeImportFileTrusted(path, file) {
		return 0, sealed, nil
	}
	if len(data) > openCodeServiceConfigLimit {
		return 0, sealed, fmt.Errorf("%s exceeds the service file limit", path)
	}
	var doc map[string]json.RawMessage
	if len(strings.TrimSpace(string(data))) == 0 {
		return 0, sealed, nil
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc == nil {
		return 0, sealed, fmt.Errorf("%s is not a JSON object", path)
	}
	raw, ok := doc["port"]
	if !ok {
		return 0, sealed, nil
	}
	var port int
	if err := json.Unmarshal(raw, &port); err != nil || port <= 0 || port > 65535 {
		return 0, sealed, fmt.Errorf("%s names a port that is not a number", path)
	}
	return port, sealed, nil
}

// OpenCodeServicePortResult is what SetOpenCodeServicePort found or did.
type OpenCodeServicePortResult struct {
	// Port is the port the account's service.json names after the call.
	Port int
	// Previous is the port the file named before the call (0: none).
	Previous int
	// Changed reports that this call wrote the port.
	Changed bool
	// CreatedDirs are the folders below home the write created.
	CreatedDirs []string
	// Sealed are the folders on the path to service.json that the account's
	// group could write and this call made sticky, so that nobody but the
	// owner of an entry in them can rename it (Unix; none on Windows).
	Sealed []string
}

// SetOpenCodeServicePort makes the account's service.json name port, as the
// account (the guardian's per-user worker). The record is the only authority
// (REVIEW-gx053-9): a file that names another port is rewritten. The other
// keys (OpenCode's password) are kept; a missing file is created at 0600 and
// OpenCode adds its password on the next start (checked with 2.2.5). A link
// in place of the folder, a non-regular file or a file that is not a JSON
// object is left alone with an error: the guardian then changes nothing in
// its record and warns.
func SetOpenCodeServicePort(home string, port int) (OpenCodeServicePortResult, error) {
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
	// A port that already matches is not accepted through a path another
	// account could replace, any more than a write is.
	sealed, err := checkOpenCodeServiceConfigFolders(home, path, false)
	result.Sealed = sealed
	if err != nil {
		return result, fmt.Errorf("opencode service port: %s: %w", path, err)
	}
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
			_ = json.Unmarshal(raw, &result.Previous)
			// A matching file that another account could write is not
			// accepted as it stands: it is rewritten as a private copy.
			if result.Previous == port && !openCodeServiceFileShared(path) {
				result.Port = port
				return result, nil
			}
		}
	}
	encoded, _ := json.Marshal(port)
	doc["port"] = encoded
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return result, err
	}
	missing := missingDirsBelow(home, path)
	if err := writeOpenCodeServiceConfig(home, path, append(data, '\n')); err != nil {
		return result, fmt.Errorf("opencode service port: write %s: %w", path, err)
	}
	result.Port, result.Changed, result.CreatedDirs = port, true, missing
	return result, nil
}

// OpenCodePortConflict is a port an account's file names (an import) that
// the record gives another account: the account gets a fresh port instead.
type OpenCodePortConflict struct {
	UID, Holder, Port int
}

// OpenCodePortPlan is one guardian pass's decision (PlanOpenCodeServicePorts).
type OpenCodePortPlan struct {
	// Ports is the port each eligible account ends the pass with: its
	// recorded port, or the port this pass binds for it.
	Ports map[int]int
	// Record is the record after the pass: every recorded binding, unchanged,
	// and the new ones.
	Record map[int]int
	// Conflicts are imports refused because the record gives the port to
	// another account, and record entries that paired two accounts.
	Conflicts []OpenCodePortConflict
	// Contested are ports two or more unrecorded accounts' files name in one
	// pass (port -> the claimants, ascending): nobody is given such a port,
	// every claimant gets a fresh one (REVIEW-gx053-10).
	Contested map[int][]int
	// NoPort are eligible accounts that get no port this pass: the range is
	// full, or no new binding may be made (allowNew false).
	NoPort []int
}

// PlanOpenCodeServicePorts binds OpenCode service ports with the guardian's
// root-owned record as the only authority (REVIEW-gx053-9):
//  1. a uid's recorded port never changes because of any user's file: the
//     account gets its recorded port and the worker writes it into the file;
//  2. a uid with no record entry yet imports the port its own file names
//     (imports), but only when the record gives that port to no other uid
//     and no other unrecorded uid's file names it in the same pass: every
//     claim is collected before any is granted, a contested port is given to
//     nobody, and each claimant gets a fresh port (nothing a user controls,
//     not uid order and not a listener, decides). OpenCode's own defaults
//     (49374, 49375) are not imported. Otherwise, and with no file port, a
//     fresh port;
//  3. new ports come from the pool minus every recorded port, so excluded
//     and departed accounts keep theirs;
//  4. an unknown uid (its file could not be read) with no record entry gets
//     nothing this pass; allowNew false (the record could not be read) binds
//     nothing new.
//
// A record that pairs two uids with one port (written by an earlier build)
// keeps the lower uid on it and rebinds the other, reported as a conflict.
// importWindow is true only in the pass that creates or rebuilds the record.
// Contested ports stay marked until an administrator clears them. A per-user
// claim reserves a free port from other accounts while its owner may retry it.
func PlanOpenCodeServicePorts(eligible []int, imports, recorded map[int]int, allowNew bool, unknown map[int]bool, importWindow bool, contestedMarks map[int]bool) OpenCodePortPlan {
	return planOpenCodeServicePorts(eligible, imports, recorded, allowNew, unknown, importWindow, contestedMarks, nil)
}

func planOpenCodeServicePorts(eligible []int, imports, recorded map[int]int, allowNew bool, unknown map[int]bool, importWindow bool, contestedMarks map[int]bool, reserved map[int]int) OpenCodePortPlan {
	plan := OpenCodePortPlan{Ports: map[int]int{}, Record: map[int]int{}}
	holder := map[int]int{}
	recordedUIDs := make([]int, 0, len(recorded))
	for uid := range recorded {
		recordedUIDs = append(recordedUIDs, uid)
	}
	sort.Ints(recordedUIDs)
	var rebind []int
	for _, uid := range recordedUIDs {
		port := recorded[uid]
		if port <= 0 || port > 65535 {
			continue
		}
		if other, taken := holder[port]; taken {
			plan.Conflicts = append(plan.Conflicts, OpenCodePortConflict{UID: uid, Holder: other, Port: port})
			rebind = append(rebind, uid)
			continue
		}
		holder[port] = uid
		plan.Record[uid] = port
	}
	sortedEligible := append([]int(nil), eligible...)
	sort.Ints(sortedEligible)
	isEligible := map[int]bool{}
	for _, uid := range sortedEligible {
		isEligible[uid] = true
		if port, ok := plan.Record[uid]; ok {
			plan.Ports[uid] = port
		}
	}
	contested := map[int]bool{}
	for port := range contestedMarks {
		contested[port] = true
	}
	fresh := func(uid int) int {
		start := OpenCodeAccountPort(uint64(uid))
		for step := 0; step < OpenCodeAccountPortSpan; step++ {
			port := OpenCodeAccountPortBase + (start-OpenCodeAccountPortBase+step)%OpenCodeAccountPortSpan
			_, taken := holder[port]
			owner, claimed := reserved[port]
			if !taken && !contested[port] && (!claimed || owner == uid) {
				holder[port] = uid
				return port
			}
		}
		return 0
	}
	if !allowNew {
		for _, uid := range sortedEligible {
			if _, bound := plan.Ports[uid]; !bound {
				plan.NoPort = append(plan.NoPort, uid)
			}
		}
		for _, uid := range rebind {
			plan.Record[uid] = recorded[uid]
		}
		return plan
	}
	// Collect every import claim of the pass before granting any (order
	// independent), so a claim decides nothing by uid order.
	claims := map[int][]int{}
	var needFresh []int
	for _, uid := range sortedEligible {
		if _, bound := plan.Ports[uid]; bound {
			continue
		}
		if unknown[uid] && importWindow {
			// Not importable in the window: no import later either; a fresh
			// port once its file can be written.
			needFresh = append(needFresh, uid)
			continue
		}
		port := imports[uid]
		if !importWindow || contested[port] || port <= 0 || port > 65535 || port == OpenCodeDefaultServicePort || port == openCodeLocalChannelPort {
			needFresh = append(needFresh, uid)
			continue
		}
		claims[port] = append(claims[port], uid)
	}
	ports := make([]int, 0, len(claims))
	for port := range claims {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	for _, port := range ports {
		claimants := claims[port]
		if other, taken := holder[port]; taken {
			for _, uid := range claimants {
				plan.Conflicts = append(plan.Conflicts, OpenCodePortConflict{UID: uid, Holder: other, Port: port})
			}
			needFresh = append(needFresh, claimants...)
			continue
		}
		if len(claimants) > 1 {
			contested[port] = true
			if plan.Contested == nil {
				plan.Contested = map[int][]int{}
			}
			plan.Contested[port] = claimants
			needFresh = append(needFresh, claimants...)
			continue
		}
		uid := claimants[0]
		if owner, claimed := reserved[port]; claimed && owner != uid {
			if owner > 0 {
				plan.Conflicts = append(plan.Conflicts, OpenCodePortConflict{UID: uid, Holder: owner, Port: port})
			}
			needFresh = append(needFresh, uid)
			continue
		}
		holder[port] = uid
		plan.Ports[uid], plan.Record[uid] = port, port
	}
	sort.Ints(needFresh)
	for _, uid := range append(rebind, needFresh...) {
		if _, bound := plan.Ports[uid]; bound {
			continue
		}
		port := fresh(uid)
		if port == 0 {
			if isEligible[uid] {
				plan.NoPort = append(plan.NoPort, uid)
			}
			if old, ok := recorded[uid]; ok {
				plan.Record[uid] = old // nothing free: the entry stays
			}
			continue
		}
		plan.Record[uid] = port
		if isEligible[uid] {
			plan.Ports[uid] = port
		}
	}
	sort.Ints(plan.NoPort)
	return plan
}
