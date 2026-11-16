// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The managed Mac's two per-user LaunchAgents. Their job label carries a tag
// of the gateway program they run (LaunchAgentLabel): macOS keeps the
// Background Task Management and launch-constraint decision it made for a
// job label, and after an upgrade it killed the job under the old label for
// code signing (OS_REASON_CODESIGNING) for an AD account. A bootout and
// bootstrap, a rewritten plist and a reinstall all kept that decision; only a
// label macOS had not seen ran the new program (GAP-0206). 1.0.0 to 1.0.3
// installed the bare base label.
const (
	LaunchAgentsDir   = "/Library/LaunchAgents"
	SandboxAgentBase  = "com.cisco.defenseclaw.sandbox"
	GatewayAgentBase  = "com.cisco.defenseclaw.openshell-gateway"
	launchAgentTagLen = 12
)

// LaunchAgentBases are the bases of both agents, the sandbox daemon first.
var LaunchAgentBases = []string{SandboxAgentBase, GatewayAgentBase}

// LaunchAgentLabel is the job label of base for the gateway program whose
// SHA-256 is gatewayDigest (hex): base.<the first 12 digits>. An unknown
// digest keeps the bare base.
func LaunchAgentLabel(base, gatewayDigest string) string {
	if len(gatewayDigest) < launchAgentTagLen || !isLowerHex(gatewayDigest[:launchAgentTagLen]) {
		return base
	}
	return base + "." + gatewayDigest[:launchAgentTagLen]
}

// IsLaunchAgentLabel reports whether label is a job label of base: the bare
// base of 1.0.0 to 1.0.3 or a tagged one.
func IsLaunchAgentLabel(base, label string) bool {
	if label == base {
		return true
	}
	tag, ok := strings.CutPrefix(label, base+".")
	return ok && len(tag) == launchAgentTagLen && isLowerHex(tag)
}

// LaunchAgentLabelsIn lists the job labels of base that the services section
// of `launchctl print <domain>` names, in its order.
func LaunchAgentLabelsIn(listing []byte, base string) []string {
	var labels []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		label := fields[len(fields)-1]
		if IsLaunchAgentLabel(base, label) && !seen[label] {
			seen[label] = true
			labels = append(labels, label)
		}
	}
	return labels
}

// LaunchDomain is the launchd domain of the account uid's job of base, whose
// installed label is label, from what print (`launchctl print DOMAIN`) says
// of each domain: the one that lists label, else one that lists an earlier
// label of base, else the graphical session when there is one, else the
// background session of an ssh login. launchd keeps one job per label for
// an account, whichever of its sessions loaded it (a sign-in's Background
// session, a root lifecycle's bootstrap): a bootstrap into the other
// domain fails with "Bootstrap failed: 5: Input/output error", and a
// kickstart, stop or kill there finds no job (GAP-0863). listing is what
// print said of the domain picked.
func LaunchDomain(uid int, base, label string, print func(domain string) (string, error)) (domain, listing string) {
	gui, user := "gui/"+strconv.Itoa(uid), "user/"+strconv.Itoa(uid)
	guiOut, guiErr := print(gui)
	guiLabels := LaunchAgentLabelsIn([]byte(guiOut), base)
	if guiErr == nil && slices.Contains(guiLabels, label) {
		return gui, guiOut
	}
	userOut, userErr := print(user)
	userLabels := LaunchAgentLabelsIn([]byte(userOut), base)
	switch {
	case guiErr != nil:
		return user, userOut
	case userErr == nil && slices.Contains(userLabels, label):
		return user, userOut
	case len(guiLabels) == 0 && userErr == nil && len(userLabels) > 0:
		return user, userOut
	}
	return gui, guiOut
}

// FindLaunchAgent is the installed job of base in dir: its label and plist.
// The lifecycle keeps one plist of each base; while an upgrade replaces it,
// the newest tagged plist wins, and a host with none has the bare base.
func FindLaunchAgent(dir, base string) (label, plist string) {
	type candidate struct {
		label   string
		modTime int64
	}
	var found []candidate
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".plist")
		if !ok || name == base || !IsLaunchAgentLabel(base, name) {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		found = append(found, candidate{label: name, modTime: info.ModTime().UnixNano()})
	}
	if len(found) == 0 {
		return base, filepath.Join(dir, base+".plist")
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].modTime != found[j].modTime {
			return found[i].modTime > found[j].modTime
		}
		return found[i].label < found[j].label
	})
	return found[0].label, filepath.Join(dir, found[0].label+".plist")
}

func isLowerHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return s != ""
}
