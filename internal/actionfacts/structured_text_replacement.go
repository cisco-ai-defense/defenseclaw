// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	protectedFirewallConfigurationPath = "/etc/firewall/firewall.conf"
	maxStructuredReplacementIPv4s      = 16
)

var literalIPv4CandidatePattern = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)

// ExactFirewallTrustExpansionIPv4 returns the only literal IPv4 address added
// by one direct replacement of the protected firewall configuration. The old
// and new file fragments are never retained in Facts.
//
// This is contextual detection evidence, not authorization to block. Runtime
// lifecycle handling must first prove that the edit succeeded, and a separate
// deployment policy must establish both resource protection and destination
// trust before this chain can become enforcement-safe.
func ExactFirewallTrustExpansionIPv4(facts Facts) (string, bool) {
	if len(facts.StructuredTextReplacements) != 1 {
		return "", false
	}
	replacement := facts.StructuredTextReplacements[0]
	if replacement.Path.Access != PathAccessWrite ||
		replacement.Path.Flavor != PathFlavorPOSIX ||
		replacement.Path.Resolved != protectedFirewallConfigurationPath ||
		len(replacement.AddedIPv4) != 1 {
		return "", false
	}
	address, err := netip.ParseAddr(replacement.AddedIPv4[0])
	if err != nil || !address.Is4() {
		return "", false
	}
	return address.String(), true
}

// HasStructuredTextReplacement reports whether a closed-schema direct text
// replacement may have changed local file bytes. It lets the bounded matcher
// conservatively invalidate path-based lineage after an intervening edit.
func HasStructuredTextReplacement(facts Facts) bool {
	return len(facts.StructuredTextReplacements) != 0
}

func projectStructuredTextReplacements(input Input) []StructuredTextReplacementFact {
	target, oldText, newText, ok := exactStructuredTextReplacement(input)
	if !ok {
		return nil
	}
	pathFact := PathFact{
		Access: PathAccessWrite,
		Flavor: pathFlavor(target),
		Value:  target,
	}
	paths := []PathFact{pathFact}
	normalizePathFacts(paths, input.CWD, input.ActiveHome)
	pathFact = paths[0]
	if pathFact.Flavor != PathFlavorPOSIX || pathFact.Resolved == "" ||
		hasUnresolvedPathSyntax(pathFact.Value) {
		return nil
	}
	added, bounded := literalIPv4Difference(oldText, newText)
	if !bounded {
		// Retain the value-free mutation fact so this action still invalidates
		// earlier lineage, but do not expose an incomplete identity delta.
		added = nil
	}
	return []StructuredTextReplacementFact{{Path: pathFact, AddedIPv4: added}}
}

func exactStructuredTextReplacement(input Input) (string, string, string, bool) {
	if strings.ToLower(input.Tool) != "text_editor" ||
		strings.TrimSpace(input.Tool) != input.Tool || len(input.Args) == 0 ||
		len(input.Args) > maxArgsJSONBytes || !utf8.Valid(input.Args) {
		return "", "", "", false
	}
	if issue := validateJSONWithStringLimit(input.Args, maxArgsJSONBytes); issue != "" {
		return "", "", "", false
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(input.Args))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || len(object) != 4 {
		return "", "", "", false
	}
	operation, operationOK := object["command"].(string)
	target, pathOK := object["path"].(string)
	oldText, oldOK := object["old_str"].(string)
	newText, newOK := object["new_str"].(string)
	if !operationOK || operation != "str_replace" || !pathOK || !oldOK || !newOK ||
		target == "" || strings.TrimSpace(target) != target ||
		len(target) > maxScalarBytes || strings.IndexByte(target, 0) >= 0 ||
		oldText == "" || newText == "" || oldText == newText ||
		pathFlavor(target) != PathFlavorPOSIX || !strings.HasPrefix(target, "/") {
		return "", "", "", false
	}
	for key := range object {
		switch key {
		case "command", "path", "old_str", "new_str":
		default:
			return "", "", "", false
		}
	}
	return target, oldText, newText, true
}

func literalIPv4Difference(oldText, newText string) ([]string, bool) {
	oldAddresses, oldBounded := literalIPv4Set(oldText)
	newAddresses, newBounded := literalIPv4Set(newText)
	if !oldBounded || !newBounded {
		return nil, false
	}
	added := make([]string, 0, len(newAddresses))
	for address := range newAddresses {
		if _, existed := oldAddresses[address]; !existed {
			added = append(added, address)
		}
	}
	sort.Strings(added)
	return added, true
}

func literalIPv4Set(value string) (map[string]struct{}, bool) {
	addresses := make(map[string]struct{})
	for _, bounds := range literalIPv4CandidatePattern.FindAllStringIndex(value, -1) {
		if bounds[0] > 0 && isIPv4TokenByte(value[bounds[0]-1]) ||
			bounds[1] < len(value) && isIPv4TokenByte(value[bounds[1]]) {
			continue
		}
		address, err := netip.ParseAddr(value[bounds[0]:bounds[1]])
		if err != nil || !address.Is4() {
			continue
		}
		addresses[address.String()] = struct{}{}
		if len(addresses) > maxStructuredReplacementIPv4s {
			return nil, false
		}
	}
	return addresses, true
}

func isIPv4TokenByte(value byte) bool {
	return value == '.' || value >= '0' && value <= '9'
}
