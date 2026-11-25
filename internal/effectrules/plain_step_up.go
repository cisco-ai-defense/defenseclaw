// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// plainStepUpProof promotes a POSIX operand with .. only when every directory
// before each step up was observed to be a real directory. A link at any
// ancestor can change where .. lands. The per-call cache bounds the extra
// reads to eight, including failed reads; an unanswered component stays
// unknown. Windows reparse points require a separate proof and are not
// collapsed here.
type plainStepUpProof struct {
	checked map[string]bool
	reads   int
}

func (p *plainStepUpProof) promote(e *effects.Effect, flavor effects.Flavor) {
	if e == nil || flavor != effects.FlavorPOSIX || hostGOOS == "windows" ||
		e.TargetState != effects.TargetStateUnknown || e.Target.Type != effects.TargetPath ||
		e.Target.Path != "" || e.Target.Glob != "" || e.Target.Lexical == "" ||
		!soleNoncanonicalTargetReason(e.Reasons) {
		return
	}
	placed, ok := p.place(e.Target.Lexical)
	if !ok {
		return
	}
	e.Target.Path = placed
	e.Target.Lexical = ""
	e.TargetState = effects.TargetStateKnown
	reasons := e.Reasons[:0]
	for _, reason := range e.Reasons {
		if reason.Scope != effects.ScopeTarget || reason.Code != effects.ReasonNonCanonicalPath {
			reasons = append(reasons, reason)
		}
	}
	e.Reasons = reasons
}

func soleNoncanonicalTargetReason(reasons []effects.Reason) bool {
	found := false
	for _, reason := range reasons {
		if reason.Scope != effects.ScopeTarget {
			continue
		}
		if reason.Code != effects.ReasonNonCanonicalPath {
			return false
		}
		found = true
	}
	return found
}

func (p *plainStepUpProof) place(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "/") || strings.Contains(raw, "//") ||
		strings.Contains(raw, "/./") || strings.HasSuffix(raw, "/.") {
		return "", false
	}
	if p.checked == nil {
		p.checked = make(map[string]bool)
	}
	segments := strings.Split(strings.TrimPrefix(raw, "/"), "/")
	stack := make([]string, 0, len(segments))
	sawStepUp := false
	for _, segment := range segments {
		switch segment {
		case "", ".":
			return "", false
		case "..":
			if len(stack) == 0 {
				return "", false
			}
			prefix := ""
			for _, part := range stack {
				prefix += "/" + part
				if known, seen := p.checked[prefix]; seen {
					if !known {
						return "", false
					}
					continue
				}
				if p.reads >= 8 {
					return "", false
				}
				info, err := os.Lstat(prefix)
				p.reads++
				plain := err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
				p.checked[prefix] = plain
				if !plain {
					return "", false
				}
			}
			stack = stack[:len(stack)-1]
			sawStepUp = true
		default:
			stack = append(stack, segment)
		}
	}
	if !sawStepUp {
		return "", false
	}
	placed := "/" + strings.Join(stack, "/")
	return placed, CanonicalAbsolute(placed, effects.FlavorPOSIX)
}
