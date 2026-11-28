// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "sort"

// Result is the full effect projection of one tool call.
type Result struct {
	Surface Surface  `json:"surface"`
	Dialect Dialect  `json:"dialect"`
	Flavor  Flavor   `json:"flavor"`
	Effects []Effect `json:"effects"`
	// Unknowns are structure-level reasons the whole projection is not fully
	// trusted (a construct the frontend could not place, a limit hit). They are
	// in addition to any per-effect reasons.
	Unknowns []Reason `json:"unknowns,omitempty"`
}

// Effect is one typed effect of a call.
type Effect struct {
	Kind        Kind        `json:"kind"`
	Target      Target      `json:"target"`
	TargetState TargetState `json:"target_state"`
	RoleState   RoleState   `json:"role_state"`
	// Reasons is non-empty whenever TargetState or RoleState is not "known", or
	// Kind is opaque. Ordered by reasonPrecedence.
	Reasons []Reason `json:"reasons,omitempty"`
	Data    *Data    `json:"data,omitempty"`
	Origin  Origin   `json:"origin"`
	// Cond is true when this effect runs only on some execution paths (an
	// if/case/loop/function body, a || alternative, after an unresolved cd).
	Cond bool `json:"cond,omitempty"`
	// LinkTarget marks a KindLink effect that names the path a link points
	// at (ln -s TARGET LINK, mklink LINK TARGET, New-Item -Target), not the
	// path the link is placed at: the file itself is not changed, it gets a
	// new name the call may later write or read through.
	LinkTarget bool `json:"link_target,omitempty"`
	// Shown marks a read whose bytes reach the call's own output, what the
	// agent is shown: the last stage that carries them prints them on a
	// stdout the call neither redirects nor captures in a substitution, and no
	// program on the way prints only a count, a test or a digest (DET111
	// GAP-1846: an own credential read raises only when its content flows).
	Shown bool `json:"shown,omitempty"`
}

// Target is what an effect acts on.
type Target struct {
	Type     TargetType `json:"type"`
	Spelling string     `json:"spelling,omitempty"`
	// Path is the lexically resolved absolute path (cwd/~/$HOME/known env
	// applied under Flavor rules). Empty when the target is not a path or could
	// not be placed.
	Path string `json:"path,omitempty"`
	// Glob holds the unquoted glob pattern when the operand is a pattern; Path
	// is then empty and a glob reason is present.
	Glob string `json:"glob,omitempty"`
	// Lexical is the lexical candidate of a spelling that is not canonical
	// (a .. after a component that may be a link, an 8.3-looking name, a //):
	// the absolute path the spelling names before any link or short name is
	// resolved, with nothing collapsed. The target stays unknown (F1): only the
	// resolver may turn it into a physical path, and the protected-set
	// classifier reads it as a pattern otherwise (DET111 D3).
	Lexical string `json:"lexical,omitempty"`
	// Network fields.
	URL    string `json:"url,omitempty"`
	Scheme string `json:"scheme,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	Scope  string `json:"scope,omitempty"`
	// Physical and Link are filled only by the resolver step (package fsres).
	Physical string    `json:"physical,omitempty"`
	Link     LinkState `json:"link"`
	// Subtree: the effect covers every file below Path, not Path alone (a git
	// clone or init into a directory). A matcher that compares exact files must
	// treat a protected path below Path as hit.
	Subtree  bool   `json:"subtree,omitempty"`
	Flavor   Flavor `json:"flavor,omitempty"`
	CaseFold bool   `json:"-"`
}

// Data is what an effect carries: the bytes a write lays down, the file an
// upload sends, the code an exec runs. It is never a path operand of the call.
type Data struct {
	Kind DataKind `json:"kind"`
	// Sources are the producers of this data, in order. An empty list means the
	// data is a literal or argument with no upstream producer.
	Sources []Source `json:"sources,omitempty"`
	Bytes   int      `json:"bytes,omitempty"`
	// Text is bounded in-process content (write body, decoded code; for a
	// piped write or send, the literal an upstream echo/printf fed it, before
	// any transform). It is excluded from JSON so the harness never logs call
	// content.
	Text string `json:"-"`
}

// Source is one producer of an effect's data (review R6). Effect is a 1-based
// index into Result.Effects; 0 means "none" so the zero value is unambiguous.
type Source struct {
	Kind     SourceKind `json:"kind"`
	Effect   int        `json:"effect,omitempty"`
	Path     string     `json:"path,omitempty"`
	Variable string     `json:"variable,omitempty"`
}

// Origin records which command produced an effect.
type Origin struct {
	Surface  Surface  `json:"surface"`
	Dialect  Dialect  `json:"dialect"`
	Command  int      `json:"command"`
	Program  string   `json:"program,omitempty"`
	Wrappers []string `json:"wrappers,omitempty"`
	Depth    int      `json:"depth,omitempty"`
	Span     [2]int   `json:"span,omitempty"`
}

// addReason adds a reason if not already present and keeps precedence order.
func (e *Effect) addReason(code ReasonCode, scope ReasonScope) {
	for _, r := range e.Reasons {
		if r.Code == code && r.Scope == scope {
			return
		}
	}
	e.Reasons = append(e.Reasons, Reason{Code: code, Scope: scope})
	sort.SliceStable(e.Reasons, func(i, j int) bool {
		return reasonPrecedence[e.Reasons[i].Code] < reasonPrecedence[e.Reasons[j].Code]
	})
	// A reason always demotes the matching state unless it is already lower.
	switch scope {
	case ScopeTarget:
		e.TargetState = TargetStateUnknown
	case ScopeRole:
		if e.RoleState == RoleStateKnown {
			e.RoleState = RoleStateUnknown
		}
	}
}

func (r *Result) addUnknown(code ReasonCode) {
	for _, u := range r.Unknowns {
		if u.Code == code {
			return
		}
	}
	r.Unknowns = append(r.Unknowns, Reason{Code: code, Scope: ScopeStructure})
	sort.SliceStable(r.Unknowns, func(i, j int) bool {
		return reasonPrecedence[r.Unknowns[i].Code] < reasonPrecedence[r.Unknowns[j].Code]
	})
}

// FullyKnown reports whether every effect has a known target and a known role
// and no structure-level unknowns. The shadow harness measures this share.
func (r Result) FullyKnown() bool {
	if len(r.Unknowns) > 0 {
		return false
	}
	// A call that produced no effect at all is not "fully known": we modeled
	// nothing about it (review HN-1). Every executable command emits at least a
	// base exec, so this only excludes genuinely empty / dropped calls.
	if len(r.Effects) == 0 {
		return false
	}
	for _, e := range r.Effects {
		if e.Kind == KindOpaque || e.TargetState != TargetStateKnown || e.RoleState != RoleStateKnown {
			return false
		}
	}
	return true
}
