// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

// defaultDistributionFlavor is the flavor tag every managed-enterprise
// artefact (manifest.json, payload-metadata.json, provenance.json)
// carries by default. Named as a package-level const so a change to
// this string flows through every emitter in one edit — the previous
// per-file literals let manifest.json and provenance.json drift out of
// sync (spec 002 CR — "The unsigned flavor rule is duplicated in two
// emitters").
const defaultDistributionFlavor = "managed-enterprise"

// unsignedDistributionFlavorSuffix is the string appended to the
// default flavor when the caller passes --unsigned. This is the marker
// the runtime + release-engineering pipeline greps for to refuse
// non-disposable-scope installs; see spec 002 REQ-16.
const unsignedDistributionFlavorSuffix = "-unsigned"

// resolveDistributionFlavor is the single source of truth for how
// `--distribution-flavor` interacts with `--unsigned`. Behaviour:
//
//   - If the caller passed no --distribution-flavor (explicitFlavor
//     is false) AND --unsigned is set, append the unsigned suffix so
//     an unsigned developer build cannot be confused with a release
//     artefact.
//
//   - If the caller explicitly passed --distribution-flavor (regardless
//     of value — including the coincidentally-default "managed-enterprise"),
//     trust them: return it verbatim. Downstream test harnesses use
//     this to shape flavor strings that already carry markers of
//     their own; earlier revisions inferred "explicit" from
//     "value != default" and mis-suffixed
//     `--distribution-flavor managed-enterprise --unsigned` (CR
//     spec-002:PRRT_kwDORuAK-s6ahAB9).
//
// emit-manifest and emit-provenance both call this — same rule, same
// bytes, no drift. Callers detect explicitFlavor via FlagSet.Visit
// after Parse (see emit_manifest.go and emit_provenance.go).
func resolveDistributionFlavor(flavor string, unsigned, explicitFlavor bool) string {
	if unsigned && !explicitFlavor {
		return defaultDistributionFlavor + unsignedDistributionFlavorSuffix
	}
	return flavor
}
