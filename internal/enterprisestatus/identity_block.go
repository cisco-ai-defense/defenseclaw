// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// States of an IdentityHealth.
const (
	IdentityStateOK      = "ok"
	IdentityStateFailing = "failing"
	IdentityStateIdle    = "idle"
	IdentityStateUnknown = "unknown"
)

// Reason codes of an unknown IdentityHealth.
const (
	CodeGatewayNotReady      = "gateway_not_ready"
	CodeGatewayDidNotReport  = "gateway_did_not_report"
	identitySourcesMax       = 8
	identitySourceMaxSeconds = 1 << 40
)

var identitySourcePattern = lazyregexp.New(`^[a-z][a-z0-9_]{0,31}$`)

// identityDirectories are the useridentity.Directory values a source may
// name.
var identityDirectories = map[string]bool{
	string(useridentity.DirectoryLocal): true, string(useridentity.DirectoryLDAP): true,
	string(useridentity.DirectoryActiveDirectory): true, string(useridentity.DirectoryEntraID): true,
	string(useridentity.DirectoryOkta): true, string(useridentity.DirectoryOther): true,
}

// IdentityHealth is the identity block: how the gateway's directory lookups
// fare, from the identity member of its /health. Tokens, counts and ages
// only; the failing accounts and the lookup error (which can name one) are
// never copied.
type IdentityHealth struct {
	// State is ok, failing (FailingAccounts > 0), idle (no lookup has
	// succeeded since the gateway started) or unknown (ReasonCode says why).
	State string `json:"state"`
	// Sources are the (source, directory) pairs that answered a lookup since
	// the gateway started, sorted by source.
	Sources []IdentitySource `json:"sources,omitempty"`
	// FailingAccounts counts accounts whose latest lookup failed within the
	// cache lifetime; StaleAccounts those of them still served facts past
	// it. Absent when unknown.
	FailingAccounts *int `json:"failing_accounts,omitempty"`
	StaleAccounts   *int `json:"stale_accounts,omitempty"`
	// ServingOfflineCache: StaleAccounts > 0, so DefenseClaw serves
	// directory facts past their 15-minute lifetime because their refresh
	// fails (they are dropped at 60 minutes). Absent when unknown.
	ServingOfflineCache *bool `json:"serving_offline_cache,omitempty"`
	// ReasonCode is gateway_not_ready or gateway_did_not_report for an
	// unknown state; absent otherwise.
	ReasonCode string `json:"reason_code,omitempty"`
}

// IdentitySource is one identity source that answered: the
// defenseclaw.user.identity.source token (useridentity.Source*), the
// directory that owns the accounts it answered for, and how long ago it last
// answered on the gateway clock.
type IdentitySource struct {
	Source           string `json:"source"`
	Directory        string `json:"directory,omitempty"`
	LastOKAgeSeconds int64  `json:"last_ok_age_seconds"`
}

// IdentityGatewayNotReady is the block while the gateway is not ready.
func IdentityGatewayNotReady() *IdentityHealth {
	return &IdentityHealth{State: IdentityStateUnknown, ReasonCode: CodeGatewayNotReady}
}

// ParseIdentityHealth reads the identity member of a gateway /health body. A
// body without it (a gateway older than this build, during an upgrade) or
// with a malformed one is unknown with gateway_did_not_report: never a
// warning or an error.
func ParseIdentityHealth(body []byte) *IdentityHealth {
	var health struct {
		Identity *struct {
			Sources []struct {
				Source           string `json:"source"`
				Directory        string `json:"directory"`
				LastOKAgeSeconds *int64 `json:"last_ok_age_seconds"`
			} `json:"sources"`
			Failing *int `json:"failing"`
			Stale   *int `json:"stale"`
		} `json:"identity"`
	}
	if json.Unmarshal(body, &health) != nil || health.Identity == nil ||
		health.Identity.Failing == nil || health.Identity.Stale == nil ||
		*health.Identity.Failing < 0 || *health.Identity.Stale < 0 {
		return &IdentityHealth{State: IdentityStateUnknown, ReasonCode: CodeGatewayDidNotReport}
	}
	in := health.Identity
	out := &IdentityHealth{}
	for _, source := range in.Sources {
		age := source.LastOKAgeSeconds
		if !identitySourcePattern.MatchString(source.Source) || age == nil || *age < 0 || *age > identitySourceMaxSeconds {
			continue
		}
		directory := source.Directory
		if !identityDirectories[directory] {
			directory = ""
		}
		out.Sources = append(out.Sources, IdentitySource{Source: source.Source, Directory: directory, LastOKAgeSeconds: *age})
	}
	sort.Slice(out.Sources, func(i, j int) bool {
		if out.Sources[i].Source != out.Sources[j].Source {
			return out.Sources[i].Source < out.Sources[j].Source
		}
		return out.Sources[i].Directory < out.Sources[j].Directory
	})
	if len(out.Sources) > identitySourcesMax {
		out.Sources = out.Sources[:identitySourcesMax]
	}
	failing, stale := *in.Failing, *in.Stale
	offline := stale > 0
	out.FailingAccounts, out.StaleAccounts, out.ServingOfflineCache = &failing, &stale, &offline
	switch {
	case failing > 0:
		out.State = IdentityStateFailing
	case len(out.Sources) == 0:
		out.State = IdentityStateIdle
	default:
		out.State = IdentityStateOK
	}
	return out
}
