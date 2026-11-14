//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// windowsSIDPersonAccount reports whether a S-1-5-21 SID names a person:
// the account lookup says SidTypeUser and the name does not end in $ (a
// computer account, a managed or group managed service account). known is
// false when the lookup fails (a domain controller out of reach): the
// ledger enrollment then decides. Answers are cached (SIDs are never
// reused); a failed lookup is retried after a minute. Replaceable in tests.
var windowsSIDPersonAccount = func(sid string) (person, known bool) {
	now := time.Now()
	if v, ok := windowsSIDKindCache.Load(sid); ok {
		entry := v.(windowsSIDKind)
		if entry.known || now.Before(entry.retryAt) {
			return entry.person, entry.known
		}
	}
	entry := windowsSIDKind{retryAt: now.Add(time.Minute)}
	if s, err := windows.StringToSid(sid); err == nil {
		if account, _, use, err := s.LookupAccount(""); err == nil {
			entry.known = true
			entry.person = use == windows.SidTypeUser && !strings.HasSuffix(strings.TrimSpace(account), "$")
		}
	}
	windowsSIDKindCache.Store(sid, entry)
	return entry.person, entry.known
}

type windowsSIDKind struct {
	person, known bool
	retryAt       time.Time
}

var windowsSIDKindCache sync.Map
