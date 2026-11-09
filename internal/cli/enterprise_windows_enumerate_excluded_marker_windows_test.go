// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0979: each enumeration cycle hands the machine-wide hook the SIDs it
// judged excluded, and an empty cycle hands it none, so an account taken off
// exclude_users is governed again; a failed publish is logged, not fatal.
func TestEnumerationCyclePublishesTheExcludedAccountMarkers(t *testing.T) {
	previous := enterpriseWindowsExcludedAccountMarkerPublisher
	t.Cleanup(func() { enterpriseWindowsExcludedAccountMarkerPublisher = previous })
	var got [][]string
	var failure error
	enterpriseWindowsExcludedAccountMarkerPublisher = func(sids []string) error {
		got = append(got, sids)
		return failure
	}
	var stderr bytes.Buffer
	publishEnterpriseWindowsExcludedAccountMarkers(&stderr, []enterprisehooks.ManifestTarget{
		{SID: "S-1-5-21-1-2-3-1001"}, {SID: "S-1-5-21-1-2-3-1002"},
	})
	publishEnterpriseWindowsExcludedAccountMarkers(&stderr, nil)
	want := [][]string{{"S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"}, {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("published %v, want %v", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("a clean publish logged %q", stderr.String())
	}
	failure = errors.New("access is denied")
	publishEnterpriseWindowsExcludedAccountMarkers(&stderr, nil)
	if !strings.Contains(stderr.String(), "could not publish the excluded-account markers") {
		t.Fatalf("a failed publish was not logged: %q", stderr.String())
	}
}
