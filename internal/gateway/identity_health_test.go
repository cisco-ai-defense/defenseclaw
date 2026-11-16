// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The identity member of /health carries, per identity source, how long ago
// it last answered, and the failing and stale counts: never a key, a
// principal, a group or the lookup error.
func TestIdentityHealthSummaryHasNoIdentifiers(t *testing.T) {
	previousDir := currentIdentitySpoolDir()
	setIdentitySpoolDir(t.TempDir())
	t.Cleanup(func() { setIdentitySpoolDir(previousDir) })
	now := time.Unix(1_800_000_000, 0)
	cache := newIdentityDirectoryCache(func(key string) (useridentity.DirectoryFacts, error) {
		switch key {
		case "1001":
			return useridentity.DirectoryFacts{Principal: "alice@DCLAB.TEST", UPN: "alice@dclab.test", Groups: []string{"dc-ml@dclab.test"},
				Source: useridentity.SourceSSSD, Directory: useridentity.DirectoryActiveDirectory, ResolvedAt: now}, nil
		case "0":
			return useridentity.DirectoryFacts{Principal: "root", Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal, ResolvedAt: now}, nil
		}
		return useridentity.DirectoryFacts{}, errors.New(`lookup of DCLAB\bob (S-1-5-21-1-2-3-1104) failed: domain controller unreachable`)
	})
	cache.logf = nil
	clock := now
	cache.now = func() time.Time { return clock }
	for _, key := range []string{"1001", "0", "1002"} {
		cache.get(key, true)
	}
	clock = now.Add(42 * time.Second)
	summary := identityHealthSummary(cache.health(), cache.answeredSources(), clock)
	body, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"failing":1,"sources":[{"directory":"local","last_ok_age_seconds":42,"source":"nss_files"},` +
		`{"directory":"active_directory","last_ok_age_seconds":42,"source":"sssd"}],"stale":0}`
	if string(body) != want {
		t.Fatalf("identity = %s\nwant      %s", body, want)
	}
	for _, leak := range []string{"1001", "1002", "alice", "bob", "dclab", "S-1-5", `\`, "@", "unreachable"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("identity names %q: %s", leak, body)
		}
	}
}

// The cache keeps at most identitySourcesMax pairs, dropping the one that
// answered longest ago, and only source tokens and known directories.
func TestIdentityHealthSourcesAreBounded(t *testing.T) {
	cache := newIdentityCache(func(string) (useridentity.DirectoryFacts, error) { return useridentity.DirectoryFacts{}, nil })
	cache.describe = func(facts useridentity.DirectoryFacts) (string, string) { return facts.Source, string(facts.Directory) }
	now := time.Unix(1_800_000_000, 0)
	for i := range identitySourcesMax + 3 {
		cache.noteAnsweredLocked(useridentity.DirectoryFacts{Source: fmt.Sprintf("source_%02d", i), Directory: useridentity.DirectoryLDAP}, now.Add(time.Duration(i)*time.Second))
	}
	cache.noteAnsweredLocked(useridentity.DirectoryFacts{Source: "Bad Source", Directory: useridentity.DirectoryLocal}, now)
	cache.noteAnsweredLocked(useridentity.DirectoryFacts{Source: "winbind", Directory: "DCLAB"}, now.Add(time.Hour))
	answers := cache.answeredSources()
	if len(answers) != identitySourcesMax {
		t.Fatalf("answers = %+v", answers)
	}
	for _, answer := range answers {
		if answer.source == "source_00" || answer.source == "Bad Source" {
			t.Fatalf("kept %q: %+v", answer.source, answers)
		}
		if answer.source == "winbind" && answer.directory != "" {
			t.Fatalf("an unknown directory is named: %+v", answer)
		}
	}
	// A cache without describe (the session cache) records nothing.
	plain := newIdentityCache(func(string) (useridentity.DirectoryFacts, error) { return useridentity.DirectoryFacts{}, nil })
	plain.noteAnsweredLocked(useridentity.DirectoryFacts{Source: "sssd"}, now)
	if len(plain.answeredSources()) != 0 {
		t.Fatal("a cache without describe recorded a source")
	}
	var none *identityDirectoryCache
	if none.answeredSources() != nil {
		t.Fatal("nil cache answered")
	}
	if summary := identityHealthSummary(identityCacheHealth{}, nil, now); fmt.Sprint(summary["sources"]) != "[]" || summary["failing"] != 0 {
		t.Fatalf("idle summary = %v", summary)
	}
}
