// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// rel-1-0-6:GAP-0262 (dc-float2, managed RHEL rc23): a deleted account left
// MaxEntriesPerUID stopped registrations and saved "always" decisions on
// its uid, and useradd gave that uid to a new account. The new account
// resolves (it was refused "Too many sandboxes are registered for your
// account"), sees none of the earlier account's decisions, and the
// earlier account's records are gone from the store; its own records stay
// through the next resolve.
func TestSandboxNewAccountOnAReusedUIDDoesNotInheritTheEarlierAccountsState(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	const uid = 1012
	key, err := sandboxAuthorityKey(f.cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := sandboxSubjectKey(key, uid, "r106fs7a", "")
	at := time.Now().UTC().Add(-2 * time.Hour)
	regs := make([]sandboxreg.Registration, 0, sandboxreg.MaxEntriesPerUID)
	for i := range sandboxreg.MaxEntriesPerUID {
		id, err := sandboxreg.NewID()
		if err != nil {
			t.Fatal(err)
		}
		regs = append(regs, sandboxreg.Registration{
			V: sandboxreg.RecordVersion, ID: id, UID: uid, UserName: "r106fs7a", SubjectKey: oldKey,
			Connector: "claudecode", Harness: "claudecode", WorkdirMode: "copy", ProjectReal: "/home/r106fs7a/project",
			State: sandboxreg.StateStopped, CreatedAt: at, BoundAt: at, SeenAt: at,
			SandboxName: "dc-old-" + strconv.Itoa(i), SandboxID: "sbx-old-" + strconv.Itoa(i), BindingID: fmt.Sprintf("sb_%032x", i+1<<20),
		})
	}
	writeSandboxStoreFile(t, sandboxreg.RegistrationsDir(f.cfg.DataDir), uid, map[string]any{"v": 1, "registrations": regs})
	decisions := []sandboxreg.Decision{
		{V: sandboxreg.RecordVersion, ID: "dec-" + regs[0].ID[4:], Registration: regs[0].ID, Kind: sandboxrelay.DecisionEgressAllow,
			Host: "earlier-keyed.example.com", Scope: sandboxrelay.DecisionScopeAlways, Actor: sandboxreg.DecisionActor{UID: uid}, CreatedAt: at, SubjectKey: oldKey},
		{V: sandboxreg.RecordVersion, ID: "dec-" + regs[1].ID[4:], Registration: regs[1].ID, Kind: sandboxrelay.DecisionEgressAllow,
			Host: "earlier-legacy.example.com", Scope: sandboxrelay.DecisionScopeAlways, Actor: sandboxreg.DecisionActor{UID: uid}, CreatedAt: at},
	}
	writeSandboxStoreFile(t, sandboxreg.DecisionsDir(f.cfg.DataDir), uid, map[string]any{"v": 1, "decisions": decisions})

	newcomer := managedHookPeer{UID: uid, Name: "r106vs7a1"}
	f.setGroups(newcomer, "dc-sbx-contractors")
	rec := f.do(newcomer, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(), map[string]string{sandboxrelay.ConnectorHeader: "claudecode"})
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve by the account now holding the uid: %d %s", rec.Code, rec.Body.String())
	}
	var resp sandboxrelay.ResolveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if rec := f.bind(newcomer, resp.Registration.ID, 1); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	listDecisions := func() []sandboxrelay.Decision {
		t.Helper()
		rec := f.do(newcomer, http.MethodGet, sandboxrelay.PathDecisions+"?registration="+resp.Registration.ID, nil, nil)
		var listed []sandboxrelay.Decision
		if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("decisions: %d %s", rec.Code, rec.Body.String())
		}
		return listed
	}
	if got := listDecisions(); len(got) != 0 {
		t.Fatalf("the new account inherits the earlier account's decisions: %+v", got)
	}
	auth, _ := f.api.sandboxAuth()
	left, err := auth.store.List(uid)
	if err != nil || len(left) != 1 || left[0].ID != resp.Registration.ID || left[0].UserName != newcomer.Name {
		t.Fatalf("store after the resolve: %d registrations, %v", len(left), err)
	}
	if saved, _ := auth.decisions.List(uid, ""); len(saved) != 0 {
		t.Fatalf("the earlier account's decisions are still stored: %+v", saved)
	}

	if rec := f.do(newcomer, http.MethodPost, sandboxrelay.PathDecisions, sandboxrelay.DecisionRequest{
		V: 1, Registration: resp.Registration.ID, Kind: sandboxrelay.DecisionEgressAllow, Host: "own.example.com", Scope: sandboxrelay.DecisionScopeAlways,
	}, nil); rec.Code != http.StatusOK {
		t.Fatalf("save own decision: %d %s", rec.Code, rec.Body.String())
	}
	second := f.resolve(newcomer, claudeResolve())
	if left, _ := auth.store.List(uid); len(left) != 2 || second.Registration.ID == resp.Registration.ID {
		t.Fatalf("the account's own registrations must stay: %d", len(left))
	}
	saved, _ := auth.decisions.List(uid, "")
	if len(saved) != 1 || saved[0].Host != "own.example.com" || !sandboxSubjectMatches(key, sandboxreg.Registration{UserName: newcomer.Name, SubjectKey: saved[0].SubjectKey}, newcomer) {
		t.Fatalf("own decision after the second resolve: %+v", saved)
	}
	if got := listDecisions(); len(got) != 1 {
		t.Fatalf("own decision listed: %+v", got)
	}
}

func writeSandboxStoreFile(t *testing.T, dir string, uid int, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if err := safefile.Write(filepath.Join(dir, strconv.Itoa(uid)+".json"), raw); err != nil {
		t.Fatal(err)
	}
}
