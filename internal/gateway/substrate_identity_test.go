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

package gateway

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

const substrateHaikuPath = "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke-with-response-stream"

type substrateLLMSeen struct {
	path, userHdr string
	subject       VerifiedSubject
	verified      bool
	profile       *profileSubject
	profileSource string
	agentUser     string
}

// substrateLLMFixture is the actor listener over the real /llm handler and
// a stand-in proxy that records what the proxy would decide on.
func substrateLLMFixture(t *testing.T) (*substrateFixture, *substrateLLMSeen) {
	t.Helper()
	prev := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(prev) })
	dir := t.TempDir()
	for _, p := range []string{"bedrock", "anthropic"} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte("real-"+p+"-key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	seen := &substrateLLMSeen{}
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = substrateLLMSeen{path: r.URL.Path, userHdr: r.Header.Get("X-User-Id")}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		seen.subject, seen.verified = verifiedSubjectFromContext(r.Context())
		seen.profile, seen.profileSource = profileRequestSubject(r.Context())
		seen.agentUser = AgentIdentityFromContext(r.Context()).UserID
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	h, err := NewSubstrateLLMHandler(SubstrateLLMConfig{Providers: DefaultSubstrateLLMProviders(dir, "us-east-1"), Proxy: proxy})
	if err != nil {
		t.Fatal(err)
	}
	return newSubstrateFixture(t, func(c *SubstrateConfig) { c.LLM = h }), seen
}

func TestSubstrateLLMCallerIsTheVerifiedPerson(t *testing.T) {
	f, seen := substrateLLMFixture(t)
	// Identity headers the actor sends never name the caller.
	rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock"+substrateHaikuPath, "tok-alice", `{"messages":[]}`,
		"X-User-Id", "root", "X-DefenseClaw-User-Id", "root", "X-DefenseClaw-Profile", "admin", "x-defenseclaw-person", "root")
	if rec.Code != http.StatusOK {
		t.Fatalf("call %d %s", rec.Code, rec.Body)
	}
	s := seen.subject
	if !seen.verified || s.UserID != "alice" || s.Source != subjectSourceSubstrateActor || s.IDKind != substrateSubjectIDKind ||
		s.Directory.Principal != "alice@example.com" || s.Directory.Source != substrateIdentitySourceOIDC || s.Directory.ResolvedAt.IsZero() {
		t.Fatalf("subject %+v verified=%v", s, seen.verified)
	}
	if seen.userHdr != "" || seen.agentUser != "alice" {
		t.Fatalf("forged user header %q, agent user %q", seen.userHdr, seen.agentUser)
	}
	if seen.profile == nil || seen.profileSource != profileSubjectVerified || seen.profile.UserID != "alice" || seen.profile.UPN != "alice@example.com" {
		t.Fatalf("profile subject %+v %q", seen.profile, seen.profileSource)
	}
	// Bob's actor is bob, whoever the request claims to be.
	if rec := f.do(t, f.actor, http.MethodPost, "/llm/anthropic/v1/messages", "tok-bob", `{"model":"m"}`, "X-User-Id", "alice"); rec.Code != 200 ||
		seen.subject.UserID != "bob" || seen.profile.UserID != "bob" {
		t.Fatalf("bob %d %+v", rec.Code, seen.subject)
	}
}

func TestSubstrateVerifiedSubjectSources(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	person := registry.Registration{Atespace: "eng-web", Name: "a", UID: subUID1, Connector: "claudecode",
		Person: registry.Person{Kind: identity.PersonHuman, Issuer: "https://idp", Subject: "eng1", Principal: "eng1@example.com",
			Groups: []string{"dc-r102-devs", "dc-r102-nested"}}}
	id, name, src, facts, ok := substrateVerifiedSubject(person, at)
	if !ok || id != "eng1" || name != "eng1@example.com" || src != subjectSourceSubstrateActor ||
		strings.Join(facts.Groups, ",") != "dc-r102-devs,dc-r102-nested" || !facts.ResolvedAt.Equal(at) {
		t.Fatalf("person %q %q %q %+v %v", id, name, src, facts, ok)
	}
	// The groups are a copy: a later change to the registration is not seen.
	person.Person.Groups[0] = "dc-admins"
	if facts.Groups[0] != "dc-r102-devs" {
		t.Fatal("groups alias the registration")
	}
	workload := person
	workload.Person = registry.Person{Kind: identity.PersonWorkload, Issuer: "https://ci", Subject: "system:serviceaccount:t:ci-workload"}
	if _, _, src, facts, ok := substrateVerifiedSubject(workload, at); !ok || src != subjectSourceSubstrateWorkload || facts.Source != substrateIdentitySourceWorkload {
		t.Fatalf("workload %q %+v %v", src, facts, ok)
	}
	// An actor DefenseClaw did not create has no person: unverified, floor only.
	attributed := registry.Registration{Atespace: "other", Name: "x", UID: subUID2, Connector: "codex", Attributed: true}
	if _, _, _, _, ok := substrateVerifiedSubject(attributed, at); ok {
		t.Fatal("an attributed actor got a subject")
	}
	if !isSubstrateSubjectSource(subjectSourceSubstrateActor) || isSubstrateSubjectSource(subjectSourcePeerCredentials) {
		t.Fatal("source check")
	}
}

func TestSubstrateLLMEscapedPathAndBodyCap(t *testing.T) {
	f, seen := substrateLLMFixture(t)
	// Provider SDKs escape the model ID's colon.
	rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock/model/us.anthropic.claude-haiku-4-5-20251001-v1%3A0/invoke-with-response-stream", "tok-alice", `{}`)
	if rec.Code != 200 || seen.path != substrateHaikuPath {
		t.Fatalf("escaped colon %d %q", rec.Code, seen.path)
	}
	for _, p := range []string{"/llm/bedrock/model/a%2F..%2Fb/invoke", "/llm/bedrock/model/%2e%2e/invoke", "/api/v1/substrate/hook/claude%63ode", "/llm/bedrock/model/../x"} {
		if rec := f.do(t, f.actor, http.MethodPost, p, "tok-alice", `{}`); rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", p, rec.Code)
		}
	}
	// A model call may carry a long conversation (the proxy's 10 MiB cap);
	// other actor routes keep the 1 MiB API cap.
	big := `{"messages":[{"role":"user","content":"` + strings.Repeat("a", 3<<20) + `"}]}`
	if rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock"+substrateHaikuPath, "tok-alice", big); rec.Code != 200 {
		t.Fatalf("3 MiB model call %d", rec.Code)
	}
	huge := `{"x":"` + strings.Repeat("a", 11<<20) + `"}`
	if rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock"+substrateHaikuPath, "tok-alice", huge); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("11 MiB model call %d", rec.Code)
	}
	if rec := f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice", big); rec.Code < 400 {
		t.Fatalf("3 MiB hook %d", rec.Code)
	}
}
