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

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
)

const b1CloneTemplates = `{"mode":"bindings","templates":[
	{"name":"github","hosts":["github.com","api.github.com"],"header":"Authorization","form":"basic","basic_user":"x-access-token"},
	{"name":"generic-basic","hosts":["*.corp.example"],"header":"Authorization","form":"basic"},
	{"name":"gitlab","hosts":["*.corp.example"],"header":"Authorization","form":"basic","basic_user":"oauth2"}]}`

// b1CloneAdmin is a gateway with the templates above, the person's own
// secrets mine, and an add that answers addReply; the agent's policy
// carries a new secret after inPolicyAfter tests.
type b1CloneAdmin struct {
	mu    sync.Mutex
	adds  []map[string]any
	tests int
}

func useB1CloneAdmin(t *testing.T, mine, addReply string, addCode, inPolicyAfter int) *b1CloneAdmin {
	t.Helper()
	g := &b1CloneAdmin{}
	raw := func(code int, body string) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		}
	}
	useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET secret-templates": raw(http.StatusOK, b1CloneTemplates),
		"GET secrets":          raw(http.StatusOK, mine),
		"POST secrets": func(w http.ResponseWriter, r *http.Request) {
			in := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&in)
			g.mu.Lock()
			g.adds = append(g.adds, in)
			g.mu.Unlock()
			raw(addCode, addReply)(w, r)
		},
		"POST secrets/gitlab-git-corp-example/test": func(w http.ResponseWriter, r *http.Request) {
			g.mu.Lock()
			g.tests++
			in := g.tests > inPolicyAfter
			g.mu.Unlock()
			raw(http.StatusOK, `{"name":"gitlab-git-corp-example","status":"set","agent":{"actor":"eng/a1","in_policy":`+map[bool]string{true: "true", false: "false"}[in]+`}}`)(w, r)
		},
	}})
	return g
}

func b1CloneSetup(t *testing.T, canAsk, yes bool) (*cobra.Command, *api.Client, *bytes.Buffer) {
	t.Helper()
	oldAsk, oldConfirm, oldRead, oldWait, oldPoll := substrateCloneCanAsk, substrateCloneConfirm, substrateCloneReadValue, substrateClonePolicyWait, substrateClonePolicyPoll
	t.Cleanup(func() {
		substrateCloneCanAsk, substrateCloneConfirm, substrateCloneReadValue = oldAsk, oldConfirm, oldRead
		substrateClonePolicyWait, substrateClonePolicyPoll = oldWait, oldPoll
	})
	substrateCloneCanAsk = func() bool { return canAsk }
	substrateCloneConfirm = func(*cobra.Command, string) (bool, error) { return yes, nil }
	substrateCloneReadValue = func(*cobra.Command) (string, error) { return "glpat-b1-inline", nil }
	substrateClonePolicyWait, substrateClonePolicyPoll = 2*time.Second, 10*time.Millisecond
	cmd := &cobra.Command{}
	var errb bytes.Buffer
	cmd.SetErr(&errb)
	s, err := substrateOpen(cmd, &substrateCommon{})
	if err != nil {
		t.Fatal(err)
	}
	return cmd, s.Client, &errb
}

// b1Clone is a clone that the host refuses until it ran refusals times.
func b1Clone(refusals int, calls *int) func() (*workspace.CloneResult, error) {
	return func() (*workspace.CloneResult, error) {
		*calls++
		if *calls <= refusals {
			return nil, &workspace.CloneError{URL: "https://git.corp.example/team/app.git", Exit: 128,
				Message: "fatal: Authentication failed for 'https://git.corp.example/team/app.git/'"}
		}
		return &workspace.CloneResult{Dir: "/sandbox/app"}, nil
	}
}

func TestB1CloneInlineRetryOnce(t *testing.T) {
	actor := api.Actor{Atespace: "eng", Name: "a1"}
	url := "https://git.corp.example/team/app.git"

	// On a terminal, yes: the secret is added under the covering template
	// (generic-basic is skipped: it needs a user name), the clone waits for
	// the policy and runs once more.
	g := useB1CloneAdmin(t, `{"secrets":[]}`, `{"name":"gitlab-git-corp-example","id":"b-0123456789","template":"gitlab","host":"git.corp.example","status":"set"}`, http.StatusCreated, 2)
	cmd, cl, errb := b1CloneSetup(t, true, true)
	calls := 0
	res, err := substrateCloneOnce(t.Context(), cmd, cl, actor, &substrateRunFlags{clone: url}, b1Clone(1, &calls))
	if err != nil || res == nil || calls != 2 {
		t.Fatalf("clone %v %v calls=%d stderr %q", res, err, calls, errb.String())
	}
	if len(g.adds) != 1 || g.adds[0]["template"] != "gitlab" || g.adds[0]["host"] != "git.corp.example" ||
		g.adds[0]["name"] != "gitlab-git-corp-example" || g.adds[0]["value"] != "glpat-b1-inline" {
		t.Fatalf("adds %v", g.adds)
	}
	if g.tests < 3 || !strings.Contains(errb.String(), "Cloning "+url+" in the agent again") || strings.Contains(errb.String(), "glpat-b1-inline") {
		t.Fatalf("tests=%d stderr %q", g.tests, errb.String())
	}

	// Refused again after the retry: no second retry, and the error says
	// the new secret was refused too.
	useB1CloneAdmin(t, `{"secrets":[]}`, `{"name":"gitlab-git-corp-example","id":"b-0123456789","template":"gitlab","host":"git.corp.example","status":"set"}`, http.StatusCreated, 0)
	cmd, cl, _ = b1CloneSetup(t, true, true)
	calls = 0
	_, err = substrateCloneOnce(t.Context(), cmd, cl, actor, &substrateRunFlags{clone: url}, b1Clone(5, &calls))
	if calls != 2 || err == nil || !strings.Contains(err.Error(), "refused your new secret gitlab-git-corp-example too") {
		t.Fatalf("calls=%d err %v", calls, err)
	}

	// --task, --json or no terminal: no question, no add, the hint only.
	for _, c := range []struct {
		name   string
		canAsk bool
		f      substrateRunFlags
	}{
		{"task", true, substrateRunFlags{clone: url, task: "fix"}},
		{"batch", true, substrateRunFlags{clone: url, batch: "tasks.txt"}},
		{"no terminal", false, substrateRunFlags{clone: url}},
	} {
		g = useB1CloneAdmin(t, `{"secrets":[]}`, `{}`, http.StatusCreated, 0)
		cmd, cl, _ = b1CloneSetup(t, c.canAsk, true)
		calls = 0
		_, err = substrateCloneOnce(t.Context(), cmd, cl, actor, &c.f, b1Clone(1, &calls))
		want := "git.corp.example needs a token. The gitlab template covers it: defenseclaw substrate secrets add gitlab-git-corp-example --template gitlab --host git.corp.example"
		if calls != 1 || len(g.adds) != 0 || err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: calls=%d adds=%v err %v", c.name, calls, g.adds, err)
		}
	}

	// No: the hint, nothing added.
	g = useB1CloneAdmin(t, `{"secrets":[]}`, `{}`, http.StatusCreated, 0)
	cmd, cl, _ = b1CloneSetup(t, true, false)
	calls = 0
	if _, err = substrateCloneOnce(t.Context(), cmd, cl, actor, &substrateRunFlags{clone: url}, b1Clone(1, &calls)); calls != 1 || len(g.adds) != 0 || err == nil {
		t.Fatalf("no: calls=%d adds=%v err %v", calls, g.adds, err)
	}

	// No template covers the host: the generic command an admin approves.
	g = useB1CloneAdmin(t, `{"secrets":[]}`, `{}`, http.StatusCreated, 0)
	cmd, cl, _ = b1CloneSetup(t, true, true)
	calls = 0
	_, err = substrateCloneOnce(t.Context(), cmd, cl, actor, &substrateRunFlags{clone: "https://git.other.example/a.git"}, b1Clone(1, &calls))
	if calls != 1 || len(g.adds) != 0 || err == nil ||
		!strings.Contains(err.Error(), "git.other.example needs a token: defenseclaw substrate secrets add NAME --template generic-bearer --host git.other.example (an administrator will be asked)") {
		t.Fatalf("uncovered: calls=%d err %v", calls, err)
	}

	// A secret of the person's already covers the host: no new one.
	g = useB1CloneAdmin(t, `{"secrets":[{"name":"gl-work","kind":"template","template":"gitlab","hosts":["git.corp.example"],"status":"set","mine":true}]}`, `{}`, http.StatusCreated, 0)
	cmd, cl, _ = b1CloneSetup(t, true, true)
	calls = 0
	_, err = substrateCloneOnce(t.Context(), cmd, cl, actor, &substrateRunFlags{clone: url}, b1Clone(1, &calls))
	if calls != 1 || len(g.adds) != 0 || err == nil || !strings.Contains(err.Error(), "refused your secret gl-work; store the right token with: defenseclaw substrate secrets set gl-work") {
		t.Fatalf("own: calls=%d err %v", calls, err)
	}

	// The add waits on an administrator: no retry.
	g = useB1CloneAdmin(t, `{"secrets":[]}`, `{"name":"gitlab-git-corp-example","id":"b-0123456789","template":"gitlab","host":"git.corp.example","status":"waiting on admin","reason":"secret_binding_outside_templates"}`, http.StatusAccepted, 0)
	cmd, cl, _ = b1CloneSetup(t, true, true)
	calls = 0
	_, err = substrateCloneOnce(t.Context(), cmd, cl, actor, &substrateRunFlags{clone: url}, b1Clone(1, &calls))
	if calls != 1 || len(g.adds) != 1 || err == nil || !strings.Contains(err.Error(), "waits on an administrator") {
		t.Fatalf("waiting: calls=%d err %v", calls, err)
	}

	// Not a credential refusal: no question at all.
	g = useB1CloneAdmin(t, `{"secrets":[]}`, `{}`, http.StatusCreated, 0)
	cmd, cl, _ = b1CloneSetup(t, true, true)
	_, err = substrateCloneOnce(t.Context(), cmd, cl, actor, &substrateRunFlags{clone: url}, func() (*workspace.CloneResult, error) {
		return nil, &workspace.CloneError{URL: url, Message: "fatal: could not resolve host: git.corp.example"}
	})
	var ce *workspace.CloneError
	if !errors.As(err, &ce) || ce.Hint != "" || len(g.adds) != 0 {
		t.Fatalf("not a credential refusal: %v %v", err, g.adds)
	}
}

func TestB1CloneSecretName(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"gitlab", "git.corp.example"}:      "gitlab-git-corp-example",
		{"github", "github.com"}:            "github-github-com",
		{"My_T", "a..b"}:                    "my-t-a-b",
		{"gitlab", strings.Repeat("a", 80)}: "gitlab-" + strings.Repeat("a", 56),
	} {
		got := substrateCloneSecretName(in[0], in[1])
		if got != want || !substrateBindingNameRE.MatchString(got) {
			t.Errorf("%v: %q, want %q", in, got, want)
		}
	}
}
