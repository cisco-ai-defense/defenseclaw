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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

type fakeBundles struct {
	stage     string
	atespaces []string
	archive   []byte
	err       error
}

func (f *fakeBundles) Apply(_ context.Context, archive []byte, stage string, atespaces []string) (any, error) {
	f.archive, f.stage, f.atespaces = archive, stage, atespaces
	return map[string]any{"result": "applied", "stage": stage}, f.err
}

func (f *fakeBundles) Rollback(_ context.Context, stage string) (any, error) {
	f.stage = stage
	return map[string]any{"result": "rolled_back"}, f.err
}

func (f *fakeBundles) Status(context.Context) (any, error) {
	return map[string]any{"stages": map[string]any{}}, f.err
}

func bundleRequest(method, path, body string, admin bool) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	return r.WithContext(withSubstratePerson(r.Context(), identity.Person{Subject: "s"}, admin))
}

func TestSubstrateBundleRoutes(t *testing.T) {
	a := &APIServer{}
	fb := &fakeBundles{}
	st := &substrateState{cfg: SubstrateConfig{Bundles: fb}}
	apply := `{"name":"v3.dcbundle","bundle":"c2lnbmVk","atespaces":["team-b","team-a"]}`

	w := httptest.NewRecorder()
	a.substrateBundleApply(st)(w, bundleRequest(http.MethodPost, "/api/v1/substrate/bundle", apply, false))
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin apply: %d", w.Code)
	}
	w = httptest.NewRecorder()
	a.substrateBundleStatus(st)(w, bundleRequest(http.MethodGet, "/api/v1/substrate/bundle/status", "", false))
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin status: %d (status is admin-only)", w.Code)
	}

	w = httptest.NewRecorder()
	a.substrateBundleApply(st)(w, bundleRequest(http.MethodPost, "/api/v1/substrate/bundle", apply, true))
	if w.Code != http.StatusOK || string(fb.archive) != "signed" || !strings.HasPrefix(fb.stage, "s-") {
		t.Fatalf("apply: %d %q stage %q", w.Code, fb.archive, fb.stage)
	}
	derived := fb.stage
	// The same atespace set in another order lands in the same stage.
	w = httptest.NewRecorder()
	a.substrateBundleApply(st)(w, bundleRequest(http.MethodPost, "/api/v1/substrate/bundle", `{"bundle":"c2lnbmVk","atespaces":["team-a","team-b"]}`, true))
	if fb.stage != derived {
		t.Fatalf("stage %q, want %q", fb.stage, derived)
	}
	for body, want := range map[string]string{
		`{"bundle":"c2lnbmVk"}`:                  "all",
		`{"bundle":"c2lnbmVk","stage":"canary"}`: "canary",
	} {
		a.substrateBundleApply(st)(httptest.NewRecorder(), bundleRequest(http.MethodPost, "/api/v1/substrate/bundle", body, true))
		if fb.stage != want {
			t.Errorf("%s: stage %q, want %q", body, fb.stage, want)
		}
	}
	for _, body := range []string{`{}`, `{"bundle":"c2lnbmVk","extra":1}`, `not json`} {
		w = httptest.NewRecorder()
		a.substrateBundleApply(st)(w, bundleRequest(http.MethodPost, "/api/v1/substrate/bundle", body, true))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, w.Code)
		}
	}

	fb.err = &enterprisebundle.Error{Code: enterprisebundle.CodeSignatureInvalid, Detail: "bad"}
	w = httptest.NewRecorder()
	a.substrateBundleApply(st)(w, bundleRequest(http.MethodPost, "/api/v1/substrate/bundle", apply, true))
	var refused struct {
		Reason  string         `json:"reason"`
		Receipt map[string]any `json:"receipt"`
	}
	if w.Code != http.StatusUnprocessableEntity || json.Unmarshal(w.Body.Bytes(), &refused) != nil ||
		refused.Reason != "signature_invalid" || refused.Receipt["result"] == nil {
		t.Fatalf("refused: %d %s", w.Code, w.Body)
	}
	fb.err = errors.New("kubernetes API 500")
	w = httptest.NewRecorder()
	a.substrateBundleRollback(st)(w, bundleRequest(http.MethodPost, "/api/v1/substrate/bundle/rollback", `{"stage":"canary"}`, true))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "500") {
		t.Fatalf("storage error: %d %s", w.Code, w.Body)
	}
	fb.err = nil
	w = httptest.NewRecorder()
	a.substrateBundleRollback(st)(w, bundleRequest(http.MethodPost, "/api/v1/substrate/bundle/rollback", `{"stage":""}`, true))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("rollback without a stage: %d", w.Code)
	}

	off := &substrateState{}
	w = httptest.NewRecorder()
	a.substrateBundleStatus(off)(w, bundleRequest(http.MethodGet, "/api/v1/substrate/bundle/status", "", true))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("bundles off: %d", w.Code)
	}
}
