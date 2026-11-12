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

package auth

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDeviceLogin(t *testing.T) {
	tests := []struct {
		name       string
		steps      []string
		wantErr    string
		wantSleeps []time.Duration
	}{
		{name: "pending then ok", steps: []string{"pending", "pending", "ok"}, wantSleeps: []time.Duration{5 * time.Second, 5 * time.Second, 5 * time.Second}},
		{name: "slow down adds 5s", steps: []string{"slow_down", "slow_down", "ok"}, wantSleeps: []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second}},
		{name: "declined", steps: []string{"pending", "denied"}, wantErr: "sign-in was declined"},
		{name: "expired by issuer", steps: []string{"expired"}, wantErr: "the code expired; run login again"},
		{name: "expired by deadline", steps: nil, wantErr: "the code expired; run login again"},
		{name: "other oauth error", steps: []string{"weird"}, wantErr: "sign-in failed (HTTP 400: invalid_client: client not allowed)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.steps = tc.steps
			idp.tokenOK = map[string]any{
				"access_token":  testJWT(t, "acc-marker", map[string]any{"iss": idp.issuer(), "sub": "u-1"}),
				"id_token":      testJWT(t, "id-marker", map[string]any{"iss": idp.issuer(), "sub": "u-1", "preferred_username": "alice", "groups": []string{"dc-devs", "dc-ml-team"}}),
				"refresh_token": "refresh-marker",
				"expires_in":    300,
			}
			clk := newClock()
			var out strings.Builder
			opened := ""
			tok, err := DeviceLogin(context.Background(), idp.context(), LoginOptions{
				Out: &out, HTTPClient: idp.srv.Client(), Interactive: true,
				OpenURL: func(u string) error { opened = u; return errors.New("no browser") },
				Now:     clk.Now, Sleep: clk.Sleep,
			})
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				noSecret(t, err, "devcode-marker", "acc-marker", "id-marker", "refresh-marker")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(clk.sleeps, tc.wantSleeps) {
				t.Errorf("sleeps = %v, want %v", clk.sleeps, tc.wantSleeps)
			}
			if tok.Kind != KindPerson || tok.Principal != "alice" || tok.Subject != "u-1" || tok.Issuer != idp.issuer() {
				t.Errorf("claims = %s", tok)
			}
			if !reflect.DeepEqual(tok.Groups, []string{"dc-devs", "dc-ml-team"}) {
				t.Errorf("groups = %v", tok.Groups)
			}
			if tok.RefreshToken != "refresh-marker" || !tok.Expiry.Equal(clk.Now().Add(300*time.Second)) {
				t.Errorf("refresh or expiry wrong: %s", tok)
			}
			o := out.String()
			for _, want := range []string{idp.srv.URL + "/activate?user_code=ABCD-EFGH", "ABCD-EFGH", "expires in 10 minutes"} {
				if !strings.Contains(o, want) {
					t.Errorf("output lacks %q:\n%s", want, o)
				}
			}
			if strings.Contains(o, "devcode-marker") {
				t.Error("output shows the device code")
			}
			if opened != idp.srv.URL+"/activate?user_code=ABCD-EFGH" {
				t.Errorf("opened %q", opened)
			}
			form := idp.deviceForms[0]
			if form["client_id"] != "defenseclaw-launcher" || form["scope"] != "openid profile email groups" || form["client_secret"] != "" {
				t.Errorf("device form = %v", form)
			}
		})
	}
}

func TestDeviceLoginBrowserRules(t *testing.T) {
	for _, tc := range []struct {
		name        string
		interactive bool
		noBrowser   bool
		want        bool
	}{
		{"interactive", true, false, true},
		{"no browser flag", true, true, false},
		{"not interactive", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.completeURI = false
			idp.steps = []string{"ok"}
			idp.tokenOK = map[string]any{"access_token": "opaque-acc"}
			clk := newClock()
			var out strings.Builder
			called := false
			_, err := DeviceLogin(context.Background(), idp.context(), LoginOptions{
				Out: &out, HTTPClient: idp.srv.Client(), Interactive: tc.interactive, NoBrowser: tc.noBrowser,
				OpenURL: func(string) error { called = true; return nil }, Now: clk.Now, Sleep: clk.Sleep,
			})
			if err != nil {
				t.Fatal(err)
			}
			if called != tc.want {
				t.Errorf("opener called = %v, want %v", called, tc.want)
			}
			if !strings.Contains(out.String(), "enter the code: ABCD-EFGH") {
				t.Errorf("output: %s", out.String())
			}
		})
	}
}

func TestDeviceLoginRefusals(t *testing.T) {
	t.Run("issuer mismatch", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.issuerName = "https://other.example.test/realms/r"
		_, err := DeviceLogin(context.Background(), idp.context(), LoginOptions{HTTPClient: idp.srv.Client()})
		if err == nil || !strings.Contains(err.Error(), "must match exactly") || !strings.Contains(err.Error(), "other.example.test") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trailing slash is a mismatch", func(t *testing.T) {
		idp := newFakeIdP(t)
		c := idp.context()
		c.Issuer += "/"
		_, err := DeviceLogin(context.Background(), c, LoginOptions{HTTPClient: idp.srv.Client()})
		if err == nil || !strings.Contains(err.Error(), "must match exactly") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no device endpoint", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.noDevice = true
		_, err := DeviceLogin(context.Background(), idp.context(), LoginOptions{HTTPClient: idp.srv.Client()})
		if err == nil || !strings.Contains(err.Error(), "device_authorization_endpoint") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("http issuer off loopback", func(t *testing.T) {
		c := Context{AdminURL: "https://admin.example.test", Issuer: "http://idp.example.test/realms/r", ClientID: "x"}
		_, err := DeviceLogin(context.Background(), c, LoginOptions{})
		if err == nil || !strings.Contains(err.Error(), "must use https") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		idp := newFakeIdP(t)
		ctx, cancel := context.WithCancel(context.Background())
		clk := newClock()
		n := 0
		_, err := DeviceLogin(ctx, idp.context(), LoginOptions{HTTPClient: idp.srv.Client(), Now: clk.Now,
			Sleep: func(ctx context.Context, d time.Duration) error {
				if n++; n == 2 {
					cancel()
				}
				return clk.Sleep(ctx, d)
			}})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("real sleep honours cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
}
