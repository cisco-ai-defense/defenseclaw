// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netguard

import (
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestIsPrivateOrReserved(t *testing.T) {
	cases := []struct {
		ip     string
		expect bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.5", true},
		{"172.16.0.1", true},
		{"192.168.1.10", true},
		{"169.254.169.254", true},
		{"169.254.170.2", true},
		{"100.64.0.1", true},
		{"::1", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"0.0.0.0", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("parse %s", tc.ip)
		}
		got := IsPrivateOrReserved(ip)
		if got != tc.expect {
			t.Errorf("IsPrivateOrReserved(%s) = %v; want %v", tc.ip, got, tc.expect)
		}
	}
}

func TestRejectInlineCredentials(t *testing.T) {
	good, _ := url.Parse("https://api.example.com/v1/chat")
	if err := RejectInlineCredentials(good); err != nil {
		t.Errorf("good url: %v", err)
	}
	bad, _ := url.Parse("https://user:pass@api.example.com/v1/chat")
	if err := RejectInlineCredentials(bad); err == nil {
		t.Errorf("inline-cred url: want error, got nil")
	}
}

func TestScrubURL(t *testing.T) {
	cases := []struct {
		in        string
		mustHide  []string
		mustKeep  []string
	}{
		{
			in:       "https://api.openai.com/v1/chat?api_key=sk-secret&temperature=0.7",
			mustHide: []string{"sk-secret"},
			mustKeep: []string{"api.openai.com", "temperature=0.7"},
		},
		{
			in:       "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=AIzaSyDummySecret",
			mustHide: []string{"AIzaSyDummySecret"},
			mustKeep: []string{"generativelanguage.googleapis.com"},
		},
		{
			in:       "https://user:pass@webhook.example.com/route?routing_key=pd-secret-routing",
			mustHide: []string{"user", "pass", "pd-secret-routing"},
			mustKeep: []string{"webhook.example.com"},
		},
		{
			in:       "https://api.amazonaws.com/foo?X-Amz-Signature=abc123sig&X-Amz-Credential=AKIA",
			mustHide: []string{"abc123sig", "AKIA"},
			mustKeep: []string{"api.amazonaws.com"},
		},
	}
	for _, tc := range cases {
		got := ScrubURLString(tc.in)
		for _, h := range tc.mustHide {
			if strings.Contains(got, h) {
				t.Errorf("ScrubURLString(%q) = %q; leaked %q", tc.in, got, h)
			}
		}
		for _, k := range tc.mustKeep {
			if !strings.Contains(got, k) {
				t.Errorf("ScrubURLString(%q) = %q; missing %q", tc.in, got, k)
			}
		}
	}
}
