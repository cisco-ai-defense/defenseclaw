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

package sandboxcli

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func bedrockKeyAt(signed time.Time, expires string) string {
	return bedrockShortTermPrefix + base64.StdEncoding.EncodeToString([]byte("bedrock.amazonaws.com/?Action=CallWithBearerToken"+
		"&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date="+signed.UTC().Format("20060102T150405Z")+"&X-Amz-Expires="+expires+"&Version=1"))
}

func TestBedrockKeyExpiry(t *testing.T) {
	signed := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	at, ok := bedrockKeyExpiry(bedrockKeyAt(signed, "43200"))
	if !ok || !at.Equal(signed.Add(12*time.Hour)) {
		t.Fatalf("expiry = %v %t", at, ok)
	}
	for _, other := range []string{"", "ABSKexamplelongtermkey", bedrockShortTermPrefix + "!!", bedrockKeyAt(signed, "x"),
		bedrockShortTermPrefix + base64.StdEncoding.EncodeToString([]byte("no query"))} {
		if _, ok := bedrockKeyExpiry(other); ok {
			t.Errorf("%q has an expiry", other)
		}
	}
}

// #1137: a run with an expired short-term Bedrock key was named only after
// the harness retried for minutes. The run says so before it starts.
func TestExpiredBedrockKeyRefusesTheRun(t *testing.T) {
	signed := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	key := bedrockKeyAt(signed, "43200")
	if err := expiredBedrockKey(EnvBedrockToken, key, signed.Add(11*time.Hour)); err != nil {
		t.Fatalf("a key with an hour left: %v", err)
	}
	err := expiredBedrockKey(EnvBedrockToken, key, signed.Add(13*time.Hour))
	if err == nil || !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), EnvBedrockToken) || strings.Contains(err.Error(), key) {
		t.Fatalf("an expired key: %v", err)
	}
	if err := expiredBedrockKey(EnvBedrockToken, "ABSKlongterm", signed.Add(100*time.Hour)); err != nil {
		t.Fatalf("a long-term key: %v", err)
	}

	ta := newTestApp(t, "")
	ta.env[EnvBedrockToken] = key
	ta.env["AWS_REGION"] = "us-east-1"
	ta.Now = func() time.Time { return signed.Add(13 * time.Hour) }
	spec, err := ResolveHarness("claudecode")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ta.detectLLM(spec, LLMBedrock, llmFromFlag, "us-east-1", nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("a run with an expired key: %v", err)
	}
}
