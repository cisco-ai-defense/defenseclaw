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

package sandboxcli

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// bedrockShortTermPrefix starts a short-term Amazon Bedrock API key: a
// base64 presigned request whose X-Amz-Date and X-Amz-Expires say when it
// stops working (at most 12 hours after it was made).
const bedrockShortTermPrefix = "bedrock-api-key-"

// bedrockKeyExpiry is when the short-term Bedrock API key key expires; ok is
// false for any other key (a long-term key, or one that does not read as a
// presigned request), whose expiry nothing here can tell.
func bedrockKeyExpiry(key string) (at time.Time, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(key), bedrockShortTermPrefix)
	if !found || rest == "" {
		return time.Time{}, false
	}
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err = enc.DecodeString(rest); err == nil {
			break
		}
	}
	if err != nil {
		return time.Time{}, false
	}
	signed := string(raw)
	if !strings.Contains(signed, "://") {
		signed = "https://" + signed
	}
	u, err := url.Parse(signed)
	if err != nil {
		return time.Time{}, false
	}
	q := u.Query()
	date, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if err != nil {
		return time.Time{}, false
	}
	secs, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	if err != nil || secs <= 0 {
		return time.Time{}, false
	}
	return date.Add(time.Duration(secs) * time.Second), true
}

// expiredBedrockKey is the refusal of a run whose short-term Bedrock API
// key in envName has already expired: the model API rejects every call,
// and the harness only retries for minutes before it says so (#1137).
// nil for a key that has not expired or whose expiry is unknown.
func expiredBedrockKey(envName, key string, now time.Time) error {
	at, ok := bedrockKeyExpiry(key)
	if !ok || now.Before(at) {
		return nil
	}
	return fmt.Errorf("the short-term Amazon Bedrock API key in %s expired at %s, so the model would reject every call: "+
		"put a fresh key in %s and run again", envName, at.Local().Format("2006-01-02 15:04 MST"), envName)
}
