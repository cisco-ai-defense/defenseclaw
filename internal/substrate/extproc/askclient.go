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

package extproc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
)

// AskPath is the gateway's callout ask route on the admin listener: the
// callout raises an ask there with its service token, and the gateway
// applies the actor's registration (its person, unattended or not, the
// profile's unattended_asks) before the ask reaches the leader's store.
const AskPath = "/api/v1/substrate/callout/ask"

// askPoll is how often a held request reads its ask again.
const askPoll = 250 * time.Millisecond

// AskClient implements AskSink against the gateway's callout ask route.
// It raises the ask (the gateway finds an open one for the same actor and
// host), then reads it again until it is decided or the hold ends; a
// pending ask at the end of the hold is AskPending.
type AskClient struct {
	url       string
	tokenFile string
	http      *http.Client
	poll      time.Duration
}

// NewAskClient builds the client from judge.url when it names the
// gateway's callout verdict route: the ask route is on the same admin
// listener, with the same token and CA (the chart's layout). Otherwise nil,
// and an ask-required host is refused (D12).
func NewAskClient(cfg *Config) (*AskClient, error) {
	if cfg == nil {
		return nil, nil
	}
	base, ok := strings.CutSuffix(strings.TrimSpace(cfg.Judge.URL), calloutapi.Path)
	if !ok || (!strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://")) {
		return nil, nil
	}
	u := base + AskPath
	tr, err := calloutTransport(cfg.Judge.CAFile)
	if err != nil {
		return nil, err
	}
	return &AskClient{url: u, tokenFile: cfg.Judge.TokenFile, http: &http.Client{Transport: tr}, poll: askPoll}, nil
}

type askWire struct {
	Actor struct {
		Atespace string `json:"atespace"`
		Name     string `json:"name"`
		UID      string `json:"uid,omitempty"`
	} `json:"actor"`
	Host    string `json:"host"`
	Summary string `json:"summary,omitempty"`
	Reason  string `json:"reason,omitempty"`
	AskID   string `json:"ask_id,omitempty"`
}

type askAnswer struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

// Ask implements AskSink.
func (c *AskClient) Ask(ctx context.Context, req AskRequest) (AskResult, error) {
	var in askWire
	in.Actor.Atespace, in.Actor.Name, in.Actor.UID = req.Actor.Atespace, req.Actor.Name, req.Actor.UID
	in.Host = req.Host
	in.Summary = strings.TrimSpace(req.Method + " " + req.Host)
	if req.Rule != "" {
		in.Reason = "the egress policy asks first (" + req.Rule + ")"
	}
	for {
		got, err := c.post(ctx, in)
		if err != nil {
			if in.AskID != "" && ctx.Err() != nil {
				return AskResult{Outcome: AskPending, ID: in.AskID}, nil
			}
			// The gateway never answered (refused, unreachable, or still
			// dialling when the hold ended): no ask exists, so this is an
			// outage the failure mode decides, never a pending ask. %v keeps
			// a context deadline out of the chain (GAP-0168).
			return AskResult{ID: in.AskID}, fmt.Errorf("%w: %v", ErrAskUnreachable, err)
		}
		switch got.State {
		case "approved":
			return AskResult{Outcome: AskApproved, ID: got.ID}, nil
		case "denied", "expired":
			// An ask a person decided carries their note; the gateway's
			// own refusal (an unattended run, D12) has no id and a reason.
			reason := got.Note
			switch {
			case reason != "":
			case got.State == "expired":
				reason = "Nobody answered the approval this host needs in time."
			case got.ID != "":
				reason = "The owner denied the approval this host needs."
			default:
				reason = got.Reason
			}
			return AskResult{Outcome: AskDenied, ID: got.ID, Reason: reason}, nil
		case "pending":
			if got.ID == "" {
				return AskResult{}, errors.New("callout ask: a pending ask without an id")
			}
			in.AskID = got.ID
		default:
			return AskResult{}, fmt.Errorf("callout ask: unknown state %q", got.State)
		}
		select {
		case <-ctx.Done():
			return AskResult{Outcome: AskPending, ID: in.AskID}, nil
		case <-time.After(c.poll):
		}
	}
}

// ErrAskUnreachable is a callout ask the gateway did not answer.
var ErrAskUnreachable = errors.New("callout ask: the gateway did not answer")

func (c *AskClient) post(ctx context.Context, in askWire) (askAnswer, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return askAnswer{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return askAnswer{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	// The admin listener keeps the CSRF gate: a POST needs a client tag.
	req.Header.Set("X-DefenseClaw-Client", calloutapi.ClientTag)
	if c.tokenFile != "" {
		tok, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return askAnswer{}, fmt.Errorf("callout ask token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return askAnswer{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return askAnswer{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return askAnswer{}, fmt.Errorf("callout ask: HTTP %d", resp.StatusCode)
	}
	var out askAnswer
	if err := json.Unmarshal(raw, &out); err != nil {
		return askAnswer{}, fmt.Errorf("callout ask: %w", err)
	}
	return out, nil
}
