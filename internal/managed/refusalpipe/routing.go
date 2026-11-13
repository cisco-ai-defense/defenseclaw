// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package refusalpipe

import (
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// The routing read on the own-status pipe: a standard account of a Windows
// standalone managed computer reads its own routing decisions and budgets,
// as the managed hook socket answers on Linux and macOS. Reads only: the
// routing dry run (POST) is not offered here.
const (
	// MaxRoutingRequestBytes bounds one routing request.
	MaxRoutingRequestBytes = 512
	// MaxRoutingAnswerBytes bounds one routing answer.
	MaxRoutingAnswerBytes = 256 << 10
	routingRequestKind    = "routing"
	routingPathPrefix     = "/api/v1/routing/"
)

type routingRequest struct {
	Request string `json:"request"`
	Path    string `json:"path"`
}

// ValidRoutingReadPath reports whether path (with its query) is a routing
// read the pipe serves: effective, budgets or explain/<id>.
func ValidRoutingReadPath(path string) bool {
	if len(path) > MaxRoutingRequestBytes-64 {
		return false
	}
	u, err := url.Parse(path)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, routingPathPrefix) {
		return false
	}
	rest := strings.TrimPrefix(u.Path, routingPathPrefix)
	switch {
	case rest == "effective":
		for key, values := range u.Query() {
			if key != "recent" || len(values) != 1 {
				return false
			}
			if n, err := strconv.Atoi(values[0]); err != nil || n < 0 || n > 1000 {
				return false
			}
		}
		return true
	case rest == "budgets":
		return u.RawQuery == ""
	case strings.HasPrefix(rest, "explain/"):
		id := strings.TrimPrefix(rest, "explain/")
		return u.RawQuery == "" && id != "" && id != "." && id != ".." && !strings.ContainsAny(id, "/\\%")
	}
	return false
}

// RoutingRequest is the pipe message of a routing read.
func RoutingRequest(path string) ([]byte, error) {
	if !ValidRoutingReadPath(path) {
		return nil, errors.New("not a routing read: use effective, budgets or explain/<id>")
	}
	return json.Marshal(routingRequest{Request: routingRequestKind, Path: path})
}

// ParseRoutingRequest returns the path of a routing request message.
func ParseRoutingRequest(message []byte) (string, bool) {
	var r routingRequest
	if len(message) > MaxRoutingRequestBytes || json.Unmarshal(message, &r) != nil || r.Request != routingRequestKind || !ValidRoutingReadPath(r.Path) {
		return "", false
	}
	return r.Path, true
}

// RoutingAnswer is the pipe answer of a routing read: the HTTP status and
// the JSON body the gateway's routing API gave the caller.
type RoutingAnswer struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// EncodeRoutingAnswer encodes an answer; a body that is not JSON becomes {}.
func EncodeRoutingAnswer(status int, body []byte) []byte {
	if !json.Valid(body) {
		body = []byte("{}")
	}
	out, _ := json.Marshal(RoutingAnswer{Status: status, Body: body})
	return out
}

// ParseRoutingAnswer decodes an answer.
func ParseRoutingAnswer(answer []byte) (int, []byte, error) {
	var a RoutingAnswer
	if err := json.Unmarshal(answer, &a); err != nil || a.Status < 100 || a.Status > 599 {
		return 0, nil, errors.New("the gateway service sent a malformed routing answer")
	}
	return a.Status, a.Body, nil
}
