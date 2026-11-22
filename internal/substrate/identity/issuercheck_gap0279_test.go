// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"net/http"
	"testing"
)

// GAP-0279: a server that answers with errors (5xx, 429) is
// issuer_unavailable, apart from a wrong address (404: issuer_http).
func TestDiagnoseIssuerServerErrorsGAP0279(t *testing.T) {
	for code, want := range map[int]string{
		http.StatusInternalServerError: IssuerUnavailable,
		http.StatusBadGateway:          IssuerUnavailable,
		http.StatusServiceUnavailable:  IssuerUnavailable,
		http.StatusTooManyRequests:     IssuerUnavailable,
		http.StatusNotFound:            IssuerHTTP,
	} {
		srv, ca := issuerServer(t, "", 1, code)
		if d := diagnose(t, srv.URL, ca); d.Cause != want {
			t.Errorf("discovery %d: %+v, want %s", code, d, want)
		}
	}
}
