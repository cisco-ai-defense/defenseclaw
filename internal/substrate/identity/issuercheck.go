// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// Sign-in server (OIDC issuer) failure causes, the classes a person may see
// (GAP-0262). The detail stays with administrators.
const (
	IssuerUnreachable  = "issuer_unreachable"   // DNS, connect or timeout: no answer
	IssuerTLSName      = "issuer_tls_name"      // the certificate does not name the issuer host
	IssuerTLSUntrusted = "issuer_tls_untrusted" // the certificate does not verify against the configured CA
	IssuerHTTP         = "issuer_http"          // the discovery address answered, but not with a discovery document
	IssuerUnavailable  = "issuer_unavailable"   // the server answered with an error of its own (5xx, 429): it is up but failing
	IssuerMismatch     = "issuer_mismatch"      // the discovery document names another issuer
	IssuerKeys         = "issuer_keys"          // the key set (jwks_uri) does not load
)

// IssuerDiagnosis is one check of the sign-in server, from where the
// caller runs (the gateway's DNS and network, its trust bundle). Cause is
// "" when every step passed.
type IssuerDiagnosis struct {
	Issuer string
	Cause  string
	Detail string
	Keys   int
}

// DiagnoseIssuer checks the issuer step by step, as the verifier uses it:
// the discovery document at <issuer>/.well-known/openid-configuration
// answers over TLS that verifies against the configured trust bundle and
// names the issuer host; the document's issuer equals the configured one
// exactly; and its jwks_uri loads with at least one key. It reads the
// network now, outside the refetch limit, and changes no cached key. It is
// for administrator checks (doctor, status), not the request path.
func (ks *KeySet) DiagnoseIssuer(ctx context.Context) IssuerDiagnosis {
	d := IssuerDiagnosis{Issuer: ks.issuer}
	ctx, cancel := context.WithTimeout(ctx, DefaultFetchTimeout)
	defer cancel()
	discoveryURL := ks.issuer + "/.well-known/openid-configuration"
	var doc discovery
	if err := ks.getJSON(ctx, discoveryURL, acceptJSON, &doc); err != nil {
		d.Cause, d.Detail = issuerCause(err), fmt.Sprintf("discovery %s: %v", discoveryURL, err)
		return d
	}
	if doc.Issuer != ks.issuer {
		d.Cause, d.Detail = IssuerMismatch, fmt.Sprintf("the discovery document names issuer %q, the configured issuer is %q", doc.Issuer, ks.issuer)
		return d
	}
	ju, err := url.Parse(doc.JWKSURI)
	if err != nil || ju.Scheme != "https" || ju.Host == "" {
		d.Cause, d.Detail = IssuerKeys, fmt.Sprintf("the discovery document's jwks_uri %q is not an https URL", doc.JWKSURI)
		return d
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := ks.getJSON(ctx, doc.JWKSURI, acceptKeySet, &set); err != nil {
		cause := issuerCause(err)
		if cause == IssuerHTTP {
			cause = IssuerKeys
		}
		// A server-side error on the key set stays issuer_unavailable.
		d.Cause, d.Detail = cause, fmt.Sprintf("key set %s: %v", doc.JWKSURI, err)
		return d
	}
	if len(set.Keys) == 0 {
		d.Cause, d.Detail = IssuerKeys, fmt.Sprintf("the key set %s holds no keys", doc.JWKSURI)
		return d
	}
	d.Keys = len(set.Keys)
	return d
}

// issuerCause classifies a fetch error.
func issuerCause(err error) string {
	var host x509.HostnameError
	var hostp *x509.HostnameError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var verr *tls.CertificateVerificationError
	var dnsErr *net.DNSError
	var op *net.OpError
	var uerr *url.Error
	var serr *statusError
	switch {
	case errors.As(err, &serr) && (serr.code >= 500 || serr.code == http.StatusTooManyRequests):
		return IssuerUnavailable
	case errors.As(err, &host), errors.As(err, &hostp):
		return IssuerTLSName
	case errors.As(err, &unknown), errors.As(err, &invalid), errors.As(err, &verr):
		return IssuerTLSUntrusted
	case errors.As(err, &dnsErr), errors.As(err, &op), errors.Is(err, context.DeadlineExceeded):
		return IssuerUnreachable
	case errors.As(err, &uerr) && uerr.Timeout():
		return IssuerUnreachable
	}
	return IssuerHTTP
}
