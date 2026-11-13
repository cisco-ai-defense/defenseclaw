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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// KubeEndpointConfigMap is the ConfigMap that holds the record; its
	// data key admin_url is the admin listener of this cluster.
	KubeEndpointConfigMap = "defenseclaw-launcher-endpoint"
	kubeEndpointKey       = "admin_url"
	kubeAPITimeout        = 15 * time.Second
	kubeNoOverride        = "there is no override: the endpoint record is the only way to allow a Kubernetes sign-in"
	kubeLoginAgain        = "run: defenseclaw substrate login --kube again"
)

// KubePin is what KubeVerifyEndpoint checked: the kubeconfig cluster's
// API server and the admin URL that cluster publishes, both normalised.
// The context stores Server and AdminURL as kube_pin_server and
// kube_pin_admin_url; Principal is the kubeconfig user, for display.
type KubePin struct {
	Server    string
	AdminURL  string
	Principal string
}

// WithKubePin returns c with the pin recorded.
func (c Context) WithKubePin(p KubePin) Context {
	c.KubePinServer, c.KubePinAdminURL = p.Server, p.AdminURL
	return c
}

// KubeNamespaceFound is login --kube without --kube-namespace: the one
// endpoint record that names the admin URL sits in Namespace. Discovery
// never pins a namespace by itself (GAP-0192, lane R5): anyone who may
// create a ConfigMap in some namespace can publish a record. Nothing went
// to the admin URL and nothing was minted; the person re-runs with
// --kube-namespace once they know DefenseClaw runs there.
type KubeNamespaceFound struct {
	Namespace string
	AdminURL  string
}

func (e *KubeNamespaceFound) Error() string {
	return fmt.Sprintf("the launcher endpoint record that names %s is in namespace %s; nothing was sent to it. If DefenseClaw runs there, sign in again with --kube-namespace %s", e.AdminURL, e.Namespace, e.Namespace)
}

var kubeNamespaceRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

func checkKubeNamespace(ns string) error {
	if !kubeNamespaceRE.MatchString(ns) {
		return fmt.Errorf("kube_namespace %q is not a valid Kubernetes namespace name", clean(ns, 80))
	}
	return nil
}

// normEndpoint normalises an http(s) URL for comparison and display:
// lowercase scheme and host, the default port made explicit, no trailing
// slash. A user name, password, query or fragment is refused, so the
// result never carries a credential.
func normEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("is not a valid URL")
	}
	if u.User != nil {
		return "", errors.New("must not carry a user name or password")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("must not have a query or fragment")
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	switch scheme {
	case "https":
		if port == "" {
			port = "443"
		}
	case "http":
		if port == "" {
			port = "80"
		}
	default:
		return "", errors.New("must be an https URL")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("needs a host")
	}
	return scheme + "://" + net.JoinHostPort(host, port) + strings.TrimRight(u.EscapedPath(), "/"), nil
}

// KubeVerifyEndpoint checks that adminURL is the launcher endpoint the
// kubeconfig's cluster publishes, before any Kubernetes credential is
// sent to it. It reads the ConfigMap KubeEndpointConfigMap in namespace
// from the cluster's API server, the only place the user's own credential
// goes, trusting the kubeconfig's certificate authority. It returns the pin
// to record in the context. With no namespace it only looks in every
// namespace for the record that names adminURL and returns
// *KubeNamespaceFound (one), or an error (none, several): it never signs in
// to a namespace the person did not name (GAP-0192).
func KubeVerifyEndpoint(ctx context.Context, o KubeOptions, adminURL, namespace string) (KubePin, error) {
	o = o.withDefaults()
	if namespace = strings.TrimSpace(namespace); namespace != "" {
		if err := checkKubeNamespace(namespace); err != nil {
			return KubePin{}, err
		}
	}
	if err := checkURL("admin_url", adminURL, false); err != nil {
		return KubePin{}, err
	}
	admin, err := normEndpoint(adminURL)
	if err != nil {
		return KubePin{}, fmt.Errorf("admin_url %s", err)
	}
	sel, err := kubeSelect(o)
	if err != nil {
		return KubePin{}, err
	}
	if sel.cluster == nil {
		return KubePin{}, sel.noCluster()
	}
	server, hc, err := kubeAPIClient(o, sel)
	if err != nil {
		return KubePin{}, err
	}
	// The user's own credential reads the record: a bearer, or the client
	// certificate kubeAPIClient presents.
	bearer, principal := "", sel.ctx.User
	if !sel.certOnly() {
		own := o
		own.ServiceAccount = ""
		tok, _, err := kubeUserCredential(ctx, own, sel)
		if err != nil {
			return KubePin{}, err
		}
		bearer, principal = tok.AccessToken, tok.Principal
	}
	if namespace == "" {
		found, err := kubeFindRecord(ctx, o, hc, sel.cluster.Server, server, bearer, principal, admin)
		if err != nil {
			return KubePin{}, err
		}
		return KubePin{}, &KubeNamespaceFound{Namespace: found, AdminURL: admin}
	}
	record := fmt.Sprintf("the endpoint record (ConfigMap %s in namespace %s)", KubeEndpointConfigMap, namespace)
	rctx, cancel := context.WithTimeout(ctx, o.apiTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, strings.TrimRight(sel.cluster.Server, "/")+"/api/v1/namespaces/"+namespace+"/configmaps/"+KubeEndpointConfigMap, nil)
	if err != nil {
		return KubePin{}, fmt.Errorf("the server URL of the kube cluster %q is not valid", clean(sel.ctx.Cluster, 100))
	}
	kubeAuthorize(req, bearer)
	resp, err := hc.Do(req)
	if err != nil {
		return KubePin{}, kubeAPIError(ctx, rctx, err, server, o.apiTimeout())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return KubePin{}, fmt.Errorf("reading %s from the Kubernetes API server %s failed", record, server)
	}
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotFound:
		return KubePin{}, fmt.Errorf("the cluster at %s has no launcher endpoint record (ConfigMap %s in namespace %s), so no Kubernetes credential is sent to %s; ask your administrator to publish the endpoint record, or give --kube-namespace NAME if DefenseClaw runs in another namespace; %s", server, KubeEndpointConfigMap, namespace, admin, kubeNoOverride)
	case resp.StatusCode == http.StatusForbidden:
		return KubePin{}, fmt.Errorf("the kubeconfig user %q may not read %s on %s (HTTP 403); check you may read ConfigMaps in that namespace, or ask your administrator to allow it; %s", clean(principal, 100), record, server, kubeNoOverride)
	case resp.StatusCode == http.StatusUnauthorized:
		return KubePin{}, fmt.Errorf("the Kubernetes API server %s did not accept the credential of the kubeconfig user %q (HTTP 401); sign in to the cluster again (for example run: kubectl get namespaces)", server, clean(principal, 100))
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return KubePin{}, fmt.Errorf("the Kubernetes API server %s answered with a redirect (HTTP %d), which the launcher does not follow; point the kubeconfig at the API server itself", server, resp.StatusCode)
	default:
		return KubePin{}, fmt.Errorf("reading %s from the Kubernetes API server %s failed (HTTP %d)", record, server, resp.StatusCode)
	}
	if len(body) > maxBody {
		return KubePin{}, fmt.Errorf("%s on %s is larger than 1 MiB", record, server)
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if json.Unmarshal(body, &cm) != nil {
		return KubePin{}, fmt.Errorf("the Kubernetes API server %s answered with something that is not a ConfigMap", server)
	}
	raw := strings.TrimSpace(cm.Data[kubeEndpointKey])
	if raw == "" {
		return KubePin{}, fmt.Errorf("%s on %s has no %s; ask your administrator to publish the endpoint record; %s", record, server, kubeEndpointKey, kubeNoOverride)
	}
	published, err := normEndpoint(raw)
	if err != nil {
		return KubePin{}, fmt.Errorf("the %s in %s on %s %s; ask your administrator to fix the endpoint record", kubeEndpointKey, record, server, err)
	}
	if published != admin {
		return KubePin{}, fmt.Errorf("the cluster at %s publishes the launcher endpoint %s, not %s, so no Kubernetes credential is sent to %s; use --admin-url %s, or ask your administrator to fix the endpoint record (ConfigMap %s in namespace %s); %s", server, published, admin, admin, published, KubeEndpointConfigMap, namespace, kubeNoOverride)
	}
	return KubePin{Server: server, AdminURL: admin, Principal: principal}, nil
}

// kubeAuthorize sets the headers of a request to the API server: the
// user's bearer when it has one (a certificate user is known by its TLS
// certificate alone).
func kubeAuthorize(req *http.Request, bearer string) {
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "defenseclaw-launcher")
}

// kubeFindRecord lists the endpoint records of every namespace and returns
// the namespace of the one that names admin. None, or more than one, is an
// error that asks for --kube-namespace.
func kubeFindRecord(ctx context.Context, o KubeOptions, hc *http.Client, rawServer, server, bearer, principal, admin string) (string, error) {
	rctx, cancel := context.WithTimeout(ctx, o.apiTimeout())
	defer cancel()
	q := url.Values{"fieldSelector": {"metadata.name=" + KubeEndpointConfigMap}}
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, strings.TrimRight(rawServer, "/")+"/api/v1/configmaps?"+q.Encode(), nil)
	if err != nil {
		return "", fmt.Errorf("the server URL of the kube cluster is not valid")
	}
	kubeAuthorize(req, bearer)
	resp, err := hc.Do(req)
	if err != nil {
		return "", kubeAPIError(ctx, rctx, err, server, o.apiTimeout())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return "", fmt.Errorf("reading the endpoint records from the Kubernetes API server %s failed", server)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return "", fmt.Errorf("the kubeconfig user %q may not list ConfigMaps in every namespace on %s, so the launcher cannot find the endpoint record; give --kube-namespace NAME (the namespace DefenseClaw runs in)", clean(principal, 100), server)
	default:
		return "", fmt.Errorf("listing the endpoint records on the Kubernetes API server %s failed (HTTP %d); give --kube-namespace NAME (the namespace DefenseClaw runs in)", server, resp.StatusCode)
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &list) != nil {
		return "", fmt.Errorf("the Kubernetes API server %s answered with something that is not a ConfigMap list", server)
	}
	var found []string
	for _, it := range list.Items {
		if it.Metadata.Name != KubeEndpointConfigMap || checkKubeNamespace(it.Metadata.Namespace) != nil {
			continue
		}
		if got, err := normEndpoint(strings.TrimSpace(it.Data[kubeEndpointKey])); err == nil && got == admin {
			found = append(found, it.Metadata.Namespace)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", fmt.Errorf("no launcher endpoint record (ConfigMap %s) on %s names %s, so no Kubernetes credential is sent to it; check --admin-url, or give --kube-namespace NAME; %s", KubeEndpointConfigMap, server, admin, kubeNoOverride)
	}
	return "", fmt.Errorf("the launcher endpoint records of the namespaces %s on %s all name %s; give --kube-namespace NAME to pick the one DefenseClaw runs in", strings.Join(found, ", "), server, admin)
}

// mintKubeToken asks the API server, with the user's own credential (bearer,
// or the client certificate kubeAPIClient presents), for a short-lived token
// of the ServiceAccount o names (or DefaultKubeServiceAccount) for the
// DefenseClaw audience. The gateway checks it with a TokenReview.
func mintKubeToken(ctx context.Context, o KubeOptions, sel *kubeSel, bearer string) (*Token, error) {
	ns, name, err := kubeServiceAccount(o)
	if err != nil {
		return nil, err
	}
	if sel.cluster == nil {
		return nil, sel.noCluster()
	}
	server, hc, err := kubeAPIClient(o, sel)
	if err != nil {
		return nil, err
	}
	who := fmt.Sprintf("the kubeconfig user %q", clean(sel.ctx.User, 100))
	why := ""
	if sel.certOnly() {
		why = who + " signs in with a client certificate, which DefenseClaw cannot check, so the launcher signs in as a ServiceAccount; "
	}
	sa := ns + "/" + name
	body, _ := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
		"spec": map[string]any{"audiences": []string{identity.KubeTokenAudience}, "expirationSeconds": kubeMintSeconds}})
	rctx, cancel := context.WithTimeout(ctx, o.apiTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, strings.TrimRight(sel.cluster.Server, "/")+"/api/v1/namespaces/"+ns+"/serviceaccounts/"+name+"/token", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("the server URL of the kube cluster %q is not valid", clean(sel.ctx.Cluster, 100))
	}
	kubeAuthorize(req, bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, kubeAPIError(ctx, rctx, err, server, o.apiTimeout())
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("%sthe ServiceAccount %s does not exist on %s: create it with kubectl -n %s create serviceaccount %s, or name another with --kube-service-account NAMESPACE/NAME", why, sa, server, ns, name)
	case http.StatusForbidden:
		return nil, fmt.Errorf("%s%s may not create a token for the ServiceAccount %s on %s (HTTP 403): it needs create on serviceaccounts/token for it, or name another with --kube-service-account NAMESPACE/NAME", why, who, sa, server)
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("the Kubernetes API server %s did not accept the credential of %s (HTTP 401); sign in to the cluster again (for example run: kubectl get namespaces)", server, who)
	default:
		return nil, fmt.Errorf("the Kubernetes API server %s did not mint a token for the ServiceAccount %s (HTTP %d)", server, sa, resp.StatusCode)
	}
	var tr struct {
		Status struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &tr) != nil {
		return nil, fmt.Errorf("the Kubernetes API server %s answered the token request with something that is not a TokenRequest", server)
	}
	tok, ok := oneToken([]byte(tr.Status.Token))
	if !ok {
		return nil, fmt.Errorf("the Kubernetes API server %s returned no token for the ServiceAccount %s", server, sa)
	}
	return &Token{Kind: KindKube, AccessToken: tok, Expiry: tr.Status.ExpirationTimestamp, Principal: "system:serviceaccount:" + ns + ":" + name}, nil
}

// kubeServiceAccountRE is a ServiceAccount name (a DNS subdomain).
var kubeServiceAccountRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// kubeServiceAccount splits o.ServiceAccount ("NAMESPACE/NAME" or "NAME",
// default DefaultKubeServiceAccount); a bare name lives in o.Namespace.
func kubeServiceAccount(o KubeOptions) (string, string, error) {
	ns, name := strings.TrimSpace(o.Namespace), strings.TrimSpace(o.ServiceAccount)
	if a, b, ok := strings.Cut(name, "/"); ok {
		ns, name = a, b
	}
	if name == "" {
		name = DefaultKubeServiceAccount
	}
	if ns == "" {
		return "", "", fmt.Errorf("the ServiceAccount %s needs its namespace: give --kube-service-account NAMESPACE/NAME or --kube-namespace NAME", clean(name, 100))
	}
	return ns, name, CheckKubeServiceAccount(ns + "/" + name)
}

// CheckKubeServiceAccount checks a "NAMESPACE/NAME" or "NAME" value.
func CheckKubeServiceAccount(v string) error {
	ns, name, ok := strings.Cut(v, "/")
	if !ok {
		ns, name = "", v
	}
	if (ok && checkKubeNamespace(ns) != nil) || !kubeServiceAccountRE.MatchString(name) || strings.Contains(name, "/") {
		return fmt.Errorf("kube_service_account %q is not NAMESPACE/NAME or NAME of a Kubernetes ServiceAccount", clean(v, 100))
	}
	return nil
}

func (o KubeOptions) apiTimeout() time.Duration {
	if o.apiTimeoutT > 0 {
		return o.apiTimeoutT
	}
	return kubeAPITimeout
}

// kubeAPIClient returns the normalised server URL and an HTTP client that
// trusts only the kubeconfig's certificate authority (the system roots
// when the cluster names none), follows no redirect and honours the
// cluster's tls-server-name and proxy-url.
func kubeAPIClient(o KubeOptions, sel *kubeSel) (string, *http.Client, error) {
	cl, name := sel.cluster, clean(sel.ctx.Cluster, 100)
	server, err := normEndpoint(cl.Server)
	if err != nil || !strings.HasPrefix(server, "https://") {
		return "", nil, fmt.Errorf("the server of the kube cluster %q must be an https URL with a host and no user name, password or query", name)
	}
	if cl.InsecureSkipTLSVerify {
		return "", nil, fmt.Errorf("the kube cluster %q sets insecure-skip-tls-verify; the launcher does not send a Kubernetes credential to an API server it cannot verify; set certificate-authority-data for the cluster", name)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cl.TLSServerName}
	if cert, err := kubeClientCert(o, sel); err != nil {
		return "", nil, err
	} else if cert != nil {
		tc.Certificates = []tls.Certificate{*cert}
	}
	var pem []byte
	switch {
	case strings.TrimSpace(cl.CertificateAuthorityData) != "":
		if pem, err = base64.StdEncoding.DecodeString(strings.TrimSpace(cl.CertificateAuthorityData)); err != nil {
			return "", nil, fmt.Errorf("the certificate-authority-data of the kube cluster %q is not base64", name)
		}
	case cl.CertificateAuthority != "":
		p := relTo(cl.CertificateAuthority, sel.clFrom)
		if pem, err = o.ReadFile(p); err != nil {
			return "", nil, fmt.Errorf("the certificate-authority file %s of the kube cluster %q cannot be read: %s", p, name, readReason(err))
		}
	}
	if pem != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return "", nil, fmt.Errorf("the certificate authority of the kube cluster %q holds no PEM certificate", name)
		}
		tc.RootCAs = pool
	}
	proxy := http.ProxyFromEnvironment
	if p := strings.TrimSpace(cl.ProxyURL); p != "" {
		pu, err := url.Parse(p)
		if err != nil || pu.Host == "" {
			return "", nil, fmt.Errorf("the proxy-url of the kube cluster %q is not valid", name)
		}
		proxy = http.ProxyURL(pu)
	}
	hc := &http.Client{
		Transport: &http.Transport{Proxy: proxy, TLSClientConfig: tc, TLSHandshakeTimeout: 10 * time.Second},
		Timeout:   o.apiTimeout(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return server, hc, nil
}

// kubeAPIError explains a failed request without the request (its URL
// holds no secret, but the cause is kept short).
func kubeAPIError(ctx, rctx context.Context, err error, server string, timeout time.Duration) error {
	var uae x509.UnknownAuthorityError
	var cve *tls.CertificateVerificationError
	var hne x509.HostnameError
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("reading the endpoint record from %s was stopped: %w", server, ctx.Err())
	case errors.Is(rctx.Err(), context.DeadlineExceeded) || isTimeout(err):
		return fmt.Errorf("the Kubernetes API server %s did not answer within %s", server, timeout)
	case errors.As(err, &uae) || errors.As(err, &cve) || errors.As(err, &hne):
		return fmt.Errorf("the Kubernetes API server %s presented a certificate the kubeconfig's certificate authority does not trust, so no credential was sent; check certificate-authority-data and tls-server-name of the cluster", server)
	}
	cause := err
	var ue *url.Error
	if errors.As(err, &ue) {
		cause = ue.Err
	}
	return fmt.Errorf("cannot reach the Kubernetes API server %s: %s", server, stderrLine(cause.Error()))
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// kubePinError says a kube context may not send its credential now.
// errors.Is(err, ErrNotSignedIn) is true: a new login --kube is the fix.
type kubePinError struct{ msg string }

func (e *kubePinError) Error() string        { return e.msg }
func (e *kubePinError) Is(target error) bool { return target == ErrNotSignedIn }

// checkKubePin refuses to hand out the kube bearer unless the context's
// admin URL (after environment overrides) and the kubeconfig's current
// cluster are the ones login --kube verified. It reads the kubeconfig but
// no credential, and returns the selection for the credential read.
func checkKubePin(c Context, o KubeOptions) (*kubeSel, error) {
	pinAdmin, errA := normEndpoint(c.KubePinAdminURL)
	pinServer, errS := normEndpoint(c.KubePinServer)
	if c.KubePinAdminURL == "" || c.KubePinServer == "" || errA != nil || errS != nil {
		return nil, &kubePinError{"this kube context was not verified against the cluster's launcher endpoint record, so no Kubernetes credential is sent; " + kubeLoginAgain + "; " + kubeNoOverride}
	}
	verified := fmt.Sprintf("this sign-in was verified for %s on %s", pinAdmin, pinServer)
	admin, err := normEndpoint(c.AdminURL)
	if err != nil {
		return nil, &kubePinError{fmt.Sprintf("%s, but admin_url %s; %s", verified, err, kubeLoginAgain)}
	}
	sel, err := kubeSelect(o)
	if err != nil {
		return nil, err
	}
	server := ""
	if sel.cluster != nil {
		server, _ = normEndpoint(sel.cluster.Server)
	}
	if admin != pinAdmin || server != pinServer {
		now := server
		if now == "" {
			now = fmt.Sprintf("the kube cluster %q", clean(sel.ctx.Cluster, 100))
		}
		return nil, &kubePinError{fmt.Sprintf("%s, not for %s on %s, so no Kubernetes credential is sent; %s", verified, admin, now, kubeLoginAgain)}
	}
	return sel, nil
}

// kubeClientCert is the selected user's client certificate (data or files,
// as in client-go), nil when it has none. It goes only to the API server.
func kubeClientCert(o KubeOptions, sel *kubeSel) (*tls.Certificate, error) {
	u, ok := sel.kc.users[sel.ctx.User]
	if !ok || !u.hasCert() {
		return nil, nil
	}
	who := fmt.Sprintf("the kubeconfig user %q", clean(sel.ctx.User, 100))
	from := sel.kc.userFrom[sel.ctx.User]
	read := func(data, file, what string) ([]byte, error) {
		if d := strings.TrimSpace(data); d != "" {
			b, err := base64.StdEncoding.DecodeString(d)
			if err != nil {
				return nil, fmt.Errorf("the %s-data of %s is not base64", what, who)
			}
			return b, nil
		}
		if strings.TrimSpace(file) == "" {
			return nil, fmt.Errorf("%s has no %s", who, what)
		}
		b, err := o.ReadFile(relTo(file, from))
		if err != nil {
			return nil, fmt.Errorf("the %s file of %s cannot be read: %s", what, who, readReason(err))
		}
		return b, nil
	}
	cert, err := read(u.ClientCertificateData, u.ClientCertificate, "client-certificate")
	if err != nil {
		return nil, err
	}
	key, err := read(u.ClientKeyData, u.ClientKey, "client-key")
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("the client certificate and key of %s do not form a pair", who)
	}
	return &pair, nil
}
