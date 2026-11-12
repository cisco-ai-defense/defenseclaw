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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultKubeNamespace is where the cluster publishes its launcher
	// endpoint record when the context names no kube_namespace.
	DefaultKubeNamespace = "defenseclaw-system"
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

// KubeNamespaceOrDefault is the namespace of the endpoint record.
func (c Context) KubeNamespaceOrDefault() string {
	if ns := strings.TrimSpace(c.KubeNamespace); ns != "" {
		return ns
	}
	return DefaultKubeNamespace
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
// (DefaultKubeNamespace when empty) from the cluster's API server, the
// only place the kube bearer goes, trusting the kubeconfig's
// certificate authority. It returns the pin to record in the context.
func KubeVerifyEndpoint(ctx context.Context, o KubeOptions, adminURL, namespace string) (KubePin, error) {
	o = o.withDefaults()
	if namespace = strings.TrimSpace(namespace); namespace == "" {
		namespace = DefaultKubeNamespace
	}
	if err := checkKubeNamespace(namespace); err != nil {
		return KubePin{}, err
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
	tok, _, err := kubeCredential(ctx, o, sel)
	if err != nil {
		return KubePin{}, err
	}
	record := fmt.Sprintf("the endpoint record (ConfigMap %s in namespace %s)", KubeEndpointConfigMap, namespace)
	rctx, cancel := context.WithTimeout(ctx, o.apiTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, strings.TrimRight(sel.cluster.Server, "/")+"/api/v1/namespaces/"+namespace+"/configmaps/"+KubeEndpointConfigMap, nil)
	if err != nil {
		return KubePin{}, fmt.Errorf("the server URL of the kube cluster %q is not valid", clean(sel.ctx.Cluster, 100))
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "defenseclaw-launcher")
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
		return KubePin{}, fmt.Errorf("the kubeconfig user %q may not read %s on %s (HTTP 403); check you may read ConfigMaps in that namespace, or ask your administrator to allow it; %s", clean(tok.Principal, 100), record, server, kubeNoOverride)
	case resp.StatusCode == http.StatusUnauthorized:
		return KubePin{}, fmt.Errorf("the Kubernetes API server %s did not accept the credential of the kubeconfig user %q (HTTP 401); sign in to the cluster again (for example run: kubectl get namespaces)", server, clean(tok.Principal, 100))
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
	return KubePin{Server: server, AdminURL: admin, Principal: tok.Principal}, nil
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
