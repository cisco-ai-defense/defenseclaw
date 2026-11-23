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

package bundle

// A small OCI distribution (registry v2) client for signed bundles
// (GAP-0437, design B-OCI-0437): GET the manifest by digest, GET the one
// bundle layer by digest, answer a Bearer or Basic challenge once. The
// registry is untrusted transport: digests are checked before anything is
// parsed and the archive then goes through the same Store.Apply (Verify) as
// file and inbox bundles. Everything fails closed.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// SourceOCI is the receipt source of a bundle pulled from a registry.
const SourceOCI = "oci"

// OCI limits.
const (
	MediaTypeBundleLayer = "application/vnd.defenseclaw.bundle.v1"

	mediaTypeOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"

	ociMaxManifestBytes = 64 << 10
	ociMaxTokenBytes    = 64 << 10
	ociMaxErrorBytes    = 4 << 10
	ociMaxLayers        = 16
	ociMaxRedirects     = 3
)

// OCIError is a failed pull. It names the host and what failed, never a
// credential or token.
type OCIError struct {
	Ref    string
	Reason string
}

func (e *OCIError) Error() string { return "oci pull " + e.Ref + ": " + e.Reason }

// OCIStage is one stage whose bundle comes from a registry.
type OCIStage struct {
	Stage     string
	Ref       string
	Atespaces []string
}

type ociCred struct{ user, pass string }

// OCIClient pulls bundles by digest.
type OCIClient struct {
	http    *http.Client
	creds   map[string]ociCred // registry host -> credentials
	timeout time.Duration
}

// NewOCIClient builds the client from substrate.bundles.oci: TLS 1.2+ with
// the system roots plus caFile, credentials only from credentialsFile (a
// mounted kubernetes.io/dockerconfigjson Secret).
func NewOCIClient(o config.SubstrateBundleOCIConfig) (*OCIClient, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("oci ca_file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("oci ca_file %s: no PEM certificate", o.CAFile)
		}
	}
	c := &OCIClient{timeout: o.EffectiveTimeout(), creds: map[string]ociCred{}}
	if o.CredentialsFile != "" {
		if c.creds, err = readDockerConfig(o.CredentialsFile); err != nil {
			return nil, err
		}
	}
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: c.timeout,
		ForceAttemptHTTP2:     true,
	}
	c.http = &http.Client{Transport: tr, CheckRedirect: checkOCIRedirect}
	return c, nil
}

// checkOCIRedirect allows at most three redirects, https only, and drops the
// Authorization header whenever the target host differs from the first
// request's (blob CDNs get no registry credentials).
func checkOCIRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= ociMaxRedirects {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("redirect to %s refused: https only", req.URL.Scheme)
	}
	if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		req.Header.Del("Authorization")
	}
	return nil
}

func readDockerConfig(path string) (map[string]ociCred, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("oci credentials_file: %w", err)
	}
	var doc struct {
		Auths map[string]struct {
			Auth     string `json:"auth"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("oci credentials_file %s: not a dockerconfigjson document", path)
	}
	out := map[string]ociCred{}
	for host, a := range doc.Auths {
		host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://"), "/")
		cr := ociCred{user: a.Username, pass: a.Password}
		if a.Auth != "" {
			dec, err := base64.StdEncoding.DecodeString(a.Auth)
			u, p, ok := strings.Cut(string(dec), ":")
			if err != nil || !ok {
				return nil, fmt.Errorf("oci credentials_file %s: auth for %s is not base64 user:password", path, host)
			}
			cr = ociCred{user: u, pass: p}
		}
		if cr.user != "" {
			out[strings.ToLower(host)] = cr
		}
	}
	return out, nil
}

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// pull is one pull's state: the ref and the Authorization value earned by
// the one challenge it may answer.
type ociPull struct {
	c          *OCIClient
	ref        string
	host, repo string
	auth       string
	answered   bool
}

// Pull fetches the bundle archive of ref (host/repo@sha256:<hex>). The
// manifest and the layer are checked against their digests before use.
func (c *OCIClient) Pull(ctx context.Context, ref string) ([]byte, error) {
	host, repo, digest, err := config.ParseSubstrateOCIRef(ref)
	if err != nil {
		return nil, &OCIError{Ref: ref, Reason: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	p := &ociPull{c: c, ref: ref, host: host, repo: repo}
	raw, err := p.get(ctx, "manifests/"+digest, mediaTypeOCIManifest+", "+mediaTypeDockerManifest, ociMaxManifestBytes)
	if err != nil {
		return nil, err
	}
	if got := sha256Digest(raw); got != digest {
		return nil, p.fail("manifest digest %s does not match the reference", got)
	}
	var m struct {
		SchemaVersion int             `json:"schemaVersion"`
		MediaType     string          `json:"mediaType"`
		Layers        []ociDescriptor `json:"layers"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, p.fail("manifest is not JSON")
	}
	if m.SchemaVersion != 2 || (m.MediaType != "" && m.MediaType != mediaTypeOCIManifest && m.MediaType != mediaTypeDockerManifest) {
		return nil, p.fail("not an image manifest (schema %d, media type %q); indexes are not supported", m.SchemaVersion, m.MediaType)
	}
	if len(m.Layers) > ociMaxLayers {
		return nil, p.fail("%d layers (at most %d)", len(m.Layers), ociMaxLayers)
	}
	var layer *ociDescriptor
	for i := range m.Layers {
		if m.Layers[i].MediaType != MediaTypeBundleLayer {
			continue
		}
		if layer != nil {
			return nil, p.fail("more than one %s layer", MediaTypeBundleLayer)
		}
		layer = &m.Layers[i]
	}
	if layer == nil {
		return nil, p.fail("no %s layer", MediaTypeBundleLayer)
	}
	if !config.SubstrateOCIDigestRe.MatchString(layer.Digest) {
		return nil, p.fail("layer digest %q is not sha256:<64 hex>", layer.Digest)
	}
	if layer.Size <= 0 || layer.Size > MaxArchiveBytes {
		return nil, p.fail("layer size %d (at most %d bytes)", layer.Size, MaxArchiveBytes)
	}
	blob, err := p.get(ctx, "blobs/"+layer.Digest, "", MaxArchiveBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(blob)) != layer.Size || sha256Digest(blob) != layer.Digest {
		return nil, p.fail("layer does not match its digest or size")
	}
	return blob, nil
}

func sha256Digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func (p *ociPull) fail(format string, a ...any) error {
	return &OCIError{Ref: p.ref, Reason: fmt.Sprintf(format, a...)}
}

// get GETs /v2/<repo>/<path> with a size limit, answering one 401
// challenge.
func (p *ociPull) get(ctx context.Context, path, accept string, limit int64) ([]byte, error) {
	u := "https://" + p.host + "/v2/" + p.repo + "/" + path
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, p.fail("bad request URL")
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if p.auth != "" {
			req.Header.Set("Authorization", p.auth)
		}
		resp, err := p.c.http.Do(req)
		if err != nil {
			return nil, p.fail("%s", transportReason(err))
		}
		if resp.StatusCode == http.StatusUnauthorized && !p.answered {
			challenge := resp.Header.Get("WWW-Authenticate")
			drain(resp)
			p.answered = true
			if p.auth, err = p.answer(ctx, challenge); err != nil {
				return nil, err
			}
			continue
		}
		body, err := readLimited(resp, limit)
		if err != nil {
			return nil, p.fail("%s %s: %v", path[:strings.IndexByte(path, '/')], p.host, err)
		}
		return body, nil
	}
}

// answer turns a challenge into an Authorization value: Basic with the
// configured credentials, or a Bearer token from the realm (https only),
// asked with the credentials when there are any.
func (p *ociPull) answer(ctx context.Context, challenge string) (string, error) {
	scheme, params := parseChallenge(challenge)
	cred, haveCred := p.c.creds[strings.ToLower(p.host)]
	switch scheme {
	case "basic":
		if !haveCred {
			return "", p.fail("registry %s wants credentials and none are configured", p.host)
		}
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(cred.user+":"+cred.pass)), nil
	case "bearer":
	default:
		return "", p.fail("registry %s answered 401 with no usable challenge", p.host)
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Scheme != "https" || realm.Host == "" {
		return "", p.fail("token realm of %s must be an https URL", p.host)
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", "repository:"+p.repo+":pull")
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", p.fail("bad token realm")
	}
	if haveCred {
		req.SetBasicAuth(cred.user, cred.pass)
	}
	resp, err := p.c.http.Do(req)
	if err != nil {
		return "", p.fail("token %s: %s", realm.Host, transportReason(err))
	}
	body, err := readLimited(resp, ociMaxTokenBytes)
	if err != nil {
		return "", p.fail("token %s: %v", realm.Host, err)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(body, &tok) != nil || tok.Token == "" && tok.AccessToken == "" {
		return "", p.fail("token %s: no token in the answer", realm.Host)
	}
	if tok.Token == "" {
		tok.Token = tok.AccessToken
	}
	return "Bearer " + tok.Token, nil
}

// parseChallenge reads `Scheme k="v", k2="v2"` (RFC 7235, quoted values).
func parseChallenge(h string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params := map[string]string{}
	for rest = strings.TrimSpace(rest); rest != ""; {
		k, v, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, `"`) {
			end := strings.IndexByte(v[1:], '"')
			if end < 0 {
				break
			}
			params[k], rest = v[1:1+end], v[2+end:]
		} else {
			val, r, _ := strings.Cut(v, ",")
			params[k], rest = strings.TrimSpace(val), ","+r
		}
		rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ","))
	}
	return strings.ToLower(scheme), params
}

// readLimited reads a 200 body of at most limit bytes; any other status is
// an error naming the status only.
func readLimited(resp *http.Response, limit int64) ([]byte, error) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, ociMaxErrorBytes))
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New("401 unauthorized (credentials or token rejected or expired)")
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, errors.New("read failed")
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return b, nil
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, ociMaxErrorBytes))
	resp.Body.Close()
}

// transportReason keeps a transport error short and free of URLs with
// query strings (a token realm query never carries a secret, but stay safe).
func transportReason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	return err.Error()
}

// ociSeen is the processed key of an OCI stage: its manifest digest and
// atespaces. The content of a digest never changes, so a stage whose key
// was processed is never pulled again.
func ociSeen(st OCIStage) string {
	h := sha256.New()
	h.Write([]byte(st.Ref))
	h.Write([]byte{0})
	h.Write([]byte(strings.Join(st.Atespaces, ",")))
	return hex.EncodeToString(h.Sum(nil))
}

// SyncOCI applies every OCI stage not processed yet. A bundle that does not
// verify is receipted once (source oci) and leaves the stage as it was; a
// pull that fails changes nothing and is tried again the next pass (its
// errors are joined in err).
func (s *Store) SyncOCI(ctx context.Context, c *OCIClient, stages []OCIStage) ([]Receipt, error) {
	d, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	var out []Receipt
	var errs []error
	for _, st := range stages {
		seen := ociSeen(st)
		if d.state.OCISeen[st.Stage] == seen {
			continue
		}
		archive, err := c.Pull(ctx, st.Ref)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rc, aerr := s.Apply(ctx, bytes.Clone(archive), st.Stage, st.Atespaces, SourceOCI)
		if rc != nil {
			out = append(out, *rc)
		}
		if aerr != nil && isStorageError(aerr) {
			return out, errors.Join(append(errs, aerr)...)
		}
		if err := s.retry(ctx, func() error { return s.markOCISeen(ctx, st.Stage, seen) }); err != nil {
			return out, errors.Join(append(errs, err)...)
		}
		if d, err = s.read(ctx); err != nil {
			return out, errors.Join(append(errs, err)...)
		}
	}
	return out, errors.Join(errs...)
}

func (s *Store) markOCISeen(ctx context.Context, stage, seen string) error {
	d, err := s.read(ctx)
	if err != nil {
		return err
	}
	if d.state.OCISeen == nil {
		d.state.OCISeen = map[string]string{}
	}
	d.state.OCISeen[stage] = seen
	return s.write(ctx, d, nil)
}
