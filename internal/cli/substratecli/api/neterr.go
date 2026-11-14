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

package api

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"syscall"
)

// transportError says in plain words why the cluster could not be reached,
// and what to check. The cause stays reachable with errors.Is and As.
type transportError struct {
	host string
	text string
	err  error
}

func (e *transportError) Error() string {
	return e.text + " (" + e.host + "). Check it with: defenseclaw substrate doctor"
}
func (e *transportError) Unwrap() error { return e.err }

func friendlyTransport(host string, err error) error {
	var unknown x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	var dns *net.DNSError
	text := "cannot reach the cluster"
	switch {
	case errors.As(err, &unknown):
		text = "the cluster certificate is not trusted; give the certificate authority with: defenseclaw substrate login --admin-ca-file FILE"
	case errors.As(err, &hostErr), errors.As(err, &certInvalid):
		text = "the cluster certificate does not match its address or is not valid"
	case errors.As(err, &dns):
		text = "cannot find the cluster address"
	case errors.Is(err, syscall.ECONNREFUSED):
		text = "nothing answers at the cluster address"
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		text = "the cluster did not answer in time"
	case errors.Is(err, context.Canceled):
		return err
	case strings.Contains(err.Error(), "x509:"):
		text = "the cluster certificate is not trusted"
	}
	return &transportError{host: host, text: text, err: err}
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}
