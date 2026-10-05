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

package otlp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

func TestFailureCodesNameTheCause(t *testing.T) {
	for status, want := range map[int]delivery.FailureCode{
		http.StatusUnauthorized:          delivery.FailureCodeHTTPAuthentication,
		http.StatusForbidden:             delivery.FailureCodeHTTPAuthentication,
		http.StatusTooManyRequests:       delivery.FailureCodeHTTPRetryable,
		http.StatusBadGateway:            delivery.FailureCodeHTTPRetryable,
		http.StatusBadRequest:            delivery.FailureCodeHTTPRejected,
		http.StatusRequestEntityTooLarge: delivery.FailureCodeHTTPRejected,
	} {
		if got := httpStatusFailureCode(status); got != want {
			t.Errorf("httpStatusFailureCode(%d) = %q, want %q", status, got, want)
		}
	}
	for err, want := range map[error]delivery.FailureCode{
		fmt.Errorf("dial: %w", netguard.ErrV8ResolutionFailed): delivery.FailureCodeResolutionFailed,
		fmt.Errorf("dial: %w", netguard.ErrV8ConnectionFailed): delivery.FailureCodeConnectionFailed,
		fmt.Errorf("do: %w", context.DeadlineExceeded):         delivery.FailureCodeRequestTimeout,
		fmt.Errorf("do: %w", context.Canceled):                 delivery.FailureCodeRequestCanceled,
		errors.New("unexpected EOF"):                           delivery.FailureCodeTransportFailed,
	} {
		if got := transportFailureCode(err); got != want {
			t.Errorf("transportFailureCode(%v) = %q, want %q", err, got, want)
		}
	}
	for code, want := range map[codes.Code]delivery.FailureCode{
		codes.Unauthenticated:  delivery.FailureCodeHTTPAuthentication,
		codes.DeadlineExceeded: delivery.FailureCodeRequestTimeout,
		codes.Unavailable:      delivery.FailureCodeConnectionFailed,
		codes.InvalidArgument:  delivery.FailureCodeHTTPRejected,
		codes.Internal:         delivery.FailureCodeAcknowledgementLost,
	} {
		if got := grpcFailureCode(grpcstatus.Error(code, "x")); got != want {
			t.Errorf("grpcFailureCode(%s) = %q, want %q", code, got, want)
		}
	}
	for _, code := range []delivery.FailureCode{
		httpStatusFailureCode(http.StatusUnauthorized), transportFailureCode(errors.New("x")),
		grpcFailureCode(grpcstatus.Error(codes.Internal, "x")),
	} {
		if !delivery.IsFailureCode(code) {
			t.Errorf("%q is not a closed delivery failure code", code)
		}
	}
}
