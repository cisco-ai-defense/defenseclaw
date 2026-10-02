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
	"net"
	"net/http"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

// failedResult pairs an outcome with the stable failure code that names why
// the export failed. The code reaches the delivery-failure alert and the
// destination health row (setup galileo status), so an operator sees
// "http_authentication" or "resolution_failed" instead of "unspecified".
// The outcome alone still drives retry and circuit decisions.
func failedResult(outcome delivery.DeliveryOutcome, code delivery.FailureCode) delivery.DeliveryResult {
	return delivery.DeliveryResult{Outcome: outcome, FailureCode: code}
}

// httpStatusFailureCode names a non-2xx OTLP/HTTP response.
func httpStatusFailureCode(status int) delivery.FailureCode {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return delivery.FailureCodeHTTPAuthentication
	case status == http.StatusRequestTimeout || status == http.StatusTooEarly ||
		status == http.StatusTooManyRequests || status >= 500:
		return delivery.FailureCodeHTTPRetryable
	default:
		return delivery.FailureCodeHTTPRejected
	}
}

// transportFailureCode names an OTLP/HTTP round trip that returned no
// response and did not write the request.
func transportFailureCode(err error) delivery.FailureCode {
	var networkError net.Error
	switch {
	case errors.Is(err, netguard.ErrV8ResolutionFailed):
		return delivery.FailureCodeResolutionFailed
	case errors.Is(err, netguard.ErrV8ConnectionFailed):
		return delivery.FailureCodeConnectionFailed
	case errors.Is(err, context.Canceled):
		return delivery.FailureCodeRequestCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return delivery.FailureCodeRequestTimeout
	case errors.As(err, &networkError) && networkError.Timeout():
		return delivery.FailureCodeRequestTimeout
	default:
		return delivery.FailureCodeTransportFailed
	}
}

// grpcFailureCode names a failed OTLP/gRPC export.
func grpcFailureCode(err error) delivery.FailureCode {
	switch grpcstatus.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return delivery.FailureCodeHTTPAuthentication
	case codes.DeadlineExceeded:
		return delivery.FailureCodeRequestTimeout
	case codes.Canceled:
		return delivery.FailureCodeRequestCanceled
	case codes.Unavailable:
		return delivery.FailureCodeConnectionFailed
	case codes.ResourceExhausted, codes.Aborted:
		return delivery.FailureCodeHTTPRetryable
	case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists, codes.FailedPrecondition,
		codes.Unimplemented, codes.OutOfRange:
		return delivery.FailureCodeHTTPRejected
	default:
		return delivery.FailureCodeAcknowledgementLost
	}
}
