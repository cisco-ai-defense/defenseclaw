// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// hookDeliveryReceipt keeps the managed hook's request open until the hook
// commits its answer to the agent. The response is a proposal; only the
// receipt proves which proposal the hook gave. Without a receipt the gateway
// records only the result it can establish from the proposal and connection.
type hookDeliveryReceipt struct {
	reader *bufio.Reader
	length string
}

type hookDeliveryAdvertisedKey struct{}

type hookDeliveryStartContextKey struct{}

func hookDeliveryReceiptForRequest(r *http.Request) *hookDeliveryReceipt {
	delivery, _ := r.Context().Value(hookDeliveryStartContextKey{}).(*hookDeliveryReceipt)
	return delivery
}

func withHookDeliveryReceipt(r *http.Request, delivery *hookDeliveryReceipt) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), hookDeliveryStartContextKey{}, delivery))
}

func (a *APIServer) beginHookDeliveryReceipt(w http.ResponseWriter, r *http.Request) *hookDeliveryReceipt {
	if a == nil || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() ||
		r.Header.Get(hookexec.HookDeliveryReceiptHeader) != "1" {
		return nil
	}
	if advertised, _ := r.Context().Value(hookDeliveryAdvertisedKey{}).(bool); !advertised {
		if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
			// Without full duplex the hook closes its request body after the
			// short capability wait, so the ordinary bounded request still works.
			return nil
		}
		if r.ProtoMajor == 1 {
			// The request body stays open across the response. Reusing this
			// HTTP/1 connection can race the server's next-request reader with
			// the final receipt read when the hook closes at its deadline.
			w.Header().Set("Connection", "close")
		}
		w.WriteHeader(http.StatusEarlyHints)
	}
	return &hookDeliveryReceipt{reader: bufio.NewReader(r.Body),
		length: r.Header.Get(hookexec.HookDeliveryPayloadBytesHeader)}
}

func (d *hookDeliveryReceipt) readPayload() ([]byte, error) {
	length, err := strconv.ParseInt(d.length, 10, 64)
	if err != nil || length < 1 || length > apiRequestBodyMaxBytes {
		return nil, &http.MaxBytesError{Limit: apiRequestBodyMaxBytes}
	}
	body := make([]byte, length)
	_, err = io.ReadFull(d.reader, body)
	return body, err
}

// offer writes one bounded JSON answer while the request remains open. The
// receipt is an exact token, not a caller-supplied verdict: a different
// verdict cannot be substituted after policy evaluation. No receipt means
// the hook's answer watchdog won or the connection was lost.
// HookDeliveryReleased means the 103 came after the hook's capability wait:
// the hook took the answer as an ordinary one and sends no receipt.
func (d *hookDeliveryReceipt) offer(w http.ResponseWriter, answer func()) string {
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return ""
	}
	w.Header().Set(hookexec.HookDeliveryRequiredHeader, "1")
	answer()
	if err := controller.Flush(); err != nil {
		return ""
	}
	line, err := bufio.NewReader(io.LimitReader(d.reader, int64(len(hookexec.HookDeliveryReceiptBlock)))).ReadString('\n')
	if err != nil {
		return ""
	}
	switch line {
	case hookexec.HookDeliveryReleased:
		return line
	case hookexec.HookDeliveryReceiptAck, hookexec.HookDeliveryReceiptBlock:
		_, _ = io.WriteString(w, hookexec.HookDeliveryConfirmed)
		_ = controller.Flush()
		return line
	default:
		return ""
	}
}

// hookActionUnconfirmed is the audited action of a managed hook call whose
// enforced result the gateway cannot prove.
const hookActionUnconfirmed = "unconfirmed"

// hookDeliveryRejectedReason is the reason of the block a managed hook
// enforced when it refused the proposed answer.
const hookDeliveryRejectedReason = "managed hook rejected the proposed answer"

// deliveredHookDecision is the decision of a call that asked for a delivery
// receipt: the offered answer once the hook acknowledged it, and the hook's
// own block when it refused it. A missing receipt cannot prove what an older
// hook emitted, even if its connection closed before the offer. A policy block
// remains a block when the configured outage mode is closed.
func (a *APIServer) deliveredHookDecision(connectorName string, resp agentHookResponse, receipt string) agentHookResponse {
	switch receipt {
	case hookexec.HookDeliveryReceiptAck:
		return resp
	case hookexec.HookDeliveryReceiptBlock:
		return failedClosedHookDelivery(resp, hookDeliveryRejectedReason)
	}
	if a.scannerCfg.EffectiveHookFailModeForConnector(connectorName) == "open" {
		// An outage can allow even if the offered policy answer blocked.
		return unconfirmedHookDelivery(resp)
	}
	if resp.Action == "block" {
		// The policy block and the closed fallback have the same result.
		return resp
	}
	return unconfirmedHookDelivery(resp)
}

// unreceiptedHookDecision is the decision of a standalone managed call that
// sent no delivery receipt.
//   - A caller that hung up before the answer was sent never got it, but an
//     older hook's local fallback cannot be proven without its receipt.
//   - A native hook's tool call without a receipt comes from an earlier hook
//     binary (a package upgrade in flight) or a connection without full
//     duplex. Its answer watchdog may have blocked after the gateway decided,
//     so only a block is known.
//   - A 1.0.4 hook that released its request before the gateway's late 103
//     took the answer without a receipt, the same as an earlier binary.
//   - Every other call keeps its evaluated decision. In-agent plugins, policy
//     bridges and events without an answer deadline send no receipt.
func (a *APIServer) unreceiptedHookDecision(hungUpBeforeAnswer bool, connectorName, event string, resp agentHookResponse) agentHookResponse {
	if a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() || hookexec.NeutralLifecycleEvent(connectorName, event) {
		return resp
	}
	closed := a.scannerCfg.EffectiveHookFailModeForConnector(connectorName) != "open"
	switch {
	case closed && resp.Action == "block":
		return resp
	case hungUpBeforeAnswer, hookexec.DeliveryReceiptEvent(connectorName, event):
		return unconfirmedHookDelivery(resp)
	}
	return resp
}

// pendingFailureHookDecision is the decision of a receipt-capable call whose
// pending occurrence could not be made durable. The gateway answers 503
// without offering the evaluated answer, and a managed standalone hook takes
// an error answer closed even under the administrator's open outage mode. A
// policy block keeps its own reason; it is the same result.
func pendingFailureHookDecision(resp agentHookResponse) agentHookResponse {
	if resp.Action == "block" {
		return resp
	}
	return failedClosedHookDelivery(resp, hookexec.ManagedGatewayNoAnswerReason)
}

func failedClosedHookDelivery(resp agentHookResponse, reason string) agentHookResponse {
	if resp.RawAction == "" {
		resp.RawAction = resp.Action
	}
	resp.Action = "block"
	resp.Mode = "action"
	resp.Severity = "HIGH"
	resp.Reason = reason
	resp.SourceReason = resp.Reason
	resp.WouldBlock = false
	resp.HookOutput = nil
	return resp
}

func unconfirmedHookDelivery(resp agentHookResponse) agentHookResponse {
	if resp.RawAction == "" {
		resp.RawAction = resp.Action
	}
	resp.Action = hookActionUnconfirmed
	resp.Reason = hookexec.ManagedGatewayNoAnswerReason
	resp.SourceReason = resp.Reason
	resp.WouldBlock = false
	resp.HookOutput = nil
	return resp
}
