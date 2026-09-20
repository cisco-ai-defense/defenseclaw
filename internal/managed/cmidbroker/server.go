// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaximumClients = 8
	replayWindow          = 5 * time.Minute
	maximumReplayEntries  = 2048
)

type ServerConfig struct {
	PipeName           string
	BrokerServiceName  string
	GatewayServiceName string
	OperationTimeout   time.Duration
	MaximumClients     int
}

type Event struct {
	Operation string
	Stage     string
	Success   bool
	Duration  time.Duration
	ClientPID uint32
}

type EventLogger func(Event)

type Server struct {
	config   ServerConfig
	provider Provider
	key      [AuthKeyBytes]byte
	log      EventLogger

	providerMu sync.Mutex
	replayMu   sync.Mutex
	replayed   map[string]time.Time
}

func NewServer(config ServerConfig, provider Provider, key []byte, logger EventLogger) (*Server, error) {
	if provider == nil {
		return nil, errors.New("cmid broker provider is unavailable")
	}
	if len(key) != AuthKeyBytes {
		return nil, errors.New("cmid broker authentication key has an invalid length")
	}
	if err := ValidateIdentityBinding(
		config.BrokerServiceName,
		config.GatewayServiceName,
		config.PipeName,
	); err != nil {
		return nil, err
	}
	if config.OperationTimeout <= 0 {
		config.OperationTimeout = defaultOperationTimeout
	}
	if config.MaximumClients <= 0 {
		config.MaximumClients = defaultMaximumClients
	}
	if config.MaximumClients > 64 {
		return nil, errors.New("cmid broker maximum client count exceeds the hard limit")
	}
	server := &Server{
		config:   config,
		provider: provider,
		log:      logger,
		replayed: make(map[string]time.Time),
	}
	copy(server.key[:], key)
	return server, nil
}

func (server *Server) processMessage(ctx context.Context, message []byte) ([]byte, error) {
	return server.processMessageForClient(ctx, message, 0)
}

func (server *Server) processMessageForClient(
	ctx context.Context,
	message []byte,
	clientPID uint32,
) ([]byte, error) {
	request, err := DecodeRequest(message)
	if err != nil {
		return nil, err
	}
	if !server.acceptNonce(request.Nonce, time.Now()) {
		return nil, fmt.Errorf("%w: replayed nonce", ErrProtocol)
	}

	started := time.Now()
	response := Response{Version: ProtocolVersion, Nonce: request.Nonce}
	operationCtx, cancel := context.WithTimeout(ctx, server.config.OperationTimeout)
	defer cancel()

	server.providerMu.Lock()
	providerErr := server.runProviderOperation(operationCtx, request.Op, &response)
	server.providerMu.Unlock()
	if providerErr != nil {
		response.OK = false
		response.Token = ""
		response.Error = providerErrorCategory(request.Op, providerErr)
	} else {
		response.OK = true
	}
	if err := SignResponse(server.key[:], &response); err != nil {
		return nil, err
	}
	encoded, err := EncodeResponse(response)
	if server.log != nil {
		server.log(Event{
			Operation: request.Op,
			Stage:     responseStage(providerErr),
			Success:   providerErr == nil && err == nil,
			Duration:  time.Since(started),
			ClientPID: clientPID,
		})
	}
	return encoded, err
}

func (server *Server) runProviderOperation(ctx context.Context, operation string, response *Response) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("provider panic")
		}
	}()
	switch operation {
	case OperationToken:
		token, err := server.provider.Token(ctx)
		if err != nil {
			return err
		}
		if token == "" || len(token) > MaxTokenBytes || strings.TrimSpace(token) != token ||
			strings.ContainsAny(token, "\x00\r\n") {
			return errors.New("invalid token")
		}
		response.Token = token
		return nil
	case OperationRefresh:
		return server.provider.Refresh(ctx)
	case OperationInvalidate:
		server.provider.Invalidate()
		return nil
	default:
		return ErrProtocol
	}
}

func providerErrorCategory(operation string, err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "provider_timeout"
	case operation == OperationToken:
		return "provider_token_failed"
	case operation == OperationRefresh:
		return "provider_refresh_failed"
	case operation == OperationInvalidate:
		return "provider_invalidate_failed"
	default:
		return "provider_failed"
	}
}

func responseStage(err error) string {
	if err == nil {
		return "complete"
	}
	return "provider"
}

func (server *Server) acceptNonce(nonce string, now time.Time) bool {
	server.replayMu.Lock()
	defer server.replayMu.Unlock()
	cutoff := now.Add(-replayWindow)
	for value, observed := range server.replayed {
		if observed.Before(cutoff) {
			delete(server.replayed, value)
		}
	}
	if _, exists := server.replayed[nonce]; exists {
		return false
	}
	if len(server.replayed) >= maximumReplayEntries {
		var oldestNonce string
		var oldestTime time.Time
		for value, observed := range server.replayed {
			if oldestNonce == "" || observed.Before(oldestTime) {
				oldestNonce, oldestTime = value, observed
			}
		}
		delete(server.replayed, oldestNonce)
	}
	server.replayed[nonce] = now
	return true
}
