// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

const (
	pipeRetryInterval = 20 * time.Millisecond
)

type ClientProvider struct {
	config ClientConfig
	key    [AuthKeyBytes]byte

	mu                sync.Mutex
	pendingInvalidate bool
}

func NewClientProvider(config ClientConfig) (*ClientProvider, error) {
	if err := ValidateIdentityBinding(
		config.BrokerServiceName,
		config.GatewayServiceName,
		config.PipeName,
	); err != nil {
		return nil, err
	}
	key, err := LoadAuthKey(config.AuthKeyPath, config.GatewayServiceName)
	if err != nil {
		return nil, err
	}
	return &ClientProvider{config: config, key: key}, nil
}

func (provider *ClientProvider) Token(ctx context.Context) (string, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.pendingInvalidate {
		if _, err := provider.exchange(ctx, OperationInvalidate); err != nil {
			return "", err
		}
		provider.pendingInvalidate = false
	}
	response, err := provider.exchange(ctx, OperationToken)
	if err != nil {
		return "", err
	}
	if response.Token == "" || strings.TrimSpace(response.Token) != response.Token ||
		strings.ContainsAny(response.Token, "\x00\r\n") {
		return "", fmt.Errorf("%w: broker returned an invalid token", ErrProtocol)
	}
	return response.Token, nil
}

func (provider *ClientProvider) Refresh(ctx context.Context) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.pendingInvalidate {
		if _, err := provider.exchange(ctx, OperationInvalidate); err != nil {
			return err
		}
		provider.pendingInvalidate = false
	}
	_, err := provider.exchange(ctx, OperationRefresh)
	return err
}

func (provider *ClientProvider) Invalidate() {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()
	if _, err := provider.exchange(ctx, OperationInvalidate); err != nil {
		provider.pendingInvalidate = true
	}
}

func (provider *ClientProvider) exchange(ctx context.Context, operation string) (Response, error) {
	if provider == nil {
		return Response{}, ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultOperationTimeout)
		defer cancel()
	}
	request, err := NewRequest(operation)
	if err != nil {
		return Response{}, err
	}
	message, err := EncodeRequest(request)
	if err != nil {
		return Response{}, err
	}
	handle, err := openClientPipe(ctx, provider.config.PipeName)
	if err != nil {
		return Response{}, ErrUnavailable
	}
	defer windows.CloseHandle(handle)

	if _, err := writeOverlapped(ctx, handle, message); err != nil {
		return Response{}, ErrUnavailable
	}
	responseBytes := make([]byte, MaxMessageBytes+1)
	count, err := readOverlapped(ctx, handle, responseBytes)
	if err != nil || count == 0 || count > MaxMessageBytes {
		return Response{}, ErrUnavailable
	}
	response, err := DecodeResponse(responseBytes[:count])
	if err != nil {
		return Response{}, err
	}
	if err := VerifyResponse(provider.key[:], request, response); err != nil {
		return Response{}, err
	}
	if !response.OK {
		return Response{}, fmt.Errorf("%w: %s", ErrUnavailable, response.Error)
	}
	return response, nil
}

func openClientPipe(ctx context.Context, pipeName string) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return 0, err
	}
	for {
		handle, openErr := windows.CreateFile(
			pointer,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION,
			0,
		)
		if openErr == nil {
			mode := uint32(windows.PIPE_READMODE_MESSAGE)
			if err := windows.SetNamedPipeHandleState(handle, &mode, nil, nil); err != nil {
				_ = windows.CloseHandle(handle)
				return 0, err
			}
			return handle, nil
		}
		if !errors.Is(openErr, windows.ERROR_PIPE_BUSY) &&
			!errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) {
			return 0, openErr
		}
		timer := time.NewTimer(pipeRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-timer.C:
		}
	}
}

func readOverlapped(ctx context.Context, handle windows.Handle, buffer []byte) (uint32, error) {
	return runOverlapped(ctx, handle, func(done *uint32, overlapped *windows.Overlapped) error {
		return windows.ReadFile(handle, buffer, done, overlapped)
	})
}

func writeOverlapped(ctx context.Context, handle windows.Handle, buffer []byte) (uint32, error) {
	return runOverlapped(ctx, handle, func(done *uint32, overlapped *windows.Overlapped) error {
		return windows.WriteFile(handle, buffer, done, overlapped)
	})
}

func runOverlapped(
	ctx context.Context,
	handle windows.Handle,
	operation func(*uint32, *windows.Overlapped) error,
) (uint32, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped := &windows.Overlapped{HEvent: event}
	var count uint32
	err = operation(&count, overlapped)
	if err == nil {
		return count, nil
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}
	for {
		wait, waitErr := windows.WaitForSingleObject(event, 25)
		if waitErr != nil {
			_ = windows.CancelIoEx(handle, overlapped)
			return 0, waitErr
		}
		if wait == windows.WAIT_OBJECT_0 {
			err = windows.GetOverlappedResult(handle, overlapped, &count, false)
			return count, err
		}
		select {
		case <-ctx.Done():
			_ = windows.CancelIoEx(handle, overlapped)
			_, _ = windows.WaitForSingleObject(event, windows.INFINITE)
			_ = windows.GetOverlappedResult(handle, overlapped, &count, false)
			return 0, ctx.Err()
		default:
		}
		runtime.KeepAlive(overlapped)
	}
}
