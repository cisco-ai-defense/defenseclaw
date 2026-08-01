// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPIDAll = 5
	mibTCPStateEstab    = 5
	maxTCPTableBytes    = 16 << 20
)

var (
	getExtendedTCPTableProc = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

	managedEnterpriseQueryServicePID = queryManagedGatewayServicePID
	managedEnterpriseConnectedPID    = connectedManagedGatewayPID
	managedEnterpriseDialContext     = (&net.Dialer{Timeout: 2 * time.Second}).DialContext
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type managedIPv4Endpoint struct {
	addr [4]byte
	port uint16
}

// managedEnterpriseHTTPClient authenticates the process behind the exact
// connected TCP socket before net/http receives the connection and can write
// a bearer token or any request bytes. The listener must remain the same
// Running SCM service process across both status queries.
func managedEnterpriseHTTPClient(
	timeout time.Duration,
	apiAddr string,
	serviceName string,
) (*http.Client, error) {
	canonicalAddr, err := normalizeManagedGatewayAddress(apiAddr)
	if err != nil {
		return nil, managedGatewayPeerError("%v", err)
	}
	if err := validateManagedGatewayServiceName(serviceName); err != nil {
		return nil, managedGatewayPeerError("%v", err)
	}
	if timeout <= 0 {
		timeout = defaultHookRequestTimeout
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" && network != "tcp4" {
					return nil, managedGatewayPeerError("unexpected network %q", network)
				}
				if address != canonicalAddr {
					return nil, managedGatewayPeerError(
						"dial target %q does not equal protected gateway %q",
						address,
						canonicalAddr,
					)
				}

				servicePID, err := managedEnterpriseQueryServicePID(serviceName)
				if err != nil {
					return nil, managedGatewayPeerError("query protected gateway service: %v", err)
				}
				conn, err := managedEnterpriseDialContext(ctx, "tcp4", canonicalAddr)
				if err != nil {
					return nil, err
				}
				verified := false
				defer func() {
					if !verified {
						_ = conn.Close()
					}
				}()

				connectedPID, err := managedEnterpriseConnectedPID(conn)
				if err != nil {
					return nil, managedGatewayPeerError("resolve connected listener owner: %v", err)
				}
				if connectedPID == 0 || connectedPID != servicePID {
					return nil, managedGatewayPeerError(
						"connected listener PID %d does not equal service PID %d",
						connectedPID,
						servicePID,
					)
				}
				recheckedPID, err := managedEnterpriseQueryServicePID(serviceName)
				if err != nil {
					return nil, managedGatewayPeerError("re-query protected gateway service: %v", err)
				}
				if recheckedPID != servicePID {
					return nil, managedGatewayPeerError(
						"gateway service PID changed from %d to %d",
						servicePID,
						recheckedPID,
					)
				}

				verified = true
				return conn, nil
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func managedGatewayPeerError(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", errManagedGatewayPeerUnverified, fmt.Sprintf(format, args...))
}

func normalizeManagedGatewayAddress(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", errors.New("managed gateway address is not canonical")
	}
	host, rawPort, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("managed gateway address is not host:port: %w", err)
	}
	if host != "127.0.0.1" {
		return "", errors.New("managed gateway address must use exact canonical 127.0.0.1")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != rawPort {
		return "", errors.New("managed gateway port is not canonical")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func validateManagedGatewayServiceName(value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 256 ||
		strings.ContainsAny(value, "\x00\r\n\\/") {
		return errors.New("managed gateway service name is invalid")
	}
	return nil
}

func queryManagedGatewayServicePID(serviceName string) (uint32, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(manager)

	name, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return 0, err
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(service)

	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err := windows.QueryServiceStatusEx(
		service,
		windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&status)),
		uint32(unsafe.Sizeof(status)),
		&needed,
	); err != nil {
		return 0, err
	}
	if status.CurrentState != windows.SERVICE_RUNNING || status.ProcessId == 0 {
		return 0, fmt.Errorf(
			"service is not Running with a process (state=%d pid=%d)",
			status.CurrentState,
			status.ProcessId,
		)
	}
	return status.ProcessId, nil
}

func connectedManagedGatewayPID(conn net.Conn) (uint32, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, fmt.Errorf("connected socket has type %T, want *net.TCPConn", conn)
	}
	client, err := managedIPv4EndpointFromAddr(tcpConn.LocalAddr())
	if err != nil {
		return 0, fmt.Errorf("parse client endpoint: %w", err)
	}
	server, err := managedIPv4EndpointFromAddr(tcpConn.RemoteAddr())
	if err != nil {
		return 0, fmt.Errorf("parse server endpoint: %w", err)
	}
	rows, err := readTCP4OwnerPIDTable()
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		if row.State != mibTCPStateEstab {
			continue
		}
		local := managedIPv4Endpoint{
			addr: ipv4FromMIB(row.LocalAddr),
			port: bits.ReverseBytes16(uint16(row.LocalPort)),
		}
		remote := managedIPv4Endpoint{
			addr: ipv4FromMIB(row.RemoteAddr),
			port: bits.ReverseBytes16(uint16(row.RemotePort)),
		}
		if local == server && remote == client {
			if row.OwningPID == 0 {
				return 0, errors.New("connected listener owner PID is zero")
			}
			return row.OwningPID, nil
		}
	}
	return 0, fmt.Errorf(
		"no ESTABLISHED reverse tuple for %v:%d -> %v:%d",
		client.addr,
		client.port,
		server.addr,
		server.port,
	)
}

func managedIPv4EndpointFromAddr(addr net.Addr) (managedIPv4Endpoint, error) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return managedIPv4Endpoint{}, fmt.Errorf("address has type %T, want *net.TCPAddr", addr)
	}
	ip := tcpAddr.IP.To4()
	if ip == nil || tcpAddr.Port < 1 || tcpAddr.Port > 65535 {
		return managedIPv4Endpoint{}, fmt.Errorf("address %q is not a valid IPv4 TCP endpoint", addr.String())
	}
	var result managedIPv4Endpoint
	copy(result.addr[:], ip)
	result.port = uint16(tcpAddr.Port)
	return result, nil
}

func ipv4FromMIB(value uint32) [4]byte {
	return [4]byte{
		byte(value),
		byte(value >> 8),
		byte(value >> 16),
		byte(value >> 24),
	}
}

func readTCP4OwnerPIDTable() ([]mibTCPRowOwnerPID, error) {
	var size uint32
	err := callGetExtendedTCPTable(nil, &size)
	if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("size IPv4 owner-PID table: %w", err)
	}
	for attempts := 0; attempts < 3; attempts++ {
		if size < 4 || size > maxTCPTableBytes {
			return nil, fmt.Errorf("IPv4 owner-PID table size %d is invalid", size)
		}
		buffer := make([]byte, size)
		err = callGetExtendedTCPTable(buffer, &size)
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read IPv4 owner-PID table: %w", err)
		}
		count := *(*uint32)(unsafe.Pointer(&buffer[0]))
		rowSize := uint64(unsafe.Sizeof(mibTCPRowOwnerPID{}))
		required := uint64(4) + uint64(count)*rowSize
		if required > uint64(len(buffer)) {
			return nil, errors.New("IPv4 owner-PID table is truncated")
		}
		rows := make([]mibTCPRowOwnerPID, int(count))
		if count > 0 {
			source := unsafe.Slice(
				(*mibTCPRowOwnerPID)(unsafe.Pointer(&buffer[4])),
				int(count),
			)
			copy(rows, source)
		}
		return rows, nil
	}
	return nil, errors.New("IPv4 owner-PID table changed during bounded read")
}

func callGetExtendedTCPTable(buffer []byte, size *uint32) error {
	var pointer uintptr
	if len(buffer) > 0 {
		pointer = uintptr(unsafe.Pointer(&buffer[0]))
	}
	result, _, _ := getExtendedTCPTableProc.Call(
		pointer,
		uintptr(unsafe.Pointer(size)),
		0,
		uintptr(windows.AF_INET),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}
