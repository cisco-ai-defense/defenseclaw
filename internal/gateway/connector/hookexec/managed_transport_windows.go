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
	mibTCPStateListen   = 2
	mibTCPStateEstab    = 5
	maxTCPTableBytes    = 16 << 20
)

var (
	getExtendedTCPTableProc = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

	managedEnterpriseQueryServicePID = queryManagedGatewayServicePID
	managedEnterpriseConnectedPID    = connectedManagedGatewayPID
	managedEnterpriseListening       = managedGatewayPortListening
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

// mibTCP6RowOwnerPID is MIB_TCP6ROW_OWNER_PID.
type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
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
				if errors.Is(err, errManagedGatewayNotRunning) {
					return nil, stoppedManagedGatewayError(canonicalAddr, err)
				}
				if err != nil {
					return nil, managedGatewayPeerError("query protected gateway service: %v", err)
				}
				// A service that has just started (or is about to stop)
				// can run without a listener on its port. Windows answers a
				// connect to such a port only after about 2 seconds of SYN
				// retries, so one try could take most of a restart budget:
				// read the listen table instead, and try again shortly.
				if listening, known := managedEnterpriseListening(canonicalAddr); known && !listening {
					// The service has a PID, so its absence is not proven. The
					// restart loop may retry, but open must not allow this call.
					return nil, fmt.Errorf("%w: %w: running service has no listener on %s yet",
						errManagedGatewayPeerUnverified, errGatewayNotConnected, canonicalAddr)
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
				if connectedPID == 0 {
					return nil, managedGatewayPeerError("connected listener PID 0 does not equal service PID %d", servicePID)
				}
				if connectedPID != servicePID {
					// The service runs, but another process answers on its
					// port: the hook names the port, not a stopped service
					// (GAP-1029).
					return nil, fmt.Errorf("%w: %w: connected listener PID %d does not equal service PID %d",
						errManagedGatewayPeerUnverified, errManagedGatewayPortHeld, connectedPID, servicePID)
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

// stoppedManagedGatewayError is the dial error when the gateway service is
// not running (serviceErr). That is an outage, which a standalone hook's
// open fail mode lets through, only when nothing listens on the gateway's
// port either. Another process on the port while the service is stopped is
// an integrity failure (errManagedGatewayPortHeld, closed in every fail
// mode), and so is a listen table the hook cannot read: before, the stopped
// service was reported before the port was looked at, so fail mode open
// allowed the call while another program held the port.
func stoppedManagedGatewayError(canonicalAddr string, serviceErr error) error {
	listening, known := managedEnterpriseListening(canonicalAddr)
	switch {
	case !known:
		return managedGatewayPeerError("gateway service is not running and the listeners on %s cannot be read: %v", canonicalAddr, serviceErr)
	case listening:
		return fmt.Errorf("%w: %w: the gateway service is not running but another process listens on %s",
			errManagedGatewayPeerUnverified, errManagedGatewayPortHeld, canonicalAddr)
	}
	// Still a peer-verification failure, but the hook can say the service
	// is stopped.
	return fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, serviceErr)
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
		return 0, fmt.Errorf("%w (state=%d pid=%d)", errManagedGatewayNotRunning, status.CurrentState, status.ProcessId)
	}
	return status.ProcessId, nil
}

// managedGatewayServiceStartType reads the service's start type.
func managedGatewayServiceStartType(service windows.Handle) (uint32, bool) {
	var needed uint32
	err := windows.QueryServiceConfig(service, nil, 0, &needed)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || needed == 0 || needed > 64<<10 {
		return 0, false
	}
	buffer := make([]byte, needed)
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	if err := windows.QueryServiceConfig(service, config, needed, &needed); err != nil {
		return 0, false
	}
	return config.StartType, true
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
	return connectedManagedGatewayPIDForEndpoints(client, server)
}

func connectedManagedGatewayPIDForEndpoints(client, server managedIPv4Endpoint) (uint32, error) {
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
		"%w: no ESTABLISHED reverse tuple for %v:%d -> %v:%d",
		errConnectedSocketNotFound,
		client.addr,
		client.port,
		server.addr,
		server.port,
	)
}

// managedGatewayPortListening reports whether any process listens on the
// IPv4 address of address (or on every address) and its port, or on that
// port over IPv6: a dual-stack listener on [::] also keeps the gateway from
// binding. known is false when either table cannot be read, and the hook
// then dials as before.
func managedGatewayPortListening(address string) (listening, known bool) {
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		return false, false
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return false, false
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return false, false
	}
	rows, err := readTCP4OwnerPIDTable()
	if err != nil {
		return false, false
	}
	rows6, err := readTCP6OwnerPIDTable()
	if err != nil {
		return false, false
	}
	return tcpTableListensOn(rows, [4]byte(ip), uint16(port)) || tcp6TableListensOn(rows6, uint16(port)), true
}

// tcp6TableListensOn reports an IPv6 LISTEN row on port at any address.
func tcp6TableListensOn(rows []mibTCP6RowOwnerPID, port uint16) bool {
	for _, row := range rows {
		if row.State == mibTCPStateListen && bits.ReverseBytes16(uint16(row.LocalPort)) == port {
			return true
		}
	}
	return false
}

// tcpTableListensOn reports a LISTEN row for addr (or 0.0.0.0) and port.
func tcpTableListensOn(rows []mibTCPRowOwnerPID, addr [4]byte, port uint16) bool {
	for _, row := range rows {
		if row.State != mibTCPStateListen || bits.ReverseBytes16(uint16(row.LocalPort)) != port {
			continue
		}
		if local := ipv4FromMIB(row.LocalAddr); local == addr || local == ([4]byte{}) {
			return true
		}
	}
	return false
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
	return readOwnerPIDTable[mibTCPRowOwnerPID](windows.AF_INET, "IPv4")
}

func readTCP6OwnerPIDTable() ([]mibTCP6RowOwnerPID, error) {
	return readOwnerPIDTable[mibTCP6RowOwnerPID](windows.AF_INET6, "IPv6")
}

func readOwnerPIDTable[Row mibTCPRowOwnerPID | mibTCP6RowOwnerPID](family uint32, label string) ([]Row, error) {
	var size uint32
	err := callGetExtendedTCPTable(nil, &size, family)
	if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("size %s owner-PID table: %w", label, err)
	}
	for attempts := 0; attempts < 3; attempts++ {
		if size < 4 || size > maxTCPTableBytes {
			return nil, fmt.Errorf("%s owner-PID table size %d is invalid", label, size)
		}
		buffer := make([]byte, size)
		err = callGetExtendedTCPTable(buffer, &size, family)
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s owner-PID table: %w", label, err)
		}
		count := *(*uint32)(unsafe.Pointer(&buffer[0]))
		var zero Row
		rowSize := uint64(unsafe.Sizeof(zero))
		required := uint64(4) + uint64(count)*rowSize
		if required > uint64(len(buffer)) {
			return nil, fmt.Errorf("%s owner-PID table is truncated", label)
		}
		rows := make([]Row, int(count))
		if count > 0 {
			source := unsafe.Slice(
				(*Row)(unsafe.Pointer(&buffer[4])),
				int(count),
			)
			copy(rows, source)
		}
		return rows, nil
	}
	return nil, fmt.Errorf("%s owner-PID table changed during bounded read", label)
}

func callGetExtendedTCPTable(buffer []byte, size *uint32, family uint32) error {
	// LazyProc.Call panics if the DLL or the exported symbol cannot be
	// resolved. Surface that as a normal error so the managed transport
	// path degrades gracefully instead of taking the whole process down.
	if err := getExtendedTCPTableProc.Find(); err != nil {
		return fmt.Errorf("resolve GetExtendedTcpTable: %w", err)
	}
	var pointer uintptr
	if len(buffer) > 0 {
		pointer = uintptr(unsafe.Pointer(&buffer[0]))
	}
	result, _, _ := getExtendedTCPTableProc.Call(
		pointer,
		uintptr(unsafe.Pointer(size)),
		0,
		uintptr(family),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}
