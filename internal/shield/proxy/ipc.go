package proxy

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/shield/audit"
	"github.com/defenseclaw/defenseclaw/internal/shield/discover"
	"github.com/defenseclaw/defenseclaw/internal/shield/inspect"
	"github.com/defenseclaw/defenseclaw/internal/shield/policy"
	"github.com/defenseclaw/defenseclaw/internal/shield/providers"
)

// Wire protocol between the interposition library and the shield daemon.
//
// The interposition library (C dylib/DLL) sends messages over a Unix domain
// socket (macOS/Linux) or named pipe (Windows).
//
// Message format (little-endian):
//   [4 bytes] total message length (excluding this header)
//   [1 byte]  message type: 0x01 = SSL_write (request), 0x02 = SSL_read (response)
//   [4 bytes] PID of calling process
//   [2 bytes] destination host length
//   [N bytes] destination host (e.g. "api.anthropic.com:443")
//   [4 bytes] payload length
//   [N bytes] payload (plaintext HTTP body or full HTTP request)
//
// Shield replies:
//   [1 byte]  verdict: 0x00 = allow, 0x01 = block

const (
	MsgTypeRequest  byte = 0x01
	MsgTypeResponse byte = 0x02

	VerdictAllow byte = 0x00
	VerdictBlock byte = 0x01
)

type InterceptMessage struct {
	Type     byte
	PID      int
	DestHost string
	Payload  []byte
}

type IPCServer struct {
	socketPath string
	listener   net.Listener
	registry   *providers.Registry
	inspector  *inspect.Inspector
	engine     *policy.Engine
	logger     *audit.Logger
	requestID  atomic.Uint64
	wg         sync.WaitGroup
	done       chan struct{}
}

func SocketPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\defenseclaw-shield`
	}
	dir := os.Getenv("DEFENSECLAW_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".defenseclaw-shield")
	}
	_ = os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "shield.sock")
}

func NewIPCServer(
	registry *providers.Registry,
	inspector *inspect.Inspector,
	engine *policy.Engine,
	logger *audit.Logger,
) *IPCServer {
	return &IPCServer{
		socketPath: SocketPath(),
		registry:   registry,
		inspector:  inspector,
		engine:     engine,
		logger:     logger,
		done:       make(chan struct{}),
	}
}

func (s *IPCServer) Start() error {
	_ = os.Remove(s.socketPath)

	var err error
	if runtime.GOOS == "windows" {
		s.listener, err = listenPipe(s.socketPath)
	} else {
		s.listener, err = net.Listen("unix", s.socketPath)
	}
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.socketPath, err)
	}

	if runtime.GOOS != "windows" {
		_ = os.Chmod(s.socketPath, 0600)
	}

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *IPCServer) Stop() {
	close(s.done)
	_ = s.listener.Close()
	s.wg.Wait()
	if runtime.GOOS != "windows" {
		_ = os.Remove(s.socketPath)
	}
}

func (s *IPCServer) SocketAddr() string {
	return s.socketPath
}

func (s *IPCServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *IPCServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	for {
		msg, err := readMessage(conn)
		if err != nil {
			return
		}

		verdict := s.processMessage(msg)

		var reply [1]byte
		if verdict.Action == policy.ActionBlock {
			reply[0] = VerdictBlock
		} else {
			reply[0] = VerdictAllow
		}
		if _, err := conn.Write(reply[:]); err != nil {
			return
		}
	}
}

func (s *IPCServer) processMessage(msg InterceptMessage) policy.Verdict {
	providerName, isLLM := s.registry.MatchHost(msg.DestHost)
	if !isLLM {
		return policy.Verdict{Action: policy.ActionAllow}
	}

	result := s.inspector.Inspect(string(msg.Payload))
	verdict := s.engine.Evaluate(result)

	direction := "request"
	if msg.Type == MsgTypeResponse {
		direction = "response"
	}

	reqID := fmt.Sprintf("req-%d", s.requestID.Add(1))
	agent := discover.IdentifyProcess(msg.PID)

	s.logger.Log(audit.Event{
		EventType:   "llm_intercept",
		Agent:       agent,
		Provider:    providerName,
		Destination: msg.DestHost,
		Direction:   direction,
		Verdict:     verdict,
		ContentSize: len(msg.Payload),
		RequestID:   reqID,
	})

	return verdict
}

func readMessage(r io.Reader) (InterceptMessage, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return InterceptMessage{}, err
	}
	totalLen := binary.LittleEndian.Uint32(hdr[:])
	if totalLen > 10*1024*1024 {
		return InterceptMessage{}, fmt.Errorf("message too large: %d", totalLen)
	}

	buf := make([]byte, totalLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return InterceptMessage{}, err
	}

	if len(buf) < 7 {
		return InterceptMessage{}, fmt.Errorf("message too short")
	}

	msg := InterceptMessage{
		Type: buf[0],
		PID:  int(binary.LittleEndian.Uint32(buf[1:5])),
	}

	hostLen := binary.LittleEndian.Uint16(buf[5:7])
	pos := 7
	if pos+int(hostLen) > len(buf) {
		return InterceptMessage{}, fmt.Errorf("host length exceeds message")
	}
	msg.DestHost = string(buf[pos : pos+int(hostLen)])
	pos += int(hostLen)

	if pos+4 > len(buf) {
		return InterceptMessage{}, fmt.Errorf("missing payload length")
	}
	payloadLen := binary.LittleEndian.Uint32(buf[pos : pos+4])
	pos += 4

	if pos+int(payloadLen) > len(buf) {
		return InterceptMessage{}, fmt.Errorf("payload exceeds message")
	}
	msg.Payload = buf[pos : pos+int(payloadLen)]
	return msg, nil
}

// listenPipe is a placeholder for Windows named pipe.
// On non-Windows this is never called.
func listenPipe(path string) (net.Listener, error) {
	return nil, fmt.Errorf("named pipes not implemented on %s", runtime.GOOS)
}

// MarshalMessage encodes a message for sending to the IPC server (used by tests and the interposition lib reference).
func MarshalMessage(msgType byte, pid int, destHost string, payload []byte) []byte {
	hostBytes := []byte(destHost)
	// 1 (type) + 4 (pid) + 2 (host len) + N (host) + 4 (payload len) + N (payload)
	bodyLen := 1 + 4 + 2 + len(hostBytes) + 4 + len(payload)

	buf := make([]byte, 4+bodyLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(bodyLen))
	buf[4] = msgType
	binary.LittleEndian.PutUint32(buf[5:9], uint32(pid))
	binary.LittleEndian.PutUint16(buf[9:11], uint16(len(hostBytes)))
	copy(buf[11:], hostBytes)
	off := 11 + len(hostBytes)
	binary.LittleEndian.PutUint32(buf[off:off+4], uint32(len(payload)))
	copy(buf[off+4:], payload)
	return buf
}

// Status returns a JSON-serializable summary of the server state.
func (s *IPCServer) Status() json.RawMessage {
	info := map[string]any{
		"socket":     s.socketPath,
		"request_id": s.requestID.Load(),
	}
	b, _ := json.Marshal(info)
	return b
}
