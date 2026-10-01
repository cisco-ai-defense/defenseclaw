package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/shield/discover"
	"github.com/defenseclaw/defenseclaw/internal/shield/policy"
)

type Event struct {
	Timestamp   string              `json:"timestamp"`
	EventType   string              `json:"event_type"`
	Agent       discover.AgentInfo  `json:"agent"`
	Provider    string              `json:"provider"`
	Destination string              `json:"destination"`
	Direction   string              `json:"direction"`
	Verdict     policy.Verdict      `json:"verdict"`
	ContentSize int                 `json:"content_size"`
	RequestID   string              `json:"request_id,omitempty"`
}

type Logger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Logger{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

func (l *Logger) Log(evt Event) {
	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(evt)
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}
