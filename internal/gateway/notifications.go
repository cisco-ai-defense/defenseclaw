package gateway

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const notificationTTL = 2 * time.Minute
const maxNotificationQueueSize = 50

// SecurityNotification represents a pending enforcement alert that the
// guardrail proxy will inject into LLM requests as a system message.
type SecurityNotification struct {
	SubjectType string
	SkillName   string
	Severity    string
	Findings    int
	Actions     []string
	Reason      string
	ExpiresAt   time.Time
	OneShot     bool
	sequence    uint64
	reserved    bool
}

// NotificationQueue is a thread-safe store for security notifications. The
// watcher pushes entries after enforcement; the guardrail proxy reads active
// (unexpired) notifications before each LLM call and injects them as system
// messages so the LLM can inform the user.
//
// Regular notifications persist for notificationTTL so that all sessions see
// them. One-shot plugin notices leave the queue after one injected request.
type NotificationQueue struct {
	mu     sync.Mutex
	items  []SecurityNotification
	nextID uint64
}

// NewNotificationQueue returns an empty queue ready for use.
func NewNotificationQueue() *NotificationQueue {
	return &NotificationQueue{}
}

// Push appends a notification with a TTL-based expiry. When the queue
// exceeds maxNotificationQueueSize, the oldest entries are dropped.
func (q *NotificationQueue) Push(n SecurityNotification) {
	q.mu.Lock()
	defer q.mu.Unlock()
	n.ExpiresAt = time.Now().Add(notificationTTL)
	q.nextID++
	n.sequence = q.nextID
	q.items = append(q.items, n)
	if len(q.items) > maxNotificationQueueSize {
		q.items = q.items[len(q.items)-maxNotificationQueueSize:]
	}
}

// ActiveNotifications returns all unexpired notifications, pruning expired
// ones in the process. Does NOT drain — the same notification is returned to
// every caller until it expires.
func (q *NotificationQueue) ActiveNotifications() []SecurityNotification {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	active := q.items[:0]
	for _, n := range q.items {
		if now.Before(n.ExpiresAt) {
			active = append(active, n)
		}
	}
	q.items = active

	if len(active) == 0 {
		return nil
	}
	out := make([]SecurityNotification, len(active))
	copy(out, active)
	return out
}

// FormatSystemMessage returns a formatted system message containing all
// active (unexpired) notifications. Returns "" when no active notifications
// exist. This is a non-consuming preview; request paths use PrepareSystemMessage.
func (q *NotificationQueue) FormatSystemMessage() string {
	notes, _ := q.snapshot(false)
	return formatNotificationMessage(notes)
}

// PrepareSystemMessage reserves one-shot notices for a single request.
func (q *NotificationQueue) PrepareSystemMessage() (string, []uint64) {
	notes, ids := q.snapshot(true)
	return formatNotificationMessage(notes), ids
}

func (q *NotificationQueue) snapshot(reserve bool) ([]SecurityNotification, []uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	notes := make([]SecurityNotification, 0, len(q.items))
	ids := make([]uint64, 0)
	retained := q.items[:0]
	for _, n := range q.items {
		if !now.Before(n.ExpiresAt) {
			continue
		}
		if !reserve || !n.reserved {
			notes = append(notes, n)
			if reserve && n.OneShot {
				n.reserved = true
				ids = append(ids, n.sequence)
			}
		}
		retained = append(retained, n)
	}
	q.items = retained
	return notes, ids
}

// CommitSystemMessage removes notices after the request carries them.
func (q *NotificationQueue) CommitSystemMessage(ids []uint64) {
	if len(ids) == 0 {
		return
	}
	selected := make(map[uint64]struct{}, len(ids))
	for _, id := range ids {
		selected[id] = struct{}{}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	retained := q.items[:0]
	for _, n := range q.items {
		if _, ok := selected[n.sequence]; !ok || !n.OneShot || !n.reserved {
			retained = append(retained, n)
		}
	}
	q.items = retained
}

// ReleaseSystemMessage makes a notice available after injection fails.
func (q *NotificationQueue) ReleaseSystemMessage(ids []uint64) {
	if len(ids) == 0 {
		return
	}
	selected := make(map[uint64]struct{}, len(ids))
	for _, id := range ids {
		selected[id] = struct{}{}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := range q.items {
		if _, ok := selected[q.items[i].sequence]; ok {
			q.items[i].reserved = false
		}
	}
}

func formatNotificationMessage(notes []SecurityNotification) string {
	if len(notes) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("[DEFENSECLAW SECURITY ENFORCEMENT]\n")

	for i, n := range notes {
		if i > 0 {
			sb.WriteString("\n---\n")
		}
		fmt.Fprintf(&sb, "%s %q was automatically enforced by DefenseClaw.\n", notificationSubjectLabel(n.SubjectType), n.SkillName)
		fmt.Fprintf(&sb, "Severity: %s", n.Severity)
		if n.Findings > 0 {
			fmt.Fprintf(&sb, " (%d finding(s))", n.Findings)
		}
		sb.WriteString("\n")
		if len(n.Actions) > 0 {
			fmt.Fprintf(&sb, "Actions taken: %s\n", strings.Join(n.Actions, ", "))
		}
		if n.Reason != "" {
			fmt.Fprintf(&sb, "Reason: %s\n", n.Reason)
		}
		if n.OneShot {
			fmt.Fprintf(&sb, "This notice concerns only %s %q. Continue unrelated requests normally.\n",
				notificationSubjectLabel(n.SubjectType), n.SkillName)
		}
	}

	for _, n := range notes {
		if !n.OneShot {
			sb.WriteString("\nYou MUST proactively inform the user about this enforcement action. ")
			sb.WriteString("Do NOT claim the component was installed or enabled successfully. ")
			sb.WriteString("Explain that DefenseClaw detected security issues and took protective action.")
			break
		}
	}
	return sb.String()
}

func notificationSubjectLabel(subjectType string) string {
	switch strings.TrimSpace(strings.ToLower(subjectType)) {
	case "plugin":
		return "Plugin"
	case "mcp":
		return "MCP Server"
	case "tool":
		return "Tool"
	default:
		return "Skill"
	}
}
