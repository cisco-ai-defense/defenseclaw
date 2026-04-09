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
	SkillName string
	Severity  string
	Findings  int
	Actions   []string
	Reason    string
	ExpiresAt time.Time
}

// NotificationQueue is a thread-safe store for security notifications. The
// watcher pushes entries after enforcement; the guardrail proxy reads active
// (unexpired) notifications before each LLM call and injects them as system
// messages so the LLM can inform the user.
//
// Notifications persist for notificationTTL so that ALL sessions (TUI,
// Telegram, etc.) see them, not just whichever session makes the next call.
type NotificationQueue struct {
	mu    sync.Mutex
	items []SecurityNotification
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
// exist. The same message may be returned on multiple calls until the
// notifications expire, ensuring every session sees the alert.
func (q *NotificationQueue) FormatSystemMessage() string {
	notes := q.ActiveNotifications()
	if len(notes) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("[DEFENSECLAW SECURITY ENFORCEMENT]\n")

	for i, n := range notes {
		if i > 0 {
			sb.WriteString("\n---\n")
		}
		fmt.Fprintf(&sb, "Skill %q was automatically enforced by DefenseClaw.\n", n.SkillName)
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
	}

	sb.WriteString("\nYou MUST proactively inform the user about this enforcement action. ")
	sb.WriteString("Do NOT confirm the skill was installed successfully. ")
	sb.WriteString("Explain that DefenseClaw detected security issues and took protective action.")
	return sb.String()
}
