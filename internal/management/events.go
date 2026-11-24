package management

import (
	"log"
	"os"
	"sync"
	"time"
)

type Event struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

const logCapacity = 128

var logger = log.New(os.Stdout, "management ", log.LstdFlags)

type eventLog struct {
	mu      sync.Mutex
	entries [logCapacity]Event
	next    int
	count   int
}

func (l *eventLog) add(level, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries[l.next] = Event{Time: time.Now(), Level: level, Message: message}
	l.next = (l.next + 1) % logCapacity
	l.count = min(l.count+1, logCapacity)
	logger.Print(level, " ", message)
}

func (l *eventLog) list() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := make([]Event, 0, l.count)
	for idx := (l.next + logCapacity - l.count) % logCapacity; len(result) < l.count; idx = (idx + 1) % logCapacity {
		result = append(result, l.entries[idx])
	}
	return result
}

// State transitions use predefined names and error codes in the log and webhook.
func (c *Controller) transitionLocked(state State, code, notification string) {
	if c.status.State == state && c.status.Error == code {
		return
	}
	c.status.State, c.status.Error = state, code
	level := "INFO"
	if state == Failed {
		level = "ERROR"
	} else if code != "" {
		level = "WARN"
	}
	message := string(state)
	if code != "" {
		message += " (" + code + ")"
	}
	c.recordLocked(level, message)
	c.notifyLocked(notification)
}

func (c *Controller) recordLocked(level, message string) {
	c.events.add(level, message)
}

func (c *Controller) notifyLocked(message string) {
	if message != "" && c.options.Notify != nil {
		c.options.Notify(Event{Time: time.Now(), Level: "INFO", Message: message})
	}
}
