// Package domain defines validated job contracts shared by manager services.
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
)

// Error is a stable public error. Error() deliberately excludes private details.
type Error struct {
	Status  int               `json:"-"`
	Code    string            `json:"code"`
	Details any               `json:"detail,omitempty"`
	Headers map[string]string `json:"-"`
}

func (e *Error) Error() string { return e.Code }
func Err(status int, code string, details ...any) *Error {
	e := &Error{Status: status, Code: code}
	if len(details) > 0 {
		e.Details = details[0]
	}
	return e
}

type JobState string

const (
	Queued         JobState = "QUEUED"
	Provisioning   JobState = "PROVISIONING"
	Starting       JobState = "STARTING"
	Running        JobState = "RUNNING"
	Reconciling    JobState = "RECONCILING"
	NeedsAttention JobState = "NEEDS_ATTENTION"
	Cancelling     JobState = "CANCELLING"
	Succeeded      JobState = "SUCCEEDED"
	Failed         JobState = "FAILED"
	Cancelled      JobState = "CANCELLED"
)
const (
	StateQueued         = Queued
	StateProvisioning   = Provisioning
	StateStarting       = Starting
	StateRunning        = Running
	StateReconciling    = Reconciling
	StateNeedsAttention = NeedsAttention
	StateCancelling     = Cancelling
	StateSucceeded      = Succeeded
	StateFailed         = Failed
	StateCancelled      = Cancelled
)

func IsTerminal(state string) bool {
	return state == "SUCCEEDED" || state == "FAILED" || state == "CANCELLED"
}
func IsJobState(state string) bool {
	switch JobState(state) {
	case Queued, Provisioning, Starting, Running, Reconciling, NeedsAttention, Cancelling, Succeeded, Failed, Cancelled:
		return true
	}
	return false
}
func RoleLevel(role string) int {
	switch role {
	case "reader":
		return 1
	case "operator":
		return 2
	case "admin":
		return 3
	}
	return 0
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func ValidIdentifier(value string) bool { return identifierPattern.MatchString(value) }
func ValidateIdentifier(value string) error {
	if !ValidIdentifier(value) {
		return fmt.Errorf("expected an approved identifier")
	}
	return nil
}

// NewID returns a cryptographically random RFC 4122 version-4 UUID in hex.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("cryptographic randomness unavailable")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[:])
}
