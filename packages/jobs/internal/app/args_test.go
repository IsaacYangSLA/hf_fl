package app

import (
	"bytes"
	"testing"
	"time"
)

func TestParseAllCommands(t *testing.T) {
	for cmd := range commandDescriptions {
		args := []string{cmd}
		switch cmd {
		case "managed-node", "participant-agent", "runtime":
			args = append(args, "--config", "/etc/hf2l/jobs.json")
		case "admin":
			args = append(args, "project-member", "--project", "p", "--principal", "u", "--role", "submitter")
		}
		a, h, e := Parse(args, &bytes.Buffer{})
		if e != nil || h || a.Command != cmd {
			t.Fatalf("%s: %#v %v", cmd, a, e)
		}
	}
	a, _, e := Parse([]string{"controller", "--once", "--interval", "0.25"}, &bytes.Buffer{})
	if e != nil || !a.Once || a.Interval != 250*time.Millisecond {
		t.Fatal(a, e)
	}
}
func TestHelpDoesNotLoadConfiguration(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"serve", "--help"}, {"runtime", "--help"}, {"admin", "project-create", "--help"}} {
		var b bytes.Buffer
		_, h, e := Parse(args, &b)
		if e != nil || !h || b.Len() == 0 {
			t.Fatal(args, h, e, b.String())
		}
	}
}
func TestMalformedArgumentsRejected(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown"}, {"serve", "--unknown"}, {"serve", "extra"}, {"serve", "--port", "0"}, {"controller", "--interval", "0"}, {"controller", "--interval", "NaN"}, {"runtime"}, {"managed-node"}, {"participant-agent"}, {"admin"}, {"admin", "project-member", "--project", "p", "--principal", "u", "--role", "reader"}, {"admin", "project-create", "--id", "p"}, {"admin", "pool-set"}} {
		if _, _, e := Parse(args, &bytes.Buffer{}); e == nil {
			t.Fatal(args)
		}
	}
}
func TestAdminExplicitUpdateFields(t *testing.T) {
	a, _, e := Parse([]string{"admin", "--config", "config.json", "project-update", "--id", "p", "--retention-days", "0"}, &bytes.Buffer{})
	if e != nil || a.Values["retention_days"] != int64(0) {
		t.Fatal(a, e)
	}
	if _, exists := a.Values["name"]; exists {
		t.Fatal("unspecified name became mutation")
	}
}
