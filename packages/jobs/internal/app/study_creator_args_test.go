package app

import (
	"bytes"
	"testing"
)

func TestStudyCreatorGrantArguments(t *testing.T) {
	for _, value := range []string{"true", "false"} {
		a, h, e := Parse([]string{"admin", "study-creator-set", "--principal", "stable-account", "--enabled=" + value}, &bytes.Buffer{})
		if e != nil || h || a.Operation != "study-creator-set" || a.Values["principal"] != "stable-account" || a.Values["enabled"] != (value == "true") {
			t.Fatal(a, h, e)
		}
	}
	for _, args := range [][]string{{"admin", "study-creator-set", "--principal", "stable-account"}, {"admin", "study-creator-set", "--enabled=true"}, {"admin", "study-creator-set", "--principal", "stable-account", "--enabled=maybe"}, {"admin", "study-creator-set", "--principal", "stable-account", "--enabled=true", "--role", "admin"}} {
		if _, _, e := Parse(args, &bytes.Buffer{}); e == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
