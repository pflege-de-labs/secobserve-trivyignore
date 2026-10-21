package main

import (
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	ok := CLI{RefreshInterval: time.Minute, MaxStaleness: time.Hour, AllowedOwners: []string{"a"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*CLI){
		"interval": func(c *CLI) { c.RefreshInterval = 0 },
		"stale":    func(c *CLI) { c.MaxStaleness = -1 },
		"owners":   func(c *CLI) { c.AllowedOwners = nil },
	} {
		c := ok
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
