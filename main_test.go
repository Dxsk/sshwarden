package main

import (
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in, host, user, port string
	}{
		{"pve1.example.com", "pve1.example.com", "", ""},
		{"ssh key ops pve1.example.com", "pve1.example.com", "", ""},
		{"prod pve1.example.com root", "pve1.example.com", "", ""},
		{"debian@mtmg.example.com", "mtmg.example.com", "debian", ""},
		{"prod root@pve1.example.com", "pve1.example.com", "root", ""},
		{"db admin@10.0.0.5", "10.0.0.5", "admin", ""},            // IP literal with user
		{"debian@host.fr:2222", "host.fr", "debian", "2222"},      // user + port
		{"host.fr:2222", "host.fr", "", "2222"},                   // port only
		{"ops admin@10.0.0.5:22 prod", "10.0.0.5", "admin", "22"}, // IP + user + port
		{"ansible", "", "", ""},
		{"shared key", "", "", ""},
		{".hidden", "", "", ""},                    // dots trimmed, no inner dot
		{"deploy v1.2 server", "", "", ""},         // version string, numeric TLD
		{"backup 1.0.3 build", "", "", ""},         // version string
		{"deploy ../../tmp/pwn.com x", "", "", ""}, // path separators rejected
	}
	for _, c := range cases {
		host, user, port := parseTarget(c.in)
		if host != c.host || user != c.user || port != c.port {
			t.Errorf("parseTarget(%q) = (%q, %q, %q), want (%q, %q, %q)", c.in, host, user, port, c.host, c.user, c.port)
		}
	}
}

func TestSkipKey(t *testing.T) {
	skip := map[string]bool{
		"backup [nobwsshd] old":       true,
		"[nobwsshd]":                  true,
		"debian@mtmg.example.com":        false,
		"pve1.example.com [nobwsshd]": true,
		"nobwsshd":                    false, // needs the brackets
	}
	for in, want := range skip {
		if got := skipKey(in); got != want {
			t.Errorf("skipKey(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize(" my key/name "); got != "my_key_name" {
		t.Errorf("sanitize = %q", got)
	}
	// Even if a host slipped through, the filename must never keep separators.
	if got := sanitize("/../../../tmp/pwn.com"); strings.ContainsAny(got, "/\\") {
		t.Errorf("sanitize left path separators: %q", got)
	}
}
