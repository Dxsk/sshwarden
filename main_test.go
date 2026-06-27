package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// blob returns a valid ed25519 public-key blob, so agent.Key.String() and
// FingerprintSHA256 behave like a real agent key.
func blob(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pk.Marshal()
}

func key(t *testing.T, comment string) *agent.Key {
	b := blob(t)
	return &agent.Key{Format: ssh.KeyAlgoED25519, Blob: b, Comment: comment}
}

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
		"debian@mtmg.example.com":     false,
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

// Issue #1: a rename (same blob, different comment) must change the fingerprint,
// or watch mode never regenerates.
func TestFingerprintIncludesComment(t *testing.T) {
	b := blob(t)
	k1 := &agent.Key{Format: ssh.KeyAlgoED25519, Blob: b, Comment: "prod"}
	k2 := &agent.Key{Format: ssh.KeyAlgoED25519, Blob: b, Comment: "debian@host.fr:2222"}
	if fingerprint([]*agent.Key{k1}) == fingerprint([]*agent.Key{k2}) {
		t.Error("fingerprint ignores Comment; key rename would be invisible in watch mode")
	}
}

func TestGenerateHostBlock(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.bw")
	keydir := filepath.Join(dir, "keys")
	if err := generate([]*agent.Key{key(t, "debian@host.fr:2222")}, out, keydir, "/sock"); err != nil {
		t.Fatal(err)
	}
	cfg := read(t, out)
	for _, want := range []string{"Host host.fr", "HostName host.fr", "User debian", "Port 2222", "IdentitiesOnly yes"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
	if _, err := os.Stat(filepath.Join(keydir, "host.fr.pub")); err != nil {
		t.Errorf("expected host.fr.pub: %v", err)
	}
}

// Issue #3: two keys on the same host -> first wins, one block, one .pub.
func TestGenerateDuplicateHost(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.bw")
	keydir := filepath.Join(dir, "keys")
	keys := []*agent.Key{key(t, "host.fr"), key(t, "root@host.fr")}
	if err := generate(keys, out, keydir, "/sock"); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(read(t, out), "Host host.fr\n"); n != 1 {
		t.Errorf("want 1 Host block, got %d", n)
	}
	pubs, _ := filepath.Glob(filepath.Join(keydir, "*.pub"))
	if len(pubs) != 1 {
		t.Errorf("want 1 .pub, got %v", pubs)
	}
}

// Issue #3: distinct unmapped keys whose names collide get a -2 suffix, no clobber.
func TestGenerateFilenameCollision(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.bw")
	keydir := filepath.Join(dir, "keys")
	keys := []*agent.Key{key(t, "shared one"), key(t, "shared/one")}
	if err := generate(keys, out, keydir, "/sock"); err != nil {
		t.Fatal(err)
	}
	pubs, _ := filepath.Glob(filepath.Join(keydir, "*.pub"))
	if len(pubs) != 2 {
		t.Errorf("want 2 distinct .pub files, got %v", pubs)
	}
}

// Issue #3: a hostname-less key is written and listed for a manual Host block.
func TestGenerateUnmapped(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.bw")
	keydir := filepath.Join(dir, "keys")
	if err := generate([]*agent.Key{key(t, "ansible")}, out, keydir, "/sock"); err != nil {
		t.Fatal(err)
	}
	cfg := read(t, out)
	if !strings.Contains(cfg, "manual Host") || !strings.Contains(cfg, `"ansible"`) {
		t.Errorf("unmapped key not listed:\n%s", cfg)
	}
}

// Issue #3: ensureKeydir refuses a non-empty unmanaged dir and a symlink.
func TestEnsureKeydirGuards(t *testing.T) {
	used := filepath.Join(t.TempDir(), "keys")
	os.MkdirAll(used, 0700)
	os.WriteFile(filepath.Join(used, "id_ed25519"), []byte("x"), 0600)
	if err := ensureKeydir(used); err == nil {
		t.Error("ensureKeydir accepted a non-empty unmanaged dir")
	}

	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(t.TempDir(), link)
	if err := ensureKeydir(link); err == nil {
		t.Error("ensureKeydir accepted a symlink")
	}
}

// Issue #3: clean removes a marked keydir but spares an unmanaged one.
func TestCleanKeydirGuard(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.bw")

	owned := filepath.Join(dir, "owned")
	os.MkdirAll(owned, 0700)
	os.WriteFile(filepath.Join(owned, keydirMarker), nil, 0600)
	if err := clean(out, owned); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Error("clean did not remove a marked keydir")
	}

	foreign := filepath.Join(dir, "foreign")
	os.MkdirAll(foreign, 0700)
	os.WriteFile(filepath.Join(foreign, "id_ed25519"), []byte("x"), 0600)
	if err := clean(out, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(foreign, "id_ed25519")); err != nil {
		t.Error("clean removed an unmanaged keydir")
	}
}

// Issue #3 + #5: ensureInclude prepends once, is idempotent, and does not
// false-match a different file sharing the same basename.
func TestEnsureInclude(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	out := filepath.Join(dir, "config.automatic.bw")

	if err := ensureInclude(cfg, out); err != nil {
		t.Fatal(err)
	}
	first := read(t, cfg)
	if strings.Count(first, "Include ") != 1 {
		t.Fatalf("want 1 Include, got:\n%s", first)
	}
	if err := ensureInclude(cfg, out); err != nil {
		t.Fatal(err)
	}
	if read(t, cfg) != first {
		t.Error("ensureInclude not idempotent")
	}

	// A same-basename Include of a different file must not suppress ours (#5).
	dir2 := t.TempDir()
	cfg2 := filepath.Join(dir2, "config")
	os.WriteFile(cfg2, []byte("Include /somewhere/else/config.automatic.bw\n"), 0600)
	if err := ensureInclude(cfg2, out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, cfg2), "Include "+out) {
		t.Error("ensureInclude false-matched a different file by basename")
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
