// bwsshd keeps an ssh_config in sync with the SSH keys held by the
// Bitwarden desktop SSH agent. It pins exactly one key per host via
// IdentitiesOnly so SSH offers the right key first and doesn't burn through
// MaxAuthTries trying every key in the agent.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	log.SetPrefix("bwsshd: ")
	log.SetFlags(0) // journald already timestamps each line

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	sock := flag.String("sock", "", "SSH agent socket; empty = auto-discover (native/flatpak/snap)")
	out := flag.String("out", filepath.Join(home, ".ssh/config.automatic.bw"), "generated ssh_config file")
	keydir := flag.String("keydir", filepath.Join(home, ".ssh/bwsshd-keys"), "where public keys are written")
	sshConfig := flag.String("ssh-config", filepath.Join(home, ".ssh/config"), "ssh_config to add the Include line to")
	watch := flag.Bool("watch", false, "loop instead of a single run")
	interval := flag.Duration("interval", 10*time.Second, "poll interval in watch mode")
	flag.Parse()

	// Running as root would write keys and config owned by root in the user's
	// ~/.ssh and defeats the whole point. Refuse it.
	if os.Geteuid() == 0 {
		log.Fatal("refusing to run as root; run as your own user")
	}

	if err := ensureInclude(*sshConfig, *out); err != nil {
		log.Fatal(err)
	}

	cands := candidateSocks(*sock, home)

	if !*watch {
		if _, err := sync(cands, *out, *keydir, ""); err != nil {
			log.Fatal(err)
		}
		return
	}

	if *interval <= 0 {
		log.Fatal("interval must be > 0")
	}

	log.Printf("watching for the Bitwarden agent socket every %s", *interval)
	last := ""
	for {
		state, err := sync(cands, *out, *keydir, last)
		if err != nil {
			log.Print(err)
		} else {
			last = state
		}
		time.Sleep(*interval)
	}
}

const stateAbsent = "absent"

// candidateSocks returns the socket paths to try, in order. An explicit -sock
// (or BW_SSH_SOCK / BITWARDEN_SSH_AUTH_SOCK env) wins; otherwise we auto-discover
// the Bitwarden desktop socket across native, Flatpak and Snap installs — the
// agent socket is created by the desktop client, so a Vaultwarden backend uses
// the same paths.
func candidateSocks(explicit, home string) []string {
	if explicit != "" {
		return []string{explicit}
	}
	var c []string
	for _, e := range []string{"BW_SSH_SOCK", "BITWARDEN_SSH_AUTH_SOCK"} {
		if v := os.Getenv(e); v != "" {
			c = append(c, v)
		}
	}
	return append(c,
		filepath.Join(home, ".bitwarden-ssh-agent.sock"),                                     // native / deb / rpm
		filepath.Join(home, ".var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock"), // flatpak
		filepath.Join(home, "snap/bitwarden/current/.bitwarden-ssh-agent.sock"),              // snap
	)
}

// sync reconciles the config with the agent. It only writes when the observed
// state differs from last, so the watch loop doesn't churn files every tick.
func sync(candidates []string, out, keydir, last string) (string, error) {
	keys, sock, present := probe(candidates)

	state := stateAbsent
	if present {
		state = sock + "|" + fingerprint(keys) // sock in the key so switching install regenerates
	}
	if state == last {
		return state, nil
	}
	if !present {
		return state, clean(out, keydir)
	}
	return state, generate(keys, out, keydir, sock)
}

// probe tries each candidate socket and returns the first that answers, along
// with the path that worked (needed for the IdentityAgent line). present=false
// when none respond (Bitwarden closed or still starting).
func probe(candidates []string) (keys []*agent.Key, sock string, present bool) {
	for _, s := range candidates {
		if _, err := os.Stat(s); err != nil {
			continue
		}
		conn, err := net.Dial("unix", s)
		if err != nil {
			continue
		}
		ks, err := agent.NewClient(conn).List()
		conn.Close()
		if err != nil {
			continue
		}
		return ks, s, true
	}
	return nil, "", false
}

// fingerprint is a stable signature of the key set, used for change detection.
func fingerprint(keys []*agent.Key) string {
	fps := make([]string, 0, len(keys))
	for _, k := range keys {
		// Comment carries host/user/port and [nobwsshd]; a rename must regenerate.
		fps = append(fps, ssh.FingerprintSHA256(k)+"\x00"+k.Comment)
	}
	sort.Strings(fps)
	return "present:" + strings.Join(fps, ",")
}

// generate writes one .pub per key and a Host block per key whose Bitwarden
// name carries a hostname. Keys with no hostname are written and listed as
// comments for a manual Host block. Stale .pub files are removed.
func generate(keys []*agent.Key, out, keydir, sock string) error {
	if err := ensureKeydir(keydir); err != nil {
		return err
	}

	// Stable order so "first key wins" on a duplicate host is deterministic.
	sort.Slice(keys, func(i, j int) bool {
		return ssh.FingerprintSHA256(keys[i]) < ssh.FingerprintSHA256(keys[j])
	})

	var b strings.Builder
	b.WriteString("# Generated by bwsshd. Do not edit; changes are overwritten.\n\n")

	written := map[string]bool{}
	seenHost := map[string]bool{}
	var unmapped []string
	hosts := 0

	for _, k := range keys {
		if skipKey(k.Comment) {
			continue
		}

		host, user, port := parseTarget(k.Comment)

		if host != "" && seenHost[host] {
			log.Printf("multiple keys map to host %s; keeping the first, ignoring %q", host, k.Comment)
			continue
		}

		base := sanitize(host)
		if base == "" {
			base = sanitize(k.Comment)
		}
		if base == "" {
			base = "key"
		}
		// Never clobber another key's .pub when filenames collide.
		name := base
		for i := 2; written[name+".pub"]; i++ {
			name = fmt.Sprintf("%s-%d", base, i)
		}

		pub := filepath.Join(keydir, name+".pub")
		if err := writeFile(pub, []byte(k.String()+"\n"), 0600); err != nil {
			return err
		}
		written[name+".pub"] = true

		if host != "" {
			seenHost[host] = true
			hosts++
			fmt.Fprintf(&b, "Host %s\n    HostName %s\n", host, host)
			if user != "" {
				fmt.Fprintf(&b, "    User %s\n", user)
			}
			if port != "" {
				fmt.Fprintf(&b, "    Port %s\n", port)
			}
			fmt.Fprintf(&b, "    IdentityAgent %s\n    IdentityFile %s\n    IdentitiesOnly yes\n\n", sock, pub)
		} else {
			unmapped = append(unmapped, fmt.Sprintf("%q -> %s", k.Comment, pub))
		}
	}

	if len(unmapped) > 0 {
		b.WriteString("# Keys with no hostname in their Bitwarden name. Add a manual Host\n")
		b.WriteString("# block referencing the .pub below:\n")
		for _, u := range unmapped {
			fmt.Fprintf(&b, "#   %s\n", u)
		}
	}

	if err := writeFile(out, []byte(b.String()), 0600); err != nil {
		return err
	}

	// Drop .pub files for keys no longer in the agent (the marker isn't *.pub).
	matches, _ := filepath.Glob(filepath.Join(keydir, "*.pub"))
	for _, m := range matches {
		if !written[filepath.Base(m)] {
			os.Remove(m)
		}
	}
	log.Printf("wrote %s: %d host(s), %d key(s) without a hostname", out, hosts, len(unmapped))
	return nil
}

// ensureInclude prepends an Include of the generated file to sshConfig so plain
// `ssh host` picks up the per-host blocks. It goes at the top because SSH is
// first-match-wins for IdentityFile/User/etc. It is idempotent.
func ensureInclude(sshConfig, out string) error {
	abs, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(sshConfig)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, l := range strings.Split(string(data), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || !strings.EqualFold(f[0], "Include") {
			continue
		}
		// Include can list several files; compare each by absolute path so a
		// same-basename include of a different file isn't a false match.
		for _, inc := range f[1:] {
			if p, err := filepath.Abs(inc); err == nil && p == abs {
				return nil // already included
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(sshConfig), 0700); err != nil {
		return err
	}
	body := "# Added by bwsshd\nInclude " + abs + "\n\n" + string(data)
	log.Printf("added Include %s to %s", abs, sshConfig)
	return writeFile(sshConfig, []byte(body), 0600)
}

const keydirMarker = ".bwsshd"

// ensureKeydir creates keydir and marks it as managed by bwsshd so clean can
// safely wipe the whole directory. It refuses to claim a directory that already
// holds unrelated files (e.g. -keydir ~/.ssh), which is what prevents deleting
// the user's own keys.
func ensureKeydir(dir string) error {
	// A symlinked keydir would make the later RemoveAll delete the link target.
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("keydir %s is a symlink; refusing to use it", dir)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	marker := filepath.Join(dir, keydirMarker)
	if _, err := os.Stat(marker); err == nil {
		return nil // already ours
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("keydir %s is not empty and not managed by bwsshd; refusing to use it", dir)
	}
	return writeFile(marker, []byte("Managed by bwsshd; this directory is removed when the agent socket is gone.\n"), 0600)
}

// clean is run when the agent is gone: empty the config so SSH's Include never
// breaks on a missing file, and remove the whole keydir, but only if we own it.
func clean(out, keydir string) error {
	if err := writeFile(out, []byte("# bwsshd: Bitwarden SSH agent socket absent, no keys offered.\n"), 0600); err != nil {
		return err
	}
	// Only wipe a real directory we own (marker present), never through a symlink.
	fi, err := os.Lstat(keydir)
	owned := err == nil && fi.Mode().IsDir()
	if _, merr := os.Stat(filepath.Join(keydir, keydirMarker)); owned && merr == nil {
		if err := os.RemoveAll(keydir); err != nil {
			return err
		}
	}
	log.Printf("agent socket absent, cleared %s", out)
	return nil
}

// skipKey reports whether a Bitwarden key name opts out of bwsshd.
func skipKey(comment string) bool {
	return strings.Contains(comment, "[nobwsshd]")
}

// parseTarget returns the host plus optional login user and port from the first
// token shaped like "[user@]host[:port]". "debian@mtmg.example.com:2222" ->
// ("mtmg.example.com", "debian", "2222"); "prod pve1.example.com" ->
// ("pve1.example.com", "", ""). Version-like tokens ("v1.2") are ignored: a real
// domain ends in an alphabetic TLD.
func parseTarget(comment string) (host, user, port string) {
	for _, f := range strings.Fields(comment) {
		f = strings.Trim(f, ".")
		u, hp := "", f
		if at := strings.LastIndex(f, "@"); at >= 0 {
			u, hp = f[:at], f[at+1:]
		}
		h, p := splitHostPort(hp)
		if looksLikeHost(h) {
			return h, u, p
		}
	}
	return "", "", ""
}

// splitHostPort separates a trailing numeric ":port" (or "[ipv6]:port") from
// host, leaving a bare IPv6 literal untouched.
func splitHostPort(s string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil && isDigits(p) {
		return h, p
	}
	return s, ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// looksLikeHost accepts an IP literal, or a dotted name whose last label (TLD)
// is alphabetic. That rejects version strings like "v1.2" or "1.0.3".
func looksLikeHost(s string) bool {
	if strings.ContainsAny(s, "/\\ ") {
		return false // not a hostname; also blocks path-traversal in derived filenames
	}
	if net.ParseIP(s) != nil {
		return true
	}
	dot := strings.LastIndex(s, ".")
	if dot < 0 {
		return false
	}
	tld := s[dot+1:]
	if tld == "" {
		return false
	}
	for _, r := range tld {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

// sanitize keeps a comment usable as a filename.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, strings.TrimSpace(s))
}

// writeFile writes data atomically: a temp file in the same dir, chmod'd to perm
// before the rename, so the visible file is never partially written nor briefly
// world-readable, and a crash never truncates an existing file (e.g. ~/.ssh/config).
func writeFile(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bwsshd-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
