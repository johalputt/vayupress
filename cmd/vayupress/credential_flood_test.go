// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/members"
	"github.com/johalputt/vayupress/internal/users"
	vmail "github.com/johalputt/vayupress/internal/vayuos/mail"
)

// Two audit findings, both about the same thing: a public endpoint that spends
// the server's Argon2id budget on a stranger's say-so, with nothing counting.
//
//	POST /api/v1/members/vayumail-login — mail addresses are public by design
//	(WKD, autoconfig, the avatar endpoint), so I do not need to guess who exists.
//	This handler had no throttle, no lockout and no limiter, while its three
//	siblings in the same file all had one. I guessed passwords against every
//	mailbox on the install at whatever rate the box could hash, and because the
//	failures were never recorded, the operator's mail-side brute-force counter
//	stayed clean the whole time.
//
//	POST /api/v1/members/login — and when I got bored of guessing, I pointed the
//	install's own mailer at a victim. Unauthenticated, unmetered, DKIM-signed
//	with the operator's domain. A few thousand of those and the domain is
//	blocklisted, which takes the entire mail product down with it.
//
// The Argon2id ceiling is the third control and the one that bounds the damage
// either way: 64 MiB and every core per derivation, with the anti-enumeration
// decoy forcing a full run even for addresses that do not exist.

// ---------------------------------------------------------------------------
// The per-IP lockout on the mailbox login
// ---------------------------------------------------------------------------

func postVayuMailLogin(t *testing.T, a *App, ip, email, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/members/vayumail-login",
		strings.NewReader(`{"email":"`+email+`","password":"`+pass+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	a.handleMemberVayuMailLogin(rec, req)
	return rec
}

func TestMailboxLoginLocksOutASourceThatKeepsGuessing(t *testing.T) {
	a := credentialFloodApp(t)
	const ip = "198.51.100.44"

	var refused int
	for i := 0; i < 12; i++ {
		rec := postVayuMailLogin(t, a, ip, "boss@example.com", "guess-number-"+string(rune('a'+i)))
		if rec.Code == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused == 0 {
		t.Error("twelve wrong passwords from one address were all answered normally.\n\n" +
			"Mail addresses on this install are published by WKD and autoconfig, so an attacker " +
			"does not have to find the mailboxes — only the passwords. Nothing here is counting, " +
			"and because the failures are not recorded the IMAP/SMTP throttle stays clean too.")
	}
}

// The lockout must not spill onto the other two surfaces that read the SAME
// package-global bucket map.
//
// auth.CheckAuthLockout is consulted by RequireAPIKey — which fronts the entire
// /api/v1 key group — and by /os/login. Keying webmail failures on the bare
// address would mean five wrong passwords here lock that source out of the REST
// API for an hour, and a stale API key failing five times locks the same source
// out of webmail. On an install behind a CDN, where the real visitor address
// does not resolve, every reader shares the edge address: five failures from
// anyone, anywhere, would lock the whole audience out of all three surfaces.
//
// This is the mutation-killer for the "portal:" prefix, and it was added because
// removing that prefix passed every other test in this file.
func TestMailboxLoginLockoutDoesNotSpillOntoTheAPIOrTheConsole(t *testing.T) {
	a := credentialFloodApp(t)
	const ip = "198.51.100.46"

	for i := 0; i < 12; i++ {
		postVayuMailLogin(t, a, ip, "boss@example.com", "wrong")
	}
	if locked, _ := auth.CheckAuthLockout("portal:" + ip); !locked {
		t.Fatal("twelve wrong passwords did not lock the portal surface, so the rest of this " +
			"test proves nothing")
	}
	if locked, until := auth.CheckAuthLockout(ip); locked {
		t.Errorf("failed WEBMAIL sign-ins locked the bare address until %s.\n\n"+
			"That bucket is read by RequireAPIKey for the whole /api/v1 key group and by "+
			"/os/login. Behind a CDN every reader shares one address, so five typos from a "+
			"stranger take the operator's API integrations and console login down with them.",
			until.Format("15:04:05"))
	}
}

// The control, and it matters more than the test above: an install where a
// wrong password once locks the mailbox out is worse than the flood. The
// lockout is keyed on the SOURCE, so a second person on a different address
// must be unaffected by the first one's mistakes.
func TestMailboxLoginLockoutDoesNotPunishABystander(t *testing.T) {
	a := credentialFloodApp(t)
	const attacker, honest = "198.51.100.45", "203.0.113.77"

	for i := 0; i < 12; i++ {
		postVayuMailLogin(t, a, attacker, "boss@example.com", "wrong")
	}
	if rec := postVayuMailLogin(t, a, honest, "boss@example.com", "also-wrong"); rec.Code == http.StatusTooManyRequests {
		t.Error("someone else's failed attempts locked out an unrelated address.\n\n" +
			"That turns the control into the outage: anyone can lock every reader out of " +
			"sign-in by guessing badly on purpose.")
	}
}

// And a correct password must still work, or the fix is an outage with a
// security rationale.
func TestMailboxLoginStillAcceptsTheRightPassword(t *testing.T) {
	a := credentialFloodApp(t)
	const ip = "203.0.113.90"

	rec := postVayuMailLogin(t, a, ip, "boss@example.com", "the-password-the-attacker-stole")
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusTooManyRequests {
		t.Fatalf("a valid mailbox credential was refused (%d) — sign-in is broken.\n\nbody: %s",
			rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// The magic-link budget
// ---------------------------------------------------------------------------

func postMemberLogin(t *testing.T, a *App, ip, email string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/members/login",
		strings.NewReader(`{"email":"`+email+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	a.handleMemberLogin(rec, req)
	return rec
}

// countLoginTokens is the assertion that matters. The response is deliberately
// identical whether the request was served or dropped — a 429 here would be a
// member-enumeration oracle — so the only honest way to tell is to count what
// the request actually caused.
func countLoginTokens(t *testing.T, a *App, email string) int {
	t.Helper()
	var n int
	if err := dbpkg.DB.QueryRow(
		`SELECT COUNT(*) FROM member_login_tokens WHERE email=?`, email).Scan(&n); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	return n
}

func TestMagicLinkFloodIsBoundedPerAddress(t *testing.T) {
	a := credentialFloodApp(t)

	// Twenty requests aimed at one victim, each from a DIFFERENT source, which is
	// what a botnet or a rotating proxy looks like and what the installer's
	// per-IP nginx limit cannot see.
	for i := 0; i < 20; i++ {
		postMemberLogin(t, a, "192.0.2."+strconv.Itoa(i+1), "victim@elsewhere.test")
	}

	n := countLoginTokens(t, a, "victim@elsewhere.test")
	if n > 5 {
		t.Errorf("%d magic links were issued to one address from 20 different sources.\n\n"+
			"Each one is a real message, DKIM-signed by the operator's domain, sent to someone "+
			"who did not ask for it. The address budget is what stops a distributed flood "+
			"aimed at a single victim, and the per-IP limit cannot: every request came from "+
			"a different IP.", n)
	}
}

func TestMagicLinkFloodIsBoundedPerSource(t *testing.T) {
	a := credentialFloodApp(t)
	const ip = "192.0.2.200"

	// One host walking a list. The per-address budget never fires — every address
	// is fresh — so only the per-source budget can stop this.
	//
	// The count is well above the budget on purpose. That budget is deliberately
	// generous (see memberLoginByIP): on an install behind a CDN, or in a Tor
	// Space where every reader arrives as 127.0.0.1, this key is the whole
	// audience, and a tight per-source limit would silently ration real people.
	// What has to hold is that walking a list terminates — not that it terminates
	// on the tenth address.
	const walk = 200
	issued := 0
	for i := 0; i < walk; i++ {
		addr := "target" + strconv.Itoa(i) + "@elsewhere.test"
		postMemberLogin(t, a, ip, addr)
		issued += countLoginTokens(t, a, addr)
	}
	if issued >= walk {
		t.Errorf("one source made this install send %d unsolicited messages to %d different "+
			"addresses, refusing none of them.\n\nThat is the operator's domain doing the "+
			"sending, and the fastest available route to having it blocklisted.", issued, walk)
	}
}

// The control: an ordinary person asking for a sign-in link must get one.
func TestMagicLinkStillWorksForAnHonestRequest(t *testing.T) {
	a := credentialFloodApp(t)

	rec := postMemberLogin(t, a, "203.0.113.5", "reader@elsewhere.test")
	if rec.Code != http.StatusOK {
		t.Fatalf("a first magic-link request got %d, want 200", rec.Code)
	}
	if countLoginTokens(t, a, "reader@elsewhere.test") != 1 {
		t.Error("no login token was created for a first, entirely ordinary request — " +
			"the budget is refusing people who have done nothing")
	}
}

// A refusal must be INVISIBLE. If a throttled request answered differently from
// a served one, this endpoint would become the member-enumeration oracle its own
// comment says it must never be.
func TestMagicLinkRefusalIsIndistinguishable(t *testing.T) {
	a := credentialFloodApp(t)
	const ip = "203.0.113.6"

	first := postMemberLogin(t, a, ip, "reader2@elsewhere.test")
	var last *httptest.ResponseRecorder
	for i := 0; i < 12; i++ {
		last = postMemberLogin(t, a, ip, "reader2@elsewhere.test")
	}
	if last.Code != first.Code || last.Body.String() != first.Body.String() {
		t.Errorf("a throttled request answers differently from a served one:\n"+
			"  served:    %d %s\n  throttled: %d %s\n\n"+
			"That difference is readable by anyone, and it turns the budget into an oracle.",
			first.Code, first.Body.String(), last.Code, last.Body.String())
	}
}

// credentialFloodApp gives every test its own database, mail engine, member
// store and mailer sink. Per-test isolation is not tidiness here: the budgets
// under test are package-level and keyed on address and source, so tests that
// shared either would spend one another's allowance and fail in a full run
// while passing alone.
func credentialFloodApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DB_PATH", filepath.Join(dir, "flood.db"))
	t.Setenv("API_KEY", "test-key")
	t.Setenv("DOMAIN", "example.com")
	t.Setenv("CACHE_DIR", dir)
	config.Load()
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	// ClosePools first: on Windows the pool connections keep flood.db open and
	// the t.TempDir RemoveAll fails after the assertions have already passed.
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
	})

	cfg := vmail.DefaultConfig()
	cfg.Enabled = true
	cfg.Domain = "example.com"
	cfg.Hostname = "mail.example.com"
	cfg.StorageDir = dir
	cfg.InboundEnabled = false
	e := vmail.NewEngine(&cfg, nil, dbpkg.DB)
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { _ = e.Stop(context.Background()) })

	hash, err := auth.HashSecretArgon2id("the-password-the-attacker-stole")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := e.Accounts().Create(context.Background(),
		"boss@example.com", hash, "Boss", "mailbox"); err != nil {
		t.Fatalf("seed mailbox: %v", err)
	}
	return &App{
		vayuMail:  e,
		sessions:  auth.NewSessionStore(dbpkg.DB),
		userStore: users.New(dbpkg.DB),
		members:   members.New(dbpkg.DB),
	}
}

// ---------------------------------------------------------------------------
// The gap the Section 1 fix left, found by the Section 2 audit.
// ---------------------------------------------------------------------------
//
// In the attacker's voice:
//
//	Your Section 1 fix put a per-source lockout on /vayumail-login. Fine. I
//	spray /vayumail-device-register instead.
//
//	It takes the same raw mailbox password — deliberately, because it is the
//	bootstrap that turns a password into a device. verifyCredentialScoped says
//	so itself: "Web-bootstrap scope keeps accepting it so a new device can
//	register." Its only defence is mailAuthThrottle, which is keyed per MAILBOX
//	and capped at two seconds, so spraying one guess across many mailboxes
//	never touches it. No per-IP lockout, no route limiter, and /api is in
//	shieldBypassPrefixes so VayuShield never sees me either.
//
// The route comment claimed otherwise — "Same throttle + uniform-401
// anti-enumeration as vayumail-login above" — and that claim is why the
// endpoint was skipped when the lockout was added. A comment asserting parity
// is not parity.
//
// The lockout deliberately shares the "portal:" namespace with vayumail-login:
// a wrong mailbox password from one address is the same fact whichever endpoint
// carried it, and separate counters would hand a sprayer a fresh budget per
// endpoint.

func postDeviceRegister(t *testing.T, a *App, ip, email, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/members/vayumail-device-register",
		strings.NewReader(`{"email":"`+email+`","password":"`+pass+`","device_name":"phone","platform":"android"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	a.handleMemberVayuMailDeviceRegister(rec, req)
	return rec
}

func TestDeviceRegisterLocksOutASourceThatKeepsGuessing(t *testing.T) {
	a := credentialFloodApp(t)
	const ip = "198.51.100.60"

	refused := 0
	for i := 0; i < 12; i++ {
		if postDeviceRegister(t, a, ip, "boss@example.com", "guess"+strconv.Itoa(i)).Code == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused == 0 {
		t.Error("twelve wrong mailbox passwords at device-register from one address were all " +
			"answered normally.\n\nThis endpoint accepts the raw mailbox password by design, and " +
			"the per-mailbox throttle does not see a spray across many mailboxes. Closing " +
			"/vayumail-login alone just moves the attack one route over.")
	}
}

// The counters must be SHARED with the webmail login, or alternating between the
// two endpoints doubles the attacker's budget.
func TestDeviceRegisterSharesItsLockoutWithTheWebmailLogin(t *testing.T) {
	a := credentialFloodApp(t)
	const ip = "198.51.100.61"

	for i := 0; i < 12; i++ {
		postDeviceRegister(t, a, ip, "boss@example.com", "wrong")
	}
	if rec := postVayuMailLogin(t, a, ip, "boss@example.com", "wrong"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("after being locked out at device-register, the same address was served at "+
			"vayumail-login (%d).\n\nSeparate counters mean a sprayer alternates endpoints and "+
			"gets a fresh budget on each.", rec.Code)
	}
}

// The control: enrolling a device with the CORRECT password is the VayuMail
// mobile app's entire onboarding flow. It must still work.
func TestDeviceRegisterStillEnrolsWithTheRightPassword(t *testing.T) {
	a := credentialFloodApp(t)
	rec := postDeviceRegister(t, a, "203.0.113.120", "boss@example.com", "the-password-the-attacker-stole")
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusTooManyRequests {
		t.Fatalf("a valid mailbox credential was refused at device-register (%d) — the mobile "+
			"app cannot onboard.\n\nbody: %s", rec.Code, rec.Body.String())
	}
}
