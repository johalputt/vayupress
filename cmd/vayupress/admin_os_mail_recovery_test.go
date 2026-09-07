// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/vayuos/mail"
	_ "github.com/mattn/go-sqlite3"
)

func cliStore(t *testing.T) (*mail.AccountStore, context.Context) {
	t.Helper()
	db, _ := sql.Open("sqlite3", ":memory:")
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	s, err := mail.NewAccountStore(db)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	ctx := context.Background()
	if err := s.Create(ctx, "user@example.com", "hash", "User", mail.RoleMailbox); err != nil {
		t.Fatalf("create: %v", err)
	}
	return s, ctx
}

// TestBreakGlassStillRevokesAppPasswords is the important one. The break-glass
// path runs when something has already gone wrong, which makes it the last place
// that should cut corners — a reset here that left an attacker's enrolled device
// connected would be worse than useless, because the operator would believe the
// account was secured.
func TestBreakGlassStillRevokesAppPasswords(t *testing.T) {
	t.Parallel()
	s, ctx := cliStore(t)
	if _, err := s.CreateAppPassword(ctx, "user@example.com", "phone", "hashA"); err != nil {
		t.Fatalf("app password: %v", err)
	}
	if _, err := s.CreateAppPassword(ctx, "user@example.com", "laptop", "hashB"); err != nil {
		t.Fatalf("app password: %v", err)
	}
	if n := len(s.AppPasswordCredentials(ctx, "user@example.com")); n != 2 {
		t.Fatalf("setup: %d credentials, want 2", n)
	}

	var out strings.Builder
	if err := runMailCLI(ctx, []string{"passwd", "user@example.com", "a-new-password"}, &out, s); err != nil {
		t.Fatalf("break-glass: %v", err)
	}
	if n := len(s.AppPasswordCredentials(ctx, "user@example.com")); n != 0 {
		t.Errorf("%d app password(s) survived a break-glass reset", n)
	}
	// It must also say what it did NOT do, or an operator assumes sessions and the
	// outbound queue were handled when the server was not even running.
	for _, want := range []string{
		"2 app password(s) revoked",
		"live webmail sessions are not ended",
		"queued outbound mail is not held",
		"audit log",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("break-glass output is missing %q:\n%s", want, out.String())
		}
	}
}

// TestBreakGlassRefusesUnknownMailbox — a typo must not silently succeed and
// leave the operator believing they reset something.
func TestBreakGlassRefusesUnknownMailbox(t *testing.T) {
	t.Parallel()
	s, ctx := cliStore(t)
	var out strings.Builder
	if err := runMailCLI(ctx, []string{"passwd", "nobody@example.com", "a-new-password"}, &out, s); err == nil {
		t.Error("break-glass accepted a mailbox that does not exist")
	}
	if err := runMailCLI(ctx, []string{"passwd", "user@example.com", "short"}, &out, s); err == nil {
		t.Error("break-glass accepted a password below the minimum length")
	}
}

// TestRecoveryCLIReportsHonestly. The whole point of the readiness view is that
// it does not overstate: an account with an unverified address is not covered.
func TestRecoveryCLIReportsHonestly(t *testing.T) {
	t.Parallel()
	s, ctx := cliStore(t)

	var out strings.Builder
	if err := runMailCLI(ctx, []string{"recovery", "user@example.com"}, &out, s); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if !strings.Contains(out.String(), "CANNOT be recovered") {
		t.Errorf("a mailbox with nothing enrolled was not reported as unrecoverable:\n%s", out.String())
	}

	out.Reset()
	if err := runMailCLI(ctx, []string{"unrecoverable"}, &out, s); err != nil {
		t.Fatalf("unrecoverable: %v", err)
	}
	if !strings.Contains(out.String(), "user@example.com") {
		t.Errorf("the unrecoverable list omitted an unenrolled mailbox:\n%s", out.String())
	}

	// Enrol an UNVERIFIED address — still unrecoverable.
	if err := s.SetRecoveryContactPending(ctx, "user@example.com", "a@elsewhere.test", nil); err != nil {
		t.Fatalf("pending: %v", err)
	}
	out.Reset()
	if err := runMailCLI(ctx, []string{"recovery", "user@example.com"}, &out, s); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if !strings.Contains(out.String(), "CANNOT be recovered") {
		t.Errorf("an UNVERIFIED address was reported as recovery:\n%s", out.String())
	}

	// Verify it — now covered.
	if err := s.VerifyRecoveryContact(ctx, "user@example.com"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	out.Reset()
	if err := runMailCLI(ctx, []string{"recovery", "user@example.com"}, &out, s); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if !strings.Contains(out.String(), "can be recovered") {
		t.Errorf("a verified address was not counted:\n%s", out.String())
	}
}

// TestMailCLIRefusesWithoutVayuMail — better a clear message than a nil panic on
// an install where mail was never configured.
func TestMailCLIRefusesWithoutVayuMail(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	if err := runMailCLI(context.Background(), []string{"recovery", "a@b.co"}, &out, nil); err == nil {
		t.Error("the CLI ran against a nil account store")
	}
	if err := runMailCLI(context.Background(), nil, &out, nil); err == nil {
		t.Error("no arguments should print usage as an error")
	}
}

// TestRecoveryConsoleJSNeverUsesInnerHTML. The panel renders mail addresses and
// server error strings, and it is the surface that displays freshly minted
// credentials.
func TestRecoveryConsoleJSNeverUsesInnerHTML(t *testing.T) {
	t.Parallel()
	js := withoutComments(repoFile(t, "static/js/admin-os-mail-recovery.js"))
	if strings.Contains(js, "innerHTML") {
		t.Error("the recovery panel must build nodes with textContent, never innerHTML")
	}
	// Codes exist in readable form exactly once, so two opposing requirements meet
	// here and the first version of this test only checked one of them.
	//
	// Switching mailbox MUST clear them (a previous account's set would be written
	// down against the wrong mailbox) — but the status refresh that runs right
	// after a successful generate must NOT, or the codes are wiped a moment after
	// being shown and the button looks broken. That shipped, and only clicking it
	// found it. So: clearing is bound to the change handler, and renderStatus is
	// asserted not to touch them.
	if !strings.Contains(js, "clearCodes()") {
		t.Error("switching mailbox must clear any codes still on screen")
	}
	// Slice renderStatus by its next SIBLING function rather than by a brace at a
	// guessed indent — the panels moved inside a bindPanel() closure and an
	// indent-sensitive slice silently over-captured into clearCodes, which is
	// meant to contain exactly the line this asserts is absent.
	render := js[strings.Index(js, "function renderStatus"):]
	if i := strings.Index(render, "function clearCodes"); i > 0 {
		render = render[:i]
	}
	if strings.Contains(render, "codesEl.hidden = true") {
		t.Error("renderStatus clears the codes; it runs after generate, so it would wipe them instantly")
	}
	// Regeneration silently invalidates the sheet the holder is carrying.
	// Confirmed through the vpConfirm modal (Wave 3.11), not window.confirm.
	if !strings.Contains(js, "vpConfirm") {
		t.Error("regenerating codes must be confirmed — it revokes the holder's existing sheet")
	}
	if !strings.Contains(js, "X-CSRF-Token") {
		t.Error("credential-issuing writes must carry the CSRF token")
	}
}

// TestRecoveryPanelsBindAfterTheDOMExists. The script tag is emitted by the
// summary card at the TOP of the page, above the mailbox list, so at execution
// time none of the per-card panels exist. Binding immediately found nothing and
// every control on every card stayed dead — which is exactly how this shipped
// once already, and is invisible without running a browser.
func TestRecoveryPanelsBindAfterTheDOMExists(t *testing.T) {
	t.Parallel()
	js := withoutComments(repoFile(t, "static/js/admin-os-mail-recovery.js"))
	if !strings.Contains(js, "DOMContentLoaded") {
		t.Error("binding does not wait for the document; the panels do not exist when this script runs")
	}
	// One panel per mailbox, so it must bind ALL of them.
	if !strings.Contains(js, "querySelectorAll('[data-recovery-panel]')") {
		t.Error("only one panel is bound; an install with many mailboxes would have one working card")
	}
	// The accounts list is swapped wholesale by HTMX on every inline action.
	if !strings.Contains(js, "htmx:afterSwap") {
		t.Error("panels are not rebound after an HTMX swap, so they die on the first alias or forwarding change")
	}
	// Thirty mailboxes must not mean thirty status requests at page load.
	if !strings.Contains(js, "'toggle'") {
		t.Error("status must load when a card is opened, not for every mailbox at page load")
	}
}

// TestRecoveryCodesCanBeSavedWithoutTheClipboard. The clipboard API needs a
// secure context and a permission some browsers refuse; codes are shown exactly
// once, so a failed copy with no alternative loses them for good.
func TestRecoveryCodesCanBeSavedWithoutTheClipboard(t *testing.T) {
	t.Parallel()
	js := withoutComments(repoFile(t, "static/js/admin-os-mail-recovery.js"))
	for _, want := range []string{"Download .txt", "Print", "Blob(", "a.download"} {
		if !strings.Contains(js, want) {
			t.Errorf("no clipboard-free way to keep the codes: missing %q", want)
		}
	}
	// A blob: URL stays resolvable for the life of the document, so leaving it
	// alive keeps the codes fetchable from the tab long after the panel is closed.
	if !strings.Contains(js, "revokeObjectURL") {
		t.Error("the download blob URL is never revoked; the codes stay retrievable from the tab")
	}
	// The saved sheet must identify what it unlocks — a bare list of twelve
	// character strings found later tells its owner nothing.
	if !strings.Contains(js, "function codeSheet") ||
		!strings.Contains(js, "'Mailbox : '") ||
		!strings.Contains(js, "/mail/recover/code") {
		t.Error("the saved sheet must name the mailbox, the server and where the codes are used")
	}
}

// TestHolderCanEnrolTheirOwnRecovery. Recovery that only an administrator can
// enrol is recovery most people never get — the readiness list would stay red
// forever. But a holder must be confined to their own mailbox, and must not be
// able to self-certify a recovery address.
func TestHolderCanEnrolTheirOwnRecovery(t *testing.T) {
	t.Parallel()
	code := withoutComments(repoFile(t, "cmd/vayupress/admin_os_mail_recovery.go"))

	if !strings.Contains(code, "func (a *App) recoveryScope") {
		t.Fatal("there is no scoping helper; the endpoints are either admin-only or unscoped")
	}
	// Every endpoint must scope rather than gate on admin.
	if n := strings.Count(code, "a.recoveryScope(r,"); n < 3 {
		t.Errorf("expected all three endpoints to scope by caller, found %d", n)
	}
	// A holder verifying their own address would defeat the check entirely: they
	// could point recovery anywhere and immediately make it usable.
	if !strings.Contains(code, `action == "verify" && !a.isAdminRequest(r)`) {
		t.Error("a holder can self-verify a recovery address, which is the whole check")
	}
	// The install-wide list names every unrecoverable mailbox — a target list.
	if !strings.Contains(code, `requested == "" && a.isAdminRequest(r)`) {
		t.Error("the install-wide readiness list is not restricted to administrators")
	}
}

// TestRecoveryCardDoesNotOverclaim pins the chip wording. "Recovery enabled"
// would describe the feature while saying nothing about whether any mailbox
// could actually be recovered — the distinction this card exists to make.
func TestRecoveryCardDoesNotOverclaim(t *testing.T) {
	t.Parallel()
	src := repoFile(t, "cmd/vayupress/admin_os_mail_recovery.go")
	code := withoutComments(src)
	if strings.Contains(code, "Recovery enabled") {
		t.Error(`the chip must report how many mailboxes are covered, not that the feature exists`)
	}
	if !strings.Contains(code, "covered") || !strings.Contains(code, "cannot be recovered") {
		t.Error("the chip must state the covered/uncovered counts")
	}
	// The Tor-mode caveat must be surfaced in the console, not just the log.
	if !strings.Contains(code, "safefetch.ClearnetBlocked()") {
		t.Error("the card must tell a Tor-mode operator that codes are the only working factor")
	}
	// Enrolment is a credential-issuing surface; it must be admin-gated.
	if n := strings.Count(code, "a.isAdminRequest(r)"); n < 3 {
		t.Errorf("expected every recovery endpoint to be admin-gated, found %d checks", n)
	}
}
