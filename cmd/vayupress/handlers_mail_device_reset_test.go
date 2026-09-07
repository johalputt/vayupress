// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/vayuos/mail"
	_ "github.com/mattn/go-sqlite3"
)

// testTime is a fixed clock so notice wording is compared, not timestamps.
func testTime() time.Time { return time.Date(2026, 7, 26, 14, 22, 0, 0, time.UTC) }

// Trusted-device recovery turns an app password into a password-reset
// credential, which raises its value considerably. These tests are about the
// three ways that could go wrong: accepting a credential that should not count,
// leaving the initiating device connected, and leaking which mailboxes exist.

func deviceStore(t *testing.T) (*mail.AccountStore, context.Context) {
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

func addDevice(t *testing.T, s *mail.AccountStore, ctx context.Context, label, secret, status string) int64 {
	t.Helper()
	h, err := auth.HashSecretArgon2id(secret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	id, err := s.CreateAppPassword(ctx, "user@example.com", label, h)
	if err != nil {
		t.Fatalf("create app password: %v", err)
	}
	if status != mail.DeviceStatusApproved {
		if err := s.SetDeviceStatus(ctx, "user@example.com", id, status); err != nil {
			t.Fatalf("status: %v", err)
		}
	}
	return id
}

// TestOnlyAnApprovedDeviceCanReset. The approval lifecycle is the operator's
// control over which devices exist; a pending device has not been approved yet
// and a blocked one was explicitly taken away. Either being able to reset the
// password would make blocking meaningless.
func TestOnlyAnApprovedDeviceCanReset(t *testing.T) {
	t.Parallel()
	s, ctx := deviceStore(t)
	addDevice(t, s, ctx, "approved-phone", "approved-secret", mail.DeviceStatusApproved)
	addDevice(t, s, ctx, "pending-tablet", "pending-secret", mail.DeviceStatusPending)
	addDevice(t, s, ctx, "blocked-laptop", "blocked-secret", mail.DeviceStatusBlocked)

	if _, ok := s.VerifyApprovedDevice(ctx, "user@example.com", "approved-secret"); !ok {
		t.Error("an approved device was refused")
	}
	if _, ok := s.VerifyApprovedDevice(ctx, "user@example.com", "pending-secret"); ok {
		t.Error("a PENDING device was accepted — it has never been approved by the operator")
	}
	if _, ok := s.VerifyApprovedDevice(ctx, "user@example.com", "blocked-secret"); ok {
		t.Error("a BLOCKED device was accepted — blocking would mean nothing")
	}
	if _, ok := s.VerifyApprovedDevice(ctx, "user@example.com", "wrong-secret"); ok {
		t.Error("a wrong secret was accepted")
	}
	if _, ok := s.VerifyApprovedDevice(ctx, "user@example.com", ""); ok {
		t.Error("an empty secret was accepted")
	}
}

// TestDeviceCredentialsAreScopedToTheirMailbox — one mailbox's device must never
// authenticate a reset of another's.
func TestDeviceCredentialsAreScopedToTheirMailbox(t *testing.T) {
	t.Parallel()
	s, ctx := deviceStore(t)
	if err := s.Create(ctx, "other@example.com", "hash", "Other", mail.RoleMailbox); err != nil {
		t.Fatalf("create other: %v", err)
	}
	addDevice(t, s, ctx, "phone", "approved-secret", mail.DeviceStatusApproved)
	if _, ok := s.VerifyApprovedDevice(ctx, "other@example.com", "approved-secret"); ok {
		t.Error("one mailbox's device authenticated against a different mailbox")
	}
}

// TestDeviceResetRevokesTheDeviceThatAuthorisedIt is the counter-intuitive one,
// and the reason it is written down.
//
// Preserving the initiating device would be friendlier: the holder would not have
// to set their phone up again. But the server cannot tell a holder's device from
// a thief's — only that the credential is valid — so a carve-out for "the device
// that asked" is precisely the carve-out an attacker would use to reset the
// password and keep sole access.
func TestDeviceResetRevokesTheDeviceThatAuthorisedIt(t *testing.T) {
	t.Parallel()
	s, ctx := deviceStore(t)
	addDevice(t, s, ctx, "phone", "approved-secret", mail.DeviceStatusApproved)
	addDevice(t, s, ctx, "laptop", "second-secret", mail.DeviceStatusApproved)

	deps := mailResetDeps{
		SetPasswordHash:    s.SetPasswordHash,
		RevokeAppPasswords: s.RevokeAllAppPasswords,
		InvalidateTokens:   s.InvalidateRecoveryTokens,
	}
	out, err := applyMailPasswordReset(ctx, deps, "user@example.com", "a-new-password",
		mailResetByDevice, "device:test")
	if err != nil {
		t.Fatalf("device reset: %v", err)
	}
	if out.AppPasswordsRevoked != 2 {
		t.Errorf("revoked %d app passwords, want both", out.AppPasswordsRevoked)
	}
	if _, ok := s.VerifyApprovedDevice(ctx, "user@example.com", "approved-secret"); ok {
		t.Error("the device that authorised the reset still works — an attacker would keep sole access")
	}
	if _, ok := s.VerifyApprovedDevice(ctx, "user@example.com", "second-secret"); ok {
		t.Error("a second device survived the reset")
	}
}

// TestDeviceResetNoticeSaysHowItWasAuthorised. "Your password was reset" with no
// cause gives the reader nothing to judge; "from one of your signed-in devices"
// is something they can recognise or not.
func TestDeviceResetNoticeSaysHowItWasAuthorised(t *testing.T) {
	t.Parallel()
	_, body := mailResetNotice("user@example.com", mailResetByDevice, "device:1.2.3.4",
		mailResetOutcome{AppPasswordsRevoked: 2}, testTime())
	if !strings.Contains(body, "signed-in devices") {
		t.Errorf("notice does not say a device authorised it:\n%s", body)
	}
	if !strings.Contains(body, "If this was NOT you") {
		t.Errorf("notice is not actionable:\n%s", body)
	}
}

// TestDeviceResetEndpointIsUniformlyOpaque. This endpoint takes a mailbox address
// and a secret, so distinguishing "no such mailbox" from "wrong secret" would
// turn it into a directory of every account on the server.
func TestDeviceResetEndpointIsUniformlyOpaque(t *testing.T) {
	t.Parallel()
	code := withoutComments(repoFile(t, "cmd/vayupress/handlers_mail_device_reset.go"))

	// Exactly one rejection message, reached through one helper.
	if n := strings.Count(code, `"That mailbox and app password were not accepted."`); n != 1 {
		t.Errorf("expected a single uniform rejection message, found %d", n)
	}
	for _, leak := range []string{"no such mailbox", "unknown mailbox", "device is blocked", "pending approval"} {
		if strings.Contains(strings.ToLower(code), leak) {
			t.Errorf("the endpoint distinguishes failure causes to the caller (%q)", leak)
		}
	}
	// Every rejection has to be audited, or credential-guessing leaves no trace.
	if !strings.Contains(code, "vayumail.recovery.device_rejected") {
		t.Error("rejections are not audited")
	}
	// It must be rate-limited: this is an online guessing surface for app passwords.
	if !strings.Contains(code, "deviceResetByIP.allow") {
		t.Error("the endpoint is not rate-limited")
	}
	// And it must go through the pipeline, not set the hash directly.
	if strings.Contains(code, "SetPasswordHash(") {
		t.Error("the device path bypasses applyMailPasswordReset")
	}
}

// TestDeviceResetGatesOnStatusNotLastUsed pins a decision that would otherwise
// look like an oversight. last_used_at is documented in TouchAppPassword as
// best-effort telemetry and "never a security decision" — gating recovery on it
// would let a missed write lock out a legitimate holder, which is the exact
// opposite of the point.
func TestDeviceResetGatesOnStatusNotLastUsed(t *testing.T) {
	t.Parallel()
	src := repoFile(t, "internal/vayuos/mail/recovery.go")
	start := strings.Index(src, "func (s *AccountStore) VerifyApprovedDevice")
	if start < 0 {
		t.Fatal("VerifyApprovedDevice not found in recovery.go")
	}
	// Normalise CRLF before slicing: a checkout whose file uses \r\n never
	// contains the "\n}\n" marker, and an unguarded strings.Index here used to
	// panic (slice from -1) instead of reporting the drift as a failure.
	fn := strings.ReplaceAll(src[start:], "\r\n", "\n")
	end := strings.Index(fn, "\n}\n")
	if end < 0 {
		t.Fatal("could not find the end of VerifyApprovedDevice")
	}
	fn = fn[:end]
	if strings.Contains(fn, "last_used_at") || strings.Contains(fn, "LastUsed") {
		t.Error("recovery gates on last-used telemetry; a missed write would lock out a real holder")
	}
	if !strings.Contains(fn, "DeviceStatusApproved") {
		t.Error("recovery does not gate on the approval lifecycle")
	}
}
