// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/members"
	"github.com/johalputt/vayupress/internal/users"
)

// TestMemberMeRecognisesOperator verifies that the public /api/v1/members/me
// snapshot reports authenticated=true with an operator chip when the request
// carries a VayuOS console session — so a signed-in owner is recognised on the
// public site instead of being shown "Sign in / Sign up".
func TestMemberMeRecognisesOperator(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("DB_PATH", filepath.Join(dir, "portal.db"))
	os.Setenv("API_KEY", "test-key")
	os.Setenv("DOMAIN", "localhost")
	os.Setenv("CACHE_DIR", dir)
	config.Load()

	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
	})

	a := &App{
		userStore: users.New(dbpkg.DB),
		sessions:  auth.NewSessionStore(dbpkg.DB),
	}
	ctx := context.Background()
	u, err := a.userStore.Create(ctx, "owner@example.com", "Site Owner", "correct horse battery", users.RoleAdmin)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, err := a.sessions.Create(ctx, u.ID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Anonymous: not authenticated.
	anon := decodeMe(t, a, "")
	if anon["authenticated"] != false {
		t.Errorf("anonymous authenticated = %v, want false", anon["authenticated"])
	}

	// With the operator console cookie: authenticated as an operator, chip links
	// to the console.
	me := decodeMe(t, a, token)
	if me["authenticated"] != true {
		t.Fatalf("operator authenticated = %v, want true", me["authenticated"])
	}
	member, ok := me["member"].(map[string]interface{})
	if !ok {
		t.Fatalf("member = %v, want an object", me["member"])
	}
	if member["operator"] != true {
		t.Errorf("member.operator = %v, want true", member["operator"])
	}
	if member["console_url"] != "/os" {
		t.Errorf("member.console_url = %v, want /os", member["console_url"])
	}
	if member["name"] != "Site Owner" {
		t.Errorf("member.name = %v, want Site Owner", member["name"])
	}
}

// TestMemberSnapshotAvatar verifies the account panel gets the member's photo:
// when the member is also a CMS user with an avatar, memberSnapshot surfaces that
// public avatar URL so the panel shows the picture instead of only an initial.
func TestMemberSnapshotAvatar(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("DB_PATH", filepath.Join(dir, "avatar.db"))
	os.Setenv("API_KEY", "test-key")
	os.Setenv("DOMAIN", "localhost")
	os.Setenv("CACHE_DIR", dir)
	config.Load()
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
	})

	a := &App{userStore: users.New(dbpkg.DB)}
	ctx := context.Background()
	u, err := a.userStore.Create(ctx, "owner@example.com", "Site Owner", "correct horse battery", users.RoleAdmin)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := a.userStore.UpdateProfile(ctx, u.ID, "Site Owner", "", "https://cdn.example.com/me.jpg", nil); err != nil {
		t.Fatalf("set avatar: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/members/me", nil)
	// A member whose email matches the CMS user → avatar flows through.
	withAvatar := a.memberSnapshot(req, &members.Member{Email: "owner@example.com", Name: "Site Owner"})
	if withAvatar["avatar"] != "https://cdn.example.com/me.jpg" {
		t.Errorf("member avatar = %v, want the CMS user avatar URL", withAvatar["avatar"])
	}
	// A member with no matching CMS user → no avatar key (panel falls back to initial).
	noAvatar := a.memberSnapshot(req, &members.Member{Email: "stranger@example.com", Name: "Stranger"})
	if _, ok := noAvatar["avatar"]; ok {
		t.Error("avatar key must be absent for a member with no matching CMS user")
	}
}

// TestResolveCommenterRecognisesOperator pins the comment-gate fix: a signed-in
// VayuOS operator (console session, no reader-member session) is resolved as an
// authorised commenter with full access — so the "Commenting as …" form the
// portal shows them is no longer refused with "please sign in as a member". This
// is the write-side counterpart to TestMemberMeRecognisesOperator: the two must
// agree on who is authenticated.
func TestResolveCommenterRecognisesOperator(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("DB_PATH", filepath.Join(dir, "commenter.db"))
	os.Setenv("API_KEY", "test-key")
	os.Setenv("DOMAIN", "localhost")
	os.Setenv("CACHE_DIR", dir)
	config.Load()
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
	})

	// a.members is nil, so resolveMember returns nil and resolveCommenter must fall
	// through to the console-operator session — the exact path that used to fail.
	a := &App{
		userStore: users.New(dbpkg.DB),
		sessions:  auth.NewSessionStore(dbpkg.DB),
	}
	ctx := context.Background()
	u, err := a.userStore.Create(ctx, "owner@example.com", "Site Owner", "correct horse battery", users.RoleAdmin)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, err := a.sessions.Create(ctx, u.ID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Anonymous → no commenter.
	if who := a.resolveCommenter(httptest.NewRequest(http.MethodPost, "/x", nil)); who != nil {
		t.Errorf("anonymous resolveCommenter = %+v, want nil", who)
	}

	// Operator console session → authorised commenter with full power.
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
	who := a.resolveCommenter(req)
	if who == nil {
		t.Fatal("operator session resolveCommenter = nil, want an authorised commenter")
	}
	if !who.Operator || who.Email != "owner@example.com" || who.Name != "Site Owner" {
		t.Errorf("operator identity = %+v, want operator owner@example.com / Site Owner", who)
	}
	if !who.Can(members.AccessMembers) || !who.Can(members.AccessPaid) {
		t.Error("an operator must clear every access level (full power over their own site)")
	}
}

func decodeMe(t *testing.T, a *App, token string) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/members/me", nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	a.handleMemberMe(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body: %s)", err, rec.Body.String())
	}
	return out
}
