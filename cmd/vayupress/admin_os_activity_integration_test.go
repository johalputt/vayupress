// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

// Wave 2.3 — activity feed v1 honesty. The feed used to say "published" for
// every article (the list projection has no status, so the verb was hardcoded),
// linked nowhere, showed member emails to every signed-in role, and swallowed
// its own failures. Each of those four is pinned here.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/members"
	"github.com/johalputt/vayupress/internal/users"
)

type feedItem struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
	Href string `json:"href"`
}

func callFeed(t *testing.T, a *App, u *users.User) []feedItem {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/os/api/activity", nil)
	if u != nil {
		req = req.WithContext(context.WithValue(req.Context(), ctxUserKey, u))
	}
	rec := httptest.NewRecorder()
	a.handleOSActivity(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var items []feedItem
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return items
}

func TestActivityFeedVerbsAreHonest(t *testing.T) {
	_, _ = newTestHarness(t)
	a := &App{} // no members store — member rows impossible regardless

	if _, err := dbpkg.DB.Exec(`INSERT INTO articles(id,title,slug,content,tags,status,created_at,updated_at)
		 VALUES('af1','Published Story','af1','body','','published',datetime('now'),datetime('now')),
		       ('af2','Hidden Draft','af2','body','','draft',datetime('now','+1 second'),datetime('now','+1 second'))`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { _, _ = dbpkg.DB.Exec(`DELETE FROM articles WHERE slug IN ('af1','af2')`) })

	items := callFeed(t, a, nil)
	found := map[string]feedItem{}
	for _, it := range items {
		found[it.Text] = it
	}
	draft, ok := findContaining(items, "Hidden Draft")
	if !ok {
		t.Fatal("draft post missing from the feed")
	}
	if found[draft.Text].Text != "Article drafted: Hidden Draft" {
		t.Errorf("draft feed text = %q, want an honest 'drafted' verb", draft.Text)
	}
	if draft.Href != "/os/editor/af2" {
		t.Errorf("draft feed href = %q, want the editor", draft.Href)
	}
	pub, ok := findContaining(items, "Published Story")
	if !ok {
		t.Fatal("published post missing from the feed")
	}
	if pub.Text != "Article published: Published Story" {
		t.Errorf("published feed text = %q", pub.Text)
	}
	if pub.Href != "/os/editor/af1" {
		t.Errorf("published feed href = %q, want the editor", pub.Href)
	}
}

func findContaining(items []feedItem, needle string) (feedItem, bool) {
	for _, it := range items {
		if strings.Contains(strings.ToLower(it.Text), strings.ToLower(needle)) {
			return it, true
		}
	}
	return feedItem{}, false
}

func TestActivityFeedGatesMemberRowsByRole(t *testing.T) {
	_, _ = newTestHarness(t)
	if _, err := dbpkg.DB.Exec(`INSERT INTO members(id,email,tier,status,created_at)
		 VALUES('m1','reader@example.com','free','active',datetime('now'))`); err != nil {
		t.Fatalf("seed member: %v", err)
	}
	t.Cleanup(func() { _, _ = dbpkg.DB.Exec(`DELETE FROM members WHERE id='m1'`) })
	a := &App{members: members.New(dbpkg.DB)}

	client := &users.User{ID: "u1", Email: "c@example.com", Role: users.RoleClient}
	for _, it := range callFeed(t, a, client) {
		if strings.Contains(strings.ToLower(it.Text), "reader@example.com") {
			t.Errorf("a client-role viewer saw a member row: %q — members are an admin surface", it.Text)
		}
	}

	admin := &users.User{ID: "u2", Email: "a@example.com", Role: users.RoleAdmin}
	found := false
	for _, it := range callFeed(t, a, admin) {
		if strings.Contains(strings.ToLower(it.Text), "reader@example.com") {
			found = true
			if it.Href != "/os/members" {
				t.Errorf("member row href = %q, want /os/members", it.Href)
			}
		}
	}
	if !found {
		t.Error("an admin viewer saw no member row although members exist")
	}
}
