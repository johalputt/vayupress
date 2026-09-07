// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

// First-run checklist tests — the card must be honest in both directions: it
// appears only while real setup work remains, every probe it reports is one
// the server actually knows, and it vanishes once the work is done. A checklist
// that nags completed work (or lies about it) is the exact dishonesty the
// dashboard upgrade exists to remove.

import (
	"context"
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/settings"
)

func TestFirstRunChecklistHonestLifecycle(t *testing.T) {
	_, _ = newTestHarness(t) // config + DB + CSRF secret
	a := &App{siteSettings: settings.New(dbpkg.DB)}
	ctx := context.Background()

	// Fresh install: every actionable probe reports work to do.
	items := a.osFirstRunChecklist(ctx, accessAdmin)
	if len(items) == 0 {
		t.Fatal("a fresh install rendered no checklist — the card must guide the first run")
	}
	byLabel := map[string]osChecklistItem{}
	for _, it := range items {
		byLabel[it.Label] = it
	}
	if it, ok := byLabel["Publish your first post"]; !ok || it.Done {
		t.Errorf("fresh install: 'Publish your first post' = %#v, want present and not done", it)
	}
	if it, ok := byLabel["Name your site"]; !ok || it.Done {
		t.Errorf("fresh install: 'Name your site' = %#v, want present and not done", it)
	}
	// The DNS review is a link-out step, never a server-claimed ✓/✗.
	if it, ok := byLabel["Review DNS & HTTPS"]; !ok || !it.Review || it.Done {
		t.Errorf("'Review DNS & HTTPS' = %#v, want a neutral review step", it)
	}
	// Dismissal markup: the card carries the data hook and the localStorage key.
	card := osFirstRunCard(items, "test-nonce")
	for _, want := range []string{`data-first-run`, `data-first-run-dismiss`, `vayuOS.firstRun.dismissed`} {
		if !strings.Contains(card, want) {
			t.Errorf("first-run card missing %q", want)
		}
	}

	// Do the work: publish a post, name the site, theme it, point a domain.
	if _, err := dbpkg.DB.Exec(`INSERT INTO articles(id,title,slug,content,tags,status,created_at,updated_at)
		 VALUES('fr1','Hello','first-run-post','body','','published',datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("seed post: %v", err)
	}
	if err := a.siteSettings.SetMany(ctx, settings.ForPrimary(), map[string]string{
		settings.KeySiteName:  "My Site",
		"theme.primary_light": "#2563eb",
	}); err != nil {
		t.Fatalf("settings: %v", err)
	}
	prevDomain := config.Cfg.Domain
	config.Cfg.Domain = "example.com"
	t.Cleanup(func() { config.Cfg.Domain = prevDomain })

	items = a.osFirstRunChecklist(ctx, accessAdmin)
	if len(items) != 0 {
		var pending []string
		for _, it := range items {
			if !it.Done && !it.Review {
				pending = append(pending, it.Label)
			}
		}
		if len(pending) > 0 {
			t.Errorf("after full setup the card still nags: %v", pending)
		}
	}
}

func TestFirstRunChecklistHiddenFromAuthorsAndLinksStayReachable(t *testing.T) {
	_, _ = newTestHarness(t)
	a := &App{siteSettings: settings.New(dbpkg.DB)}
	ctx := context.Background()

	// Authors cannot open /os/settings — the card must not hand them dead links.
	if got := a.osFirstRunChecklist(ctx, accessEditor); got != nil {
		t.Errorf("editor-level viewer got a checklist (%d items) linking into admin-only pages", len(got))
	}

	// With one probe done and others pending, the card survives for admins and
	// every pending row links to a page at or below their access level.
	if _, err := dbpkg.DB.Exec(`INSERT INTO articles(id,title,slug,content,tags,status,created_at,updated_at)
		 VALUES('fr2','Hi','fr2','body','','published',datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("seed post: %v", err)
	}
	items := a.osFirstRunChecklist(ctx, accessAdmin)
	if len(items) == 0 {
		t.Fatal("expected the card to survive with pending items")
	}
	for _, it := range items {
		if it.Done || it.Review {
			continue
		}
		if osPathMinLevel(it.Href) > accessAdmin {
			t.Errorf("pending item %q links to %q which needs level %d — even an admin sees a dead link",
				it.Label, it.Href, osPathMinLevel(it.Href))
		}
	}
}
