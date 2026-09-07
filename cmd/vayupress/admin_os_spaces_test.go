// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/config"
)

// TestTorWorldNav asserts the Tor world (OnionMode) console is Tor-only: it shows
// the blog, the anonymous services (VayuMail·Tor, VayuTalk·Tor) and onion Domains,
// and hides every clearnet-only section (ADR-0141).
func TestTorWorldNav(t *testing.T) {
	prev := config.Cfg.OnionMode
	config.Cfg.OnionMode = true
	defer func() { config.Cfg.OnionMode = prev }()

	nav := osSidebarNav("dashboard", &osSettings{AccessLevel: accessAdmin})

	// Tor world MUST include these. Content (Posts, Pages, Comments, Media, New
	// Post) moved INTO the dashboard workspace, so the sidebar keeps only the
	// Dashboard hub, the design tool, the anonymous services and system areas.
	for _, want := range []string{
		">Dashboard<", ">Theme<", ">Analytics<",
		">VayuMail<", ">VayuTalk<", ">Domains<", ">System<",
		"Anonymous services",
	} {
		if !strings.Contains(nav, want) {
			t.Errorf("Tor world nav missing %q", want)
		}
	}
	// Tor world MUST hide every clearnet-only section, AND the content items that
	// now live in the dashboard workspace (they must not reappear in the sidebar).
	// Analytics IS shown (Tor visit stats are privacy-preserving and served from the
	// Tor world's own DB), so it is intentionally NOT in this deny list.
	for _, deny := range []string{
		">Monetization<", ">Advertising<", ">Newsletter<", ">Members<",
		">VayuMCP<", ">SEO<", ">VayuShield<", ">VayuTor<", ">Website<",
		">Governance<", ">Fault Engine<",
		">Posts<", ">Pages<", ">Comments<", ">Media<", ">New Post<",
	} {
		if strings.Contains(nav, deny) {
			t.Errorf("Tor world nav must NOT show %q", deny)
		}
	}
}

// TestSpaceSwitch covers the top-of-sidebar one-click world switch (ADR-0141):
// admin-only, CSP-safe, correct active segment, and static (non-switchable) on a
// whole-install Tor world.
func TestSpaceSwitch(t *testing.T) {
	// Non-admins never see the switch.
	if got := spaceSwitch(accessAuthor, &osSettings{}); got != "" {
		t.Errorf("spaceSwitch must be empty for non-admins, got %q", got)
	}
	if got := spaceSwitch(accessEditor, &osSettings{TorSpaceOn: true}); got != "" {
		t.Errorf("spaceSwitch must be empty for editors, got %q", got)
	}

	// Clearnet install: the switch is a clean two-segment control — Clearnet active,
	// Tor the click-to-enter segment. The live .onion status now lives on the
	// dashboard (osWorldCard), not under the switch, so no status panel is rendered.
	off := spaceSwitch(accessAdmin, &osSettings{})
	assertCSPSafe(t, "spaceSwitch/off", off)
	if !strings.Contains(off, `data-space-switch="on"`) || !strings.Contains(off, `data-space-switch="off"`) {
		t.Error("clearnet switch must offer both segments")
	}
	if !strings.Contains(off, `class="space-switch__seg is-active" data-space-switch="off"`) {
		t.Error("with Tor off, the Clearnet segment must be active")
	}
	if strings.Contains(off, "space-switch__status") {
		t.Error("the .onion status moved to the dashboard — no status panel under the switch")
	}

	// Enabling the Space must NOT change the switch itself (status is on the
	// dashboard now): Clearnet stays active, Tor stays the click-to-enter control,
	// and no .onion is crammed under the switch.
	on := spaceSwitch(accessAdmin, &osSettings{TorSpaceOn: true, TorSpaceRunning: true, TorSpaceOnion: "abcxyz.onion"})
	assertCSPSafe(t, "spaceSwitch/on", on)
	if !strings.Contains(on, `class="space-switch__seg is-active" data-space-switch="off"`) {
		t.Error("Clearnet must stay the active segment on the clearnet console")
	}
	if strings.Contains(on, "data-copy") || strings.Contains(on, "abcxyz.onion") {
		t.Error("the switch must not carry the .onion — it now lives on the dashboard")
	}

	// Whole-install Tor world: static indicator with a working Clearnet back-link,
	// no interactive switch buttons.
	prev := config.Cfg.OnionMode
	config.Cfg.OnionMode = true
	defer func() { config.Cfg.OnionMode = prev }()
	self := spaceSwitch(accessAdmin, &osSettings{})
	assertCSPSafe(t, "spaceSwitch/self", self)
	if strings.Contains(self, "data-space-switch") {
		t.Error("a dedicated Tor install must not offer a switch control")
	}
	if !strings.Contains(self, "is-active") || !strings.Contains(self, "/os/world?target=clearnet") {
		t.Error("dedicated Tor install must show Tor active + a Clearnet back-link")
	}
}

// TestOSWorldCard covers the dashboard world card that now carries the Anonymous
// Tor world's status + .onion, moved off the sidebar switch (dashboard redesign).
func TestOSWorldCard(t *testing.T) {
	// Clearnet, Space off → nothing to show.
	if got := osWorldCard(false, false, false, ""); got != "" {
		t.Errorf("world card must be empty when the Space is off, got %q", got)
	}
	// Clearnet, Space live → address + copy button + enter link.
	live := osWorldCard(false, true, true, "abcxyz.onion")
	assertCSPSafe(t, "osWorldCard/live", live)
	if !strings.Contains(live, "abcxyz.onion") || !strings.Contains(live, `data-copy="http://abcxyz.onion"`) {
		t.Error("a live Space world card must show its .onion with a copy button")
	}
	if !strings.Contains(live, "/os/world?target=tor") {
		t.Error("a live Space world card must offer to enter the Tor world")
	}
	// Clearnet, Space booting → starting state, no address/copy.
	starting := osWorldCard(false, true, false, "")
	if !strings.Contains(starting, "Starting your anonymous world") || strings.Contains(starting, "data-copy") {
		t.Error("a booting Space must show a starting state and no onion")
	}
	// Tor world itself → "you're in" + this install's onion + a Clearnet back-link.
	self := osWorldCard(true, false, false, "myonion.onion")
	assertCSPSafe(t, "osWorldCard/self", self)
	if !strings.Contains(self, "myonion.onion") || !strings.Contains(self, "/os/world?target=clearnet") {
		t.Error("the Tor world card must show its onion and a Clearnet back-link")
	}
}

// TestOSWorkspaceGrid checks the dashboard workspace surfaces the content areas
// (moved off the sidebar) with counts + notification badges, omits the
// clearnet-only Website tile in the Tor world, and gates every tile by access
// level so RBAC shown==reachable parity holds on the dashboard too.
func TestOSWorkspaceGrid(t *testing.T) {
	clearnet := osWorkspaceGrid(false, 1234, 5, 3, 2, 40, accessAdmin)
	assertCSPSafe(t, "osWorkspaceGrid/clearnet", clearnet)
	for _, want := range []string{
		`href="/os/editor"`, `href="/os/posts"`, `href="/os/pages"`,
		`href="/os/comments"`, `href="/os/messages"`, `href="/os/media"`,
		`href="/os/website"`, "1,234", "Workspace",
	} {
		if !strings.Contains(clearnet, want) {
			t.Errorf("clearnet workspace missing %q", want)
		}
	}
	// Pending comments (3) + unread messages (2) render as notification badges.
	if !strings.Contains(clearnet, `work-card__badge">3<`) || !strings.Contains(clearnet, `work-card__badge">2<`) {
		t.Error("workspace must surface pending-comment and unread-message badges")
	}
	// The Tor world omits the clearnet-only Website tile.
	tor := osWorkspaceGrid(true, 10, 2, 0, 0, 4, accessAdmin)
	if strings.Contains(tor, `href="/os/website"`) {
		t.Error("Tor workspace must not show the clearnet Website tile")
	}
	// Role gate: a viewer who cannot reach a page must not be shown its tile.
	// /os/website is admin-gated; /os/editor stays open to writers.
	author := osWorkspaceGrid(false, 1, 1, 0, 0, 1, accessAuthor)
	if strings.Contains(author, `href="/os/website"`) {
		t.Error("an author-level viewer was shown the admin-only Website tile — a silent denial loop rendered as an invitation")
	}
	if !strings.Contains(author, `href="/os/posts"`) {
		t.Error("an author-level viewer lost the Posts tile — the gate overreached")
	}
}

// TestOSSpacesCardsCSPSafe verifies the Spaces fragments are CSP-safe and carry
// the right content, including the one-click Anonymous Tor Space toggle.
func TestOSSpacesCardsCSPSafe(t *testing.T) {
	header := osSpacesHeader()
	assertCSPSafe(t, "osSpacesHeader", header)

	model := osSpacesModelCard()
	assertCSPSafe(t, "osSpacesModelCard", model)
	for _, want := range []string{"Clearnet Space", "Tor Space", "no mesh"} {
		if !strings.Contains(model, want) {
			t.Errorf("model card missing %q", want)
		}
	}

	// Current-space card, both worlds.
	clear := osSpacesCurrentCard(false, "example.test")
	assertCSPSafe(t, "current/clearnet", clear)
	if !strings.Contains(clear, "space-badge--clearnet") || strings.Contains(clear, "space-badge--tor") {
		t.Error("clearnet current card must show only the clearnet badge")
	}
	tor := osSpacesCurrentCard(true, "abcxyz.onion")
	assertCSPSafe(t, "current/tor", tor)
	if !strings.Contains(tor, "space-badge--tor") || !strings.Contains(tor, "abcxyz.onion") {
		t.Error("tor current card must show the tor badge and the onion")
	}

	// Off state: the toggle offers to turn ON.
	off := osSpacesTorSpaceCard(torSpaceStatus{Enabled: false})
	assertCSPSafe(t, "torspace/off", off)
	if !strings.Contains(off, `data-space-toggle="on"`) || !strings.Contains(off, "Turn on") {
		t.Error("off card must offer to turn the Tor Space on")
	}
	if !strings.Contains(off, "same server") {
		t.Error("card must carry the honest same-server caveat")
	}

	// Running state: offers OFF, shows the onion, marks Running.
	on := osSpacesTorSpaceCard(torSpaceStatus{Enabled: true, Running: true, Onion: "abcxyz.onion", Port: 8347})
	assertCSPSafe(t, "torspace/on", on)
	if !strings.Contains(on, `data-space-toggle="off"`) || !strings.Contains(on, "Running") {
		t.Error("running card must offer OFF and show Running")
	}
	if !strings.Contains(on, "abcxyz.onion") {
		t.Error("running card must show the anonymous onion address")
	}

	// Error surfaces (html-escaped).
	errCard := osSpacesTorSpaceCard(torSpaceStatus{Enabled: true, LastErr: "boom <x>"})
	assertCSPSafe(t, "torspace/err", errCard)
	if !strings.Contains(errCard, "boom &lt;x&gt;") {
		t.Error("error must be html-escaped and shown")
	}

	// Tor-self card (whole-install Tor).
	self := osSpacesTorSelfCard("abcxyz.onion")
	assertCSPSafe(t, "torself", self)
	if !strings.Contains(self, "abcxyz.onion") {
		t.Error("tor-self card must show this install's onion")
	}
}
