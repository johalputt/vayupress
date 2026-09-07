// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

// Wave 3.11 — selector parity. A JS handler bound to a selector nothing renders
// is dead weight that pretends a feature exists (initPostsSearch outlived its
// input by an entire redesign); a Go template that renders a hook with no
// handler is a button that lies. This test pins both directions for the known
// registry against the shipped sources.
func TestSelectorParity(t *testing.T) {
	goSrc, jsSrc := readConsoleSources(t)

	// Hooks admin-os.js binds — each must be rendered by the Go templates.
	// (data-media-select is created by the JS itself and is deliberately absent.)
	boundInJS := []string{
		"data-post-row", "data-post-select", "data-post-select-all", "data-post-bulk",
		"data-post-bulkbar", "data-post-bulk-count", "data-post-delete",
		"data-setting-key", "data-media-grid", "data-media-dropzone", "data-media-input",
		"data-media-search", "data-media-empty", "data-media-filter", "data-media-delete-selected",
		"data-media-sel-count", "data-notif-toggle",
		"data-space-switch", "data-copy", "data-first-run-dismiss",
	}
	for _, hook := range boundInJS {
		if !strings.Contains(goSrc, hook) {
			t.Errorf("admin-os.js binds %q but no Go template renders it — dead JS pretending a feature exists", hook)
		}
	}

	// Dead-selector drift, pinned by name: the client-side posts search was
	// removed with its feature. Neither side may reappear alone.
	for _, dead := range []string{"data-posts-search", "data-search-empty"} {
		if strings.Contains(jsSrc, dead) && !strings.Contains(goSrc, dead) {
			t.Errorf("admin-os.js still binds %q, which no Go template renders", dead)
		}
		if strings.Contains(goSrc, dead) && !strings.Contains(jsSrc, dead) {
			t.Errorf("Go renders %q but admin-os.js has no handler for it", dead)
		}
	}
}

// TestNoWindowConfirmPinsModalUsage — window.confirm is unstyled browser chrome
// that cannot say what will happen; destructive actions confirm through the
// vpConfirm modal instead.
func TestNoWindowConfirmPinsModalUsage(t *testing.T) {
	goSrc, jsSrc := readConsoleSources(t)
	if strings.Contains(jsSrc, "window.confirm") {
		t.Error("admin-os.js still calls window.confirm — use the vpConfirm modal (Wave 3.11)")
	}
	if !strings.Contains(jsSrc, "vpConfirm") {
		t.Error("admin-os.js lost the vpConfirm usage — destructive actions must confirm through the modal")
	}
	// The posts page inline script confirmed through window.confirm too.
	if !strings.Contains(goSrc, "vpConfirm") {
		t.Error("the posts page script lost vpConfirm — destructive actions must confirm through the modal")
	}
	if strings.Contains(goSrc, "window.confirm") {
		t.Error("a Go-rendered page script still calls window.confirm — use vpConfirm (Wave 3.11)")
	}
}

func readConsoleSources(t *testing.T) (goSrc, jsSrc string) {
	t.Helper()
	layout, err := os.ReadFile("admin_os_ui.go")
	if err != nil {
		t.Fatalf("read admin_os_ui.go: %v", err)
	}
	media, err := os.ReadFile("admin_os_media.go")
	if err != nil {
		t.Fatalf("read admin_os_media.go: %v", err)
	}
	js, err := os.ReadFile("../../static/js/admin-os.js")
	if err != nil {
		t.Fatalf("read admin-os.js: %v", err)
	}
	return string(layout) + string(media), string(js)
}
