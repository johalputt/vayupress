// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// TestPurifyIsEditorOnly pins the Wave 3.3 scoping: DOMPurify exists for the
// block editor's client-side sanitisation alone. Every other console page
// shipping the 21 KB library was a tax paid for nothing, on every load.
func TestPurifyIsEditorOnly(t *testing.T) {
	if !pageUsesPurify(`<div class="editor-canvas" data-editor-canvas></div>`) {
		t.Fatal("an editor page was not detected as needing DOMPurify")
	}
	if pageUsesPurify(`<div class="work-grid">posts and pages</div>`) {
		t.Fatal("a non-editor page was detected as needing DOMPurify")
	}

	with := adminOSShellFoot("n", "", false, true)
	without := adminOSShellFoot("n", "", false, false)
	if !strings.Contains(with, "purify.min.js") {
		t.Error("editor shell foot does not load purify.min.js")
	}
	if strings.Contains(without, "purify.min.js") {
		t.Error("a non-editor shell foot still ships purify.min.js — the scoping regressed")
	}
}
