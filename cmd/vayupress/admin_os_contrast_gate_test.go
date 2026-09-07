// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Wave 0.3 — the console-token contrast gate. The Theme Studio measures the
// operator's chosen accents, but the console's OWN shipped palette was never
// measured: --text on --bg-base, muted text on cards, brand links, semantic
// colors, ink on brand fills. A product whose every surface depends on these
// tokens shipping an unmeasured palette is the exact dishonesty the audit
// calls out — so this test measures the tokens as shipped, parsed live from
// admin-os.css, and fails if any reading pairing drifts below its WCAG bar.
//
// Parsing the file (not duplicating hexes) means the gate can never drift from
// what actually renders: change the token, the gate re-measures it.

const consoleCSSPath = "../../static/css/admin-os.css"

var consoleTokenRe = regexp.MustCompile(`(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{3,8})`)

func parseConsoleSections(t *testing.T) (dark, light map[string]string) {
	t.Helper()
	b, err := os.ReadFile(consoleCSSPath)
	if err != nil {
		t.Fatalf("read %s: %v", consoleCSSPath, err)
	}
	css := string(b)
	lightAt := strings.Index(css, `.vp-os[data-theme="light"]`)
	if lightAt < 0 {
		t.Fatal("admin-os.css has no light-theme token block")
	}
	// First declaration wins: later occurrences are the media-query mirror of
	// the same light values and the component-scoped re-declarations.
	dark = sectionTokens(css[:lightAt])
	light = sectionTokens(css[lightAt:])
	return dark, light
}

func sectionTokens(section string) map[string]string {
	out := map[string]string{}
	for _, m := range consoleTokenRe.FindAllStringSubmatch(section, -1) {
		if _, ok := out[m[1]]; !ok {
			out[m[1]] = strings.ToLower(m[2])
		}
	}
	return out
}

// TestConsoleTokensPassWCAGAA measures the console's shipped palette in BOTH
// themes. Text tokens clear AA normal (4.5); semantic colors are used for text
// AND UI accents so they clear 4.5 against their page backgrounds; ink on brand
// fills clears 4.5 because every .btn--primary label depends on it.
func TestConsoleTokensPassWCAGAA(t *testing.T) {
	dark, light := parseConsoleSections(t)

	type pairing struct {
		fgKey, bgKey string
		bar          float64
	}
	bar := func(fgKey, bgKey string, v float64) pairing { return pairing{fgKey, bgKey, v} }
	// text-1: titles; text-2: body copy; text-3: muted secondary (bylines,
	// dates, hints) — the pairing audits most often find failing, so it is
	// measured at its real reading size: AA normal.
	textPairs := []pairing{
		bar("--text", "--bg-base", wcagAANormal), bar("--text", "--bg-surface", wcagAANormal),
		bar("--text-2", "--bg-base", wcagAANormal), bar("--text-2", "--bg-surface", wcagAANormal),
		bar("--text-3", "--bg-base", wcagAANormal), bar("--text-3", "--bg-surface", wcagAANormal),
		bar("--brand", "--bg-base", wcagAANormal), bar("--brand", "--bg-surface", wcagAANormal),
		bar("--ok", "--bg-base", wcagAANormal), bar("--warn", "--bg-base", wcagAANormal),
		bar("--danger", "--bg-base", wcagAANormal), bar("--info", "--bg-base", wcagAANormal),
		bar("--on-brand", "--brand", wcagAANormal),
	}
	for _, theme := range []struct {
		name   string
		tokens map[string]string
	}{{"dark", dark}, {"light", light}} {
		for _, p := range textPairs {
			fg, bg := theme.tokens[p.fgKey], theme.tokens[p.bgKey]
			if fg == "" || bg == "" {
				t.Errorf("%s theme: token %s or %s missing from admin-os.css", theme.name, p.fgKey, p.bgKey)
				continue
			}
			ratio := contrastRatio(fg, bg)
			if ratio < p.bar {
				t.Errorf("%s theme: %s (%s) on %s (%s) = %.2f:1, below WCAG AA %.1f:1 — the console's own palette must not ship unreadable",
					theme.name, p.fgKey, fg, p.bgKey, bg, ratio, p.bar)
			}
		}
	}
}
