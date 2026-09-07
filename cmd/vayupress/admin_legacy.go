// SPDX-License-Identifier: Apache-2.0

package main

// admin_legacy.go — legacy admin redirection into VayuOS (`/os`).
//
// As of v1.6.0 the canonical admin surface is VayuOS, mounted at `/os`, and
// Admin v2 has been removed (ADR-0069 Stage 3). The three historical surfaces —
// the classic console root (`/admin`), Admin v2 (`/admin/v2`), and Admin v3
// (`/admin/v3`) — permanently redirect (301) into the `/os` equivalent.
//
// The API surface (/api/v1/*) and the operator console sub-pages (/admin/modes,
// /admin/faults, …) are unaffected — they have a separate lifecycle.

import (
	"net/http"
	"strings"

	"github.com/johalputt/vayupress/internal/logging"
)

// legacyToOSPath maps a deprecated admin path (`/admin`, `/admin/v2[/...]`, or
// `/admin/v3[/...]`) to its VayuOS (`/os`) equivalent, preserving any trailing
// segments (e.g. an editor slug). The bare roots map to the VayuOS dashboard.
func legacyToOSPath(p string) string {
	switch {
	case p == "/admin", p == "/admin/v2", p == "/admin/v3":
		return "/os"
	case p == "/admin/theme":
		// Wave 2.7: the classic theme editor is retired in favour of the
		// VayuOS Theme page at the same conceptual address.
		return "/os/theme"
	case strings.HasPrefix(p, "/admin/v2/"):
		return "/os/" + strings.TrimPrefix(p, "/admin/v2/")
	case strings.HasPrefix(p, "/admin/v3/"):
		return "/os/" + strings.TrimPrefix(p, "/admin/v3/")
	default:
		return "/os"
	}
}

// legacyRedirect returns a handler that permanently (301) redirects the current
// path to its VayuOS (`/os`) equivalent. Admin v2 was removed in v1.6.0
// (ADR-0069 Stage 3); these redirects keep old bookmarks and integrations
// working. Each hit emits a structured deprecation warning to the server log so
// operators can find and update stale links.
func legacyRedirect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := legacyToOSPath(r.URL.Path)
		ra, ua := logIdentity(r)
		logging.LogJSON(logging.LogFields{
			Level:      "warn",
			Severity:   "warning",
			Component:  "admin-legacy",
			Method:     r.Method,
			Path:       r.URL.Path,
			RemoteAddr: ra,
			UserAgent:  ua,
			Msg:        "deprecated admin route used; permanently redirecting to VayuOS (" + target + ")",
		})
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
}

// operatorLegacyRedirect 301-redirects a legacy operator-console page URL
// (/admin/modes, /admin/policy, /admin/topology, /admin/replay, /admin/faults,
// /admin/adr) to its VayuOS equivalent under /os. The operator consoles now
// live inside the single VayuOS shell; only the page URLs moved (the POST
// control endpoints under /admin/* are unchanged).
func operatorLegacyRedirect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := "/os/" + strings.TrimPrefix(r.URL.Path, "/admin/")
		ra, ua := logIdentity(r)
		logging.LogJSON(logging.LogFields{
			Level:      "warn",
			Severity:   "warning",
			Component:  "admin-legacy",
			Method:     r.Method,
			Path:       r.URL.Path,
			RemoteAddr: ra,
			UserAgent:  ua,
			Msg:        "deprecated operator route used; permanently redirecting to VayuOS (" + target + ")",
		})
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
}
