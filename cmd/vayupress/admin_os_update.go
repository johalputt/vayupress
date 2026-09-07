// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_update.go — VayuOS "Update & Migration" panel.
//
// This brings two operator capabilities that previously required shell access
// (CLI `vayupress update …`, manual file copies) into a single one-click admin
// surface, while preserving every security guarantee of the underlying engine:
//
//   1. One-click self-update. Check GitHub for a newer release, then apply it —
//      download, SHA-256 + Sigstore signature verification against the
//      pinned release key, automatic database backup, atomic binary swap, and an
//      in-process re-exec to activate the new version. No command line, nothing
//      left half-done. Rollback restores the previous binary.
//
//   2. Full backup / export / import. Download the entire site (database +
//      every setting) as one consistent, checksummed .tar.gz, and restore from
//      such a file. Export and import stream with the server read/write
//      deadlines lifted, so there is no size limit — a multi-gigabyte site moves
//      in constant memory.
//
// Security posture: an apply is admin-role gated and CSRF-protected (an
// authenticated admin clicking Update is the explicit opt-in), and is refused in
// read-only/quarantined/maintenance modes. The downloaded release is ALWAYS
// SHA-256 checksum verified; if a release signing key is pinned
// (VAYU_RELEASE_PUBKEY) the Ed25519 signature is additionally required. Every
// action is recorded in the WORM audit log and the update_history table.
//
// CSP posture is identical to the rest of VayuOS: no inline styles, the only
// inline <script> carries the per-request nonce, all interpolated values are
// escaped, and DOM writes in the JS use textContent.

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	htmpl "html/template"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/logging"
	"github.com/johalputt/vayupress/internal/mode"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/update"
)

const (
	updateOwner = "johalputt"
	// Canonical repository name. GitHub renamed the repo to "VayuPress"; using the
	// canonical case avoids a 301 redirect on every releases-API call (which, with
	// the SSRF-guarded outbound transport, could make the update check fail).
	updateRepo = "VayuPress"
)

// restartCleanup flushes and closes the database immediately before a re-exec
// so a self-restart never loses a write or leaves the WAL un-checkpointed.
func restartCleanup() {
	if dbpkg.DB != nil {
		if _, err := dbpkg.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			logging.LogError("update", "pre-restart WAL checkpoint", err.Error())
		}
		_ = dbpkg.DB.Close()
	}
}

// selfUpdateConfigured reports whether the operator has opted in and pinned a
// release key, i.e. whether one-click apply can run.
func selfUpdateConfigured() (enabled bool, hasKey bool) {
	return os.Getenv("VAYU_SELFUPDATE_ENABLED") == "true", strings.TrimSpace(os.Getenv("VAYU_RELEASE_PUBKEY")) != ""
}

// binaryDirWritable returns an empty string when the directory holding binPath
// can be written (so the atomic binary swap can create its temp file there), or
// a short human reason when it cannot. It probes by actually creating and
// removing a temp file — the only reliable test across permission bits, a
// read-only mount, and a systemd ProtectSystem sandbox.
func binaryDirWritable(binPath string) string {
	dir := filepath.Dir(binPath)
	f, err := os.CreateTemp(dir, ".vayupress-write-probe-*")
	if err != nil {
		if os.IsPermission(err) {
			return "permission denied writing to " + dir + "."
		}
		msg := err.Error()
		if strings.Contains(msg, "read-only") {
			return dir + " is mounted read-only."
		}
		return "could not write to " + dir + " (" + msg + ")."
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return ""
}

// updateReadonlyHelp builds the operator-facing message shown when the running
// binary sits in a directory the service cannot write. It names the real cause
// (a root-owned / read-only binary location) and the permanent, enterprise fix
// (run from a service-owned directory) rather than the incomplete
// "add ReadWritePaths" advice — ReadWritePaths only relaxes systemd's sandbox and
// still leaves a root-owned /usr/local/bin unwritable by the non-root service.
func updateReadonlyHelp(realPath, why string) string {
	dir := filepath.Dir(realPath)
	user := serviceUserGuess()
	// The atomic swap creates a temp file in the binary's directory and renames it
	// over the binary, so it needs write permission on the DIRECTORY, not the file.
	// The usual cause now is that the directory is owned by root while the service
	// runs as a non-root user — fixable with a single chown, no re-deploy needed.
	return "Cannot install the update because the binary's directory is not writable by the service: " + why +
		" VayuPress runs from " + realPath + " as user “" + user + "”, but the directory " + dir +
		" is not owned by that user, so the service cannot create the temporary file the atomic swap needs." +
		" Fix it once with:  sudo chown -R " + user + ":" + user + " " + dir +
		"  (a ReadWritePaths grant is not enough — that relaxes systemd's sandbox, not the Unix ownership)." +
		" Then click Update now again. Alternatively, run scripts/update-vayupress.sh, which now sets this" +
		" ownership for you. If the path above is under /usr (e.g. /usr/local/bin), move the binary into" +
		" /var/lib/vayupress/bin instead — /usr is root-owned and read-only under systemd ProtectSystem."
}

// serviceUserGuess returns the OS user the process runs as, for the chown hint.
// Falls back to "vayupress" (the documented service account) when unknown.
func serviceUserGuess() string {
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.Username) != "" {
		return u.Username
	}
	return "vayupress"
}

// inlineBackupMaxBytes bounds the database size for which the in-app, in-request
// pre-update backup (a synchronous gzip of the whole DB) is offered. Above this,
// gzipping the database inside the update request would read the entire file and
// thrash a memory-constrained single-VPS host into swap — exactly the failure
// mode that made one-click updates fail on large catalogues. Past this size the
// operator should snapshot during a quiet window (stop · cp · start) or use the
// Export button, then update with the backup unticked: a binary update never
// rewrites the database and the previous binary is kept as <binary>.bak.
const inlineBackupMaxBytes = 2 << 30 // 2 GiB

// dbSizeBytes returns the on-disk size of the live database file (0 if unknown).
func dbSizeBytes() int64 {
	if config.Cfg.DBPath == "" {
		return 0
	}
	fi, err := os.Stat(config.Cfg.DBPath)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// ── Page ─────────────────────────────────────────────────────────────────────

func (a *App) handleOSUpdate(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())

	_, hasKey := selfUpdateConfigured()
	curMode := string(mode.Global.Current())
	modeOK := update.PreflightMode(curMode) == nil

	// Pre-render a banner explaining the current verification posture.
	//
	// It used to have two arms, and BOTH overstated what was enforced: the
	// no-key arm called the update "checksum verified" while the page around it
	// said "signed", and the key arm promised Ed25519 verification against an
	// asset the release pipeline has never produced, so pinning a key broke
	// updates outright. Every release is now verified against the signature it
	// actually carries, so the posture no longer depends on operator setup and
	// the copy says the same thing in both arms.
	var banner string
	switch {
	case !modeOK:
		banner = `<div class="settings-callout">
    <strong>Updates are paused.</strong>
    <span class="text-sm muted">The system is in <code>` + html.EscapeString(curMode) + `</code> mode, which blocks changing the binary. Checking for updates and backups still work; updates resume automatically once the system returns to normal.</span>
  </div>`
	case hasKey:
		banner = `<div class="settings-callout">
    <strong>One-click updates are ready.</strong>
    <span class="text-sm muted">Every release is checked against the signature its build published, and installed only if that signature was made by this project&rsquo;s own release workflow &mdash; so a binary from anywhere else is refused even if it downloads cleanly. You have also pinned a release key, which is required on top. The binary is then swapped atomically and the service restarts. A database backup first is optional (checkbox below).</span>
  </div>`
	default:
		banner = `<div class="settings-callout">
    <strong>One-click updates are ready.</strong>
    <span class="text-sm muted">Every release is checked against the signature its build published, and installed only if that signature was made by this project&rsquo;s own release workflow &mdash; so a binary from anywhere else is refused even if it downloads cleanly. Nothing to configure: this applies to every install. The binary is then swapped atomically and the service restarts. A database backup first is optional (checkbox below).</span>
  </div>`
	}

	// WHAT A RESTART COSTS, on the page where restarts are decided (ADR-0155 P4).
	//
	// This page's whole job is to offer an action that stops the service, and it
	// has never said what that action costs. On an install without socket
	// activation the startup time IS the outage, and the number lived only in a
	// journal line the operator could not read without root. Measured here,
	// quoted as a range, and paired with whether the socket queues — because the
	// same number means "everyone gets an error" or "everyone waits" depending
	// on that, and those are different decisions.
	cost := readStartupCost(r.Context(), a.siteSettings, socketActivated)
	banner += `<div class="settings-callout"><strong>What restarting costs here.</strong> ` +
		`<span class="text-sm muted">` + html.EscapeString(cost.Describe()) + `</span></div>`

	// If the root agent had to repair this install after a failed update, say so
	// here — this is the page the operator opens next, and an install that
	// silently rolled itself back to an older binary while they were not looking
	// is exactly the kind of thing they must not have to deduce from the version
	// number. Empty for the overwhelming majority of installs, which have never
	// needed it.
	banner += binaryRepairNotice()

	historyRows := a.updateHistoryRowsHTML(r)

	// The in-app pre-update backup gzips the whole database inside the request,
	// which is unsafe on a large DB (it can swap-thrash a small VPS). For a large
	// DB, default the checkbox OFF and explain the safe path; otherwise keep it on.
	dbSize := dbSizeBytes()
	backupChecked := " checked"
	backupNote := `Recommended for most sites. A binary update never changes your database and the previous binary is kept for rollback, so you can safely untick this — handy for very large databases where a full snapshot is slow. For a downloadable copy, use Export below.`
	if dbSize > inlineBackupMaxBytes {
		backupChecked = ""
		backupNote = `Your database is large (` + html.EscapeString(humanBytes(dbSize)) + `), so the in-app backup is turned off by default — gzipping a database this size inside the update can overload the server. A binary update never changes your database and the previous binary is kept for rollback. To keep a copy, snapshot it during a quiet window or use Export below <strong>before</strong> updating.`
	}

	// Start disabled; the on-load check enables it only when an update is
	// actually available and the mode allows applying.
	applyDisabled := " disabled"

	iconHistory := `<svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="7" stroke="currentColor" stroke-width="1.4"/><path d="M10 5.6V10l2.9 1.8" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>`

	historyBody := `<div class="table-wrap"><table class="table">
    <thead><tr><th>#</th><th>From</th><th>To</th><th>Status</th><th>Detail</th><th>When</th></tr></thead>
    <tbody data-history-body>` + historyRows + `</tbody>
  </table></div>`

	body := `<div class="page-header">
  <h1>Update &amp; Migration</h1>
  <div class="page-actions">
    <span class="text-sm muted">Current version <strong>v` + html.EscapeString(Version) + `</strong> · mode <strong>` + html.EscapeString(curMode) + `</strong></span>
  </div>
</div>
<p class="page-sub">Keep VayuPress current and your data safe — one-click updates that refuse anything not signed by this project, and full, checksummed database backups. Tap a card to expand it.</p>
` + banner + `
<div class="section-head"><span class="section-head__title">Install an update</span><span class="section-head__hint">Signature checked · auto-backup · atomic swap</span></div>
<div class="upd-hero" data-update-card>
  <div class="upd-hero__aura" aria-hidden="true"></div>
  <div class="upd-hero__head">
    <span class="upd-hero__badge">Software update</span>
    <p class="upd-hero__lead">Install the latest VayuPress release in one click — the download is refused unless it carries a valid signature from this project&rsquo;s release workflow, then automatic database backup, atomic swap and restart, all handled for you.</p>
  </div>
  <div class="upd-vers" data-update-state>
    <div class="upd-ver">
      <span class="upd-ver__label">Installed</span>
      <span class="upd-ver__num">v` + html.EscapeString(Version) + `</span>
    </div>
    <span class="upd-ver__arrow" aria-hidden="true">
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none"><path d="M4 12h15M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </span>
    <div class="upd-ver">
      <span class="upd-ver__label">Latest release</span>
      <span class="upd-ver__num upd-ver__num--latest" data-latest-version>—</span>
    </div>
    <div class="upd-ver upd-ver--status">
      <span class="upd-ver__label">Status</span>
      <span class="upd-status" data-update-status>Not checked yet</span>
    </div>
  </div>
  <div class="update-notes" data-update-notes hidden></div>
  <div class="upd-opts">
    <label class="upd-check">
      <input type="checkbox" data-update-backup` + backupChecked + `> <span>Back up the database first</span>
    </label>
    <div class="upd-opt-note">` + backupNote + `</div>
    <label class="upd-check">
      <input type="checkbox" data-update-prerelease> <span>Include pre-release &amp; development builds</span>
    </label>
    <div class="upd-opt-note">Off installs only stable releases. Turn on to also offer the newest <strong>unreleased</strong> pre-release build when one is published — useful for early testing. Verification is unchanged: a pre-release is signed by the same workflow and checked the same way.</div>
  </div>
  <div class="upd-actions" data-actions-wrap>
    <button type="button" class="btn btn--ghost btn--sm" data-update-check>Check for updates</button>
    <button type="button" class="btn btn--primary btn--sm" data-update-apply` + applyDisabled + `>Update now</button>
    <button type="button" class="btn btn--ghost btn--sm" data-update-rollback>Roll back</button>
    <span class="text-xs muted" data-update-msg role="status" aria-live="polite"></span>
  </div>
</div>

` + provisionCardHTML() + `
<div class="section-head"><span class="section-head__title">Update history</span><span class="section-head__hint">Every check, install and rollback</span></div>
<div class="mon-stack">` +
		monAcc(iconHistory, "Update history", "Every check, install and rollback, newest first", "", false, historyBody) +
		`</div>
<p class="text-sm muted mt-4">Backups moved to <a href="/os/vayukeep">Operations → Backup &amp; Recovery</a> — automatic copies, manual export and import, and restore, all in one place.</p>

<script nonce="` + nonce + `" src="/os/static/js/admin-os-update.js?v=` + assetVer("js/admin-os-update.js") + `"></script>`

	writeOSHTML(w, r, adminOSLayout(nonce, "Update & Migration", "update", cfg, htmpl.HTML(body)))
}

// updateHistoryRowsHTML renders the most recent update_history rows as table
// rows (escaped). Returns an empty-state row when there is no history.
func (a *App) updateHistoryRowsHTML(r *http.Request) string {
	if a.updateStore == nil {
		return `<tr><td colspan="6" class="muted">Update history unavailable.</td></tr>`
	}
	recs, err := a.updateStore.List(r.Context(), 25)
	if err != nil || len(recs) == 0 {
		return `<tr><td colspan="6" class="muted">No update activity recorded yet.</td></tr>`
	}
	var b strings.Builder
	for _, rec := range recs {
		when := config.FormatSite(rec.StartedAt, "2 Jan 2006 15:04")
		b.WriteString(`<tr>
  <td class="muted">` + strconv.FormatInt(rec.ID, 10) + `</td>
  <td>` + html.EscapeString(dashOr(rec.FromVersion)) + `</td>
  <td>` + html.EscapeString(dashOr(rec.ToVersion)) + `</td>
  <td>` + updateStatusPill(rec.Status) + `</td>
  <td class="muted text-sm">` + html.EscapeString(rec.Detail) + `</td>
  <td class="muted text-sm">` + html.EscapeString(when) + `</td>
</tr>`)
	}
	return b.String()
}

func updateStatusPill(status string) string {
	cls := "status-pill"
	switch status {
	case "success":
		cls = "status-pill status-pill--live"
	case "failed":
		cls = "status-pill status-pill--draft"
	}
	return `<span class="` + cls + `">` + html.EscapeString(status) + `</span>`
}

func dashOr(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// ── JSON APIs ─────────────────────────────────────────────────────────────────

// handleOSUpdateCheck queries GitHub for the latest release (read-only). It
// records the check in update_history, matching the CLI `update check`.
func (a *App) handleOSUpdateCheck(w http.ResponseWriter, r *http.Request) {
	// An optional GitHub token raises the API rate limit (60→5000/hour), so a box
	// that checks often no longer gets a confusing "unable to check".
	if update.AuthToken == "" {
		if t := strings.TrimSpace(os.Getenv("VAYU_UPDATE_TOKEN")); t != "" {
			update.AuthToken = t
		} else if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" {
			update.AuthToken = t
		}
	}
	includePre := isTruthyParam(r.URL.Query().Get("prerelease"))
	client := &http.Client{Timeout: 30 * time.Second, Transport: safeOutboundTransport()}
	rel, err := update.CheckLatestChannel(r.Context(), client, updateOwner, updateRepo, includePre)
	if err != nil {
		// Surface the underlying reason (rate limit, network, etc.) verbatim so the
		// panel shows something actionable instead of a bare "unable to check".
		writeAPIError(w, r, http.StatusBadGateway, "check-failed", err.Error(), "")
		return
	}
	available := update.UpdateAvailable(Version, rel.Version)
	if a.updateStore != nil {
		_, _ = a.updateStore.Log(r.Context(), update.Record{
			FromVersion: Version, ToVersion: rel.Version, Status: "checked",
			Detail: fmt.Sprintf("current=%s latest=%s available=%t (via VayuOS)", Version, rel.Version, available),
		})
	}
	enabled, hasKey := selfUpdateConfigured()
	modeOK := update.PreflightMode(string(mode.Global.Current())) == nil
	writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"current":   Version,
		"latest":    rel.Version,
		"available": available,
		"notes":     rel.Notes,
		"url":       rel.URL,
		"canApply":  modeOK,
		// "signed" reported whether an operator had pinned a key, which never had
		// anything to do with whether the release was signed — and read as though
		// it did. Every release is signature-verified now, so it says so; hasKey
		// stays for the separate, optional Ed25519 pin.
		"signed":     true,
		"enabled":    enabled,
		"hasKey":     hasKey,
		"mode":       string(mode.Global.Current()),
		"prerelease": includePre,
	})
}

// latestUpdateNotice reports whether a newer release is known to exist,
// returning its version. It reads ONLY the cached update_history rows (the most
// recent "checked" record), never the network, so it is cheap enough to call on
// every page render for the topbar bell. It stays silent in a Tor Space — the
// anonymous world never advertises a clearnet update (ADR-0141 anti-leak).
func (a *App) latestUpdateNotice(ctx context.Context) (string, bool) {
	if a.updateStore == nil || config.Cfg.OnionMode {
		return "", false
	}
	recs, err := a.updateStore.List(ctx, 25)
	if err != nil {
		return "", false
	}
	for _, rec := range recs {
		if rec.Status != "checked" || rec.ToVersion == "" {
			continue
		}
		// Recompute against the RUNNING version so a stale "available" row from
		// before an upgrade never lingers: once we are on that version it is false.
		if update.UpdateAvailable(Version, rec.ToVersion) {
			return rec.ToVersion, true
		}
		return "", false // the most recent check says we are up to date
	}
	return "", false
}

// startUpdateWatcher periodically checks GitHub for a newer release and
// records the result in update_history, so the topbar bell can surface "update
// available" without the operator ever opening this page. Read-only and
// clearnet-only: it never runs in a Tor Space (anti-leak, ADR-0141), and it only
// writes a history row when the answer CHANGES, to keep the log clean.
func (a *App) startUpdateWatcher(done <-chan struct{}) {
	if a.updateStore == nil || config.Cfg.OnionMode {
		return
	}
	check := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		client := &http.Client{Timeout: 30 * time.Second, Transport: safeOutboundTransport()}
		rel, err := update.CheckLatestChannel(ctx, client, updateOwner, updateRepo, false)
		if err != nil {
			return
		}
		// Skip logging when the latest release is unchanged since the last check.
		if recs, err := a.updateStore.List(ctx, 25); err == nil {
			for _, rec := range recs {
				if rec.Status == "checked" {
					if rec.ToVersion == rel.Version {
						return
					}
					break
				}
			}
		}
		available := update.UpdateAvailable(Version, rel.Version)
		_, _ = a.updateStore.Log(ctx, update.Record{
			FromVersion: Version, ToVersion: rel.Version, Status: "checked",
			Detail: fmt.Sprintf("current=%s latest=%s available=%t (auto)", Version, rel.Version, available),
		})
	}
	go func() {
		// Let boot settle before the first network call.
		select {
		case <-done:
			return
		case <-time.After(2 * time.Minute):
		}
		check()
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				check()
			}
		}
	}()
}

// isTruthyParam reports whether a query/form value means "on" (1/true/yes/on).
func isTruthyParam(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// handleOSUpdateApply verifies and installs the latest release. With
// {"restart": true} it re-execs the process to activate the new binary; with
// {"dryRun": true} it verifies signatures without writing anything.
func (a *App) handleOSUpdateApply(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}
	// Backup defaults to ON when the field is absent, so older callers / the CLI
	// keep their safe behaviour; the VayuOS panel sends it explicitly from the
	// operator's checkbox. A pointer lets us tell "omitted" from "false".
	var body struct {
		DryRun     bool  `json:"dryRun"`
		Restart    bool  `json:"restart"`
		Backup     *bool `json:"backup"`
		Prerelease bool  `json:"prerelease"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // empty body → zero-value defaults
	backup := body.Backup == nil || *body.Backup

	// Guard against the most common one-click-update failure on large catalogues:
	// the in-request gzip of a multi-GB database reads the whole file and can
	// swap-thrash a memory-constrained VPS, so the update appears to fail (or
	// hangs) every time. Refuse the inline backup fast — before downloading or
	// touching anything — with the safe path, rather than attempting it. The
	// binary is left untouched, so retrying with backup off succeeds.
	if backup && !body.DryRun {
		if sz := dbSizeBytes(); sz > inlineBackupMaxBytes {
			writeAPIError(w, r, http.StatusPreconditionFailed, "backup-too-large",
				"Your database is "+humanBytes(sz)+", which is too large to back up safely from inside the update — gzipping it here can overload the server. "+
					"Untick “Back up the database first” and click Update now (a binary update never changes your database, and the previous binary is kept for rollback), "+
					"or take a snapshot during a quiet window / use Export first, then update.", "")
			return
		}
	}

	curMode := string(mode.Global.Current())
	// The caller is an authenticated admin who explicitly clicked Update — that
	// is the opt-in. We only refuse in modes that forbid mutating the binary.
	// Verification still happens in ApplyVerified, and is no longer optional:
	// the release's Sigstore signature is required and pinned to the project's
	// release workflow, with the checksum kept for a clearer transport error.
	if err := update.PreflightMode(curMode); err != nil {
		writeAPIError(w, r, http.StatusPreconditionFailed, "preflight", err.Error(), "")
		return
	}

	binPath, err := os.Executable()
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "exe-error", err.Error(), "")
		return
	}
	// Follow symlinks to the real file. An enterprise deployment runs VayuPress
	// from a service-owned writable directory (e.g. /var/lib/vayupress/bin) and
	// exposes /usr/local/bin/vayupress as a symlink to it, so the atomic swap must
	// target the resolved file, never the symlink.
	realPath := update.ResolveInstallPath(binPath)
	// Preflight: the real binary's directory must be writable by the service
	// account, or the atomic swap will fail. The classic cause is running from a
	// root-owned /usr/local/bin (which the non-root service cannot write, and
	// which systemd ProtectSystem also mounts read-only) — fail fast with the
	// permanent fix rather than a confusing mid-update error.
	if why := binaryDirWritable(realPath); why != "" {
		writeAPIError(w, r, http.StatusPreconditionFailed, "binary-readonly",
			updateReadonlyHelp(realPath, why), "")
		return
	}

	// Ask VayuKeep for a restore point from immediately BEFORE the upgrade. This
	// is the moment the old upgrade-only backup was accidentally right about, and
	// the one an operator most often needs to roll back to. It never blocks or
	// fails the update (ADR-0145).
	if !body.DryRun {
		a.vayuKeepPreflight("an in-place update")
	}

	st := a.updateStore
	var histID int64
	if st != nil {
		histID, _ = st.Log(r.Context(), update.Record{FromVersion: Version, Status: "started", Detail: fmt.Sprintf("dry_run=%t (via VayuOS)", body.DryRun)})
	}

	// A generous timeout: release binaries can be large and links slow.
	client := &http.Client{Timeout: 15 * time.Minute, Transport: safeOutboundTransport()}
	opt := update.ApplyOptions{
		Current:           Version,
		DryRun:            body.DryRun,
		BinaryPath:        realPath, // swap the resolved real file, not a launch-time symlink
		IncludePrerelease: body.Prerelease,
	}
	// Pre-update database backup is the operator's choice. When enabled we point
	// ApplyVerified at the DB so it snapshots before swapping the binary; when
	// disabled we leave DBPath empty so it skips the backup entirely. A binary
	// update never rewrites the database, and the previous binary is always kept
	// as <binary>.bak for instant rollback, so skipping is safe — and it avoids a
	// slow/failing snapshot stalling the update on very large databases.
	if backup {
		opt.DBPath = config.Cfg.DBPath
		opt.BackupDir = config.Cfg.CacheDir + "/update-backups"
	}
	newVersion, err := update.ApplyVerified(r.Context(), client, updateOwner, updateRepo, opt, st)
	if err != nil {
		if st != nil && histID > 0 {
			_ = st.MarkComplete(r.Context(), histID, "failed", err.Error())
		}
		msg := err.Error()
		// Make the most common, recoverable failure self-explanatory: the
		// pre-update backup couldn't be written (slow/large DB, low space). The
		// binary was NOT touched, so the operator can simply retry without backup.
		if backup && strings.Contains(msg, "backup") {
			msg = "The pre-update database backup could not be completed, so the update was not applied (your binary is unchanged). " +
				"Untick “Back up the database first” and try again — a binary update never modifies your database, and the previous binary is kept for rollback — or take a backup from the Export section first. Original error: " + msg
		}
		writeAPIError(w, r, http.StatusBadGateway, "apply-failed", msg, "")
		return
	}

	if body.DryRun {
		if st != nil && histID > 0 {
			_ = st.MarkComplete(r.Context(), histID, "checked", "dry-run verification passed for "+newVersion)
		}
		writeJSON(w, r, http.StatusOK, map[string]interface{}{
			"status": "verified", "version": newVersion,
			"note": "Signature + checksum verified. Nothing was written (dry run).",
		})
		return
	}

	if st != nil && histID > 0 {
		_ = st.MarkComplete(r.Context(), histID, "success", "applied "+newVersion+" via VayuOS")
	}
	dbpkg.AuditLog("update.apply", dbpkg.AuditActor(r), newVersion, "binary updated "+Version+" -> "+newVersion+" via VayuOS")
	logging.LogInfo("update", "applied "+newVersion+" via VayuOS admin")

	// Carry the update through to the privileged helper.
	//
	// This closes the gap that made a whole class of fixes undeliverable. The
	// helper ships its OWN copies of the reconcile and firewall scripts, so a bug
	// fixed in either of those needs the HELPER upgraded — and the in-app updater
	// only ever swapped the binary. An operator who updates from the panel would
	// take the new app and keep the old firewall script indefinitely, with the
	// panel showing everything healthy. That is exactly how a firewall that could
	// not be re-applied survived across releases.
	//
	// The consent is the same as the button's: an operator clicked "Update now",
	// which is a request to be on the new version, and the helper is part of the
	// version. The app still supplies ONE BIT — the helper picks its own source
	// and verifies the signature before running anything, so this changes what
	// triggers an upgrade and nothing about what is trusted.
	//
	// Skipped when the helper is too old to act on it: the flag would sit unread
	// forever, and a request nobody will ever answer is worse than none.
	if shieldAgentSupportsSelfUpgrade() {
		if err := shieldRequestAgentUpgrade(); err != nil {
			logging.LogWarn("update", "could not ask the VayuShield helper to upgrade itself: "+err.Error())
		} else {
			logging.LogInfo("update", "asked the VayuShield helper to upgrade itself to match "+newVersion)
		}
	}

	if body.Restart {
		update.ScheduleRestartExec(realPath, 1500*time.Millisecond, restartCleanup)
		writeJSON(w, r, http.StatusOK, map[string]interface{}{
			"status": "updated-restarting", "version": newVersion,
			"note": "Update installed. The service is re-launching to activate v" + newVersion + ".",
		})
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"status": "updated", "version": newVersion,
		"note": update.RestartInstructions(newVersion),
	})
}

// handleOSUpdateRestart re-execs the running process. Used to activate an
// already-installed update or a staged database restore.
func (a *App) handleOSUpdateRestart(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}
	dbpkg.AuditLog("update.restart", dbpkg.AuditActor(r), "", "operator-initiated restart via VayuOS")
	update.ScheduleRestart(1200*time.Millisecond, restartCleanup)
	writeJSON(w, r, http.StatusOK, map[string]interface{}{"status": "restarting"})
}

// handleOSUpdateRollback swaps the previous binary (kept as <binary>.bak by a
// prior apply) back over the running binary, then restarts to activate it.
func (a *App) handleOSUpdateRollback(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}
	binPath, err := os.Executable()
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "exe-error", err.Error(), "")
		return
	}
	// The prior apply kept the old binary as <realfile>.bak next to the resolved
	// real file, so resolve symlinks before locating and restoring it.
	realPath := update.ResolveInstallPath(binPath)
	bak := realPath + ".bak"
	if _, err := os.Stat(bak); err != nil {
		writeAPIError(w, r, http.StatusNotFound, "no-rollback", "No rollback artifact found — nothing to roll back to.", "")
		return
	}

	st := a.updateStore
	var histID int64
	if st != nil {
		histID, _ = st.Log(r.Context(), update.Record{ToVersion: Version, Status: "started", Detail: "rollback (via VayuOS)"})
	}
	if err := os.Rename(bak, realPath); err != nil {
		if st != nil && histID > 0 {
			_ = st.MarkComplete(r.Context(), histID, "failed", "rollback: "+err.Error())
		}
		writeAPIError(w, r, http.StatusInternalServerError, "rollback-failed", err.Error(), "")
		return
	}
	if st != nil && histID > 0 {
		_ = st.MarkComplete(r.Context(), histID, "rolled_back", "rolled back from "+Version)
	}
	dbpkg.AuditLog("update.rollback", dbpkg.AuditActor(r), "", "rolled back binary via VayuOS")
	update.ScheduleRestartExec(realPath, 1200*time.Millisecond, restartCleanup)
	writeJSON(w, r, http.StatusOK, map[string]interface{}{"status": "rolled-back-restarting"})
}

// handleOSUpdateHistory returns recent update_history rows as JSON.
func (a *App) handleOSUpdateHistory(w http.ResponseWriter, r *http.Request) {
	if a.updateStore == nil {
		writeJSON(w, r, http.StatusOK, map[string]interface{}{"history": []any{}})
		return
	}
	recs, err := a.updateStore.List(r.Context(), 50)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "history-error", err.Error(), "")
		return
	}
	out := make([]map[string]interface{}, 0, len(recs))
	for _, rec := range recs {
		out = append(out, map[string]interface{}{
			"id":        rec.ID,
			"from":      rec.FromVersion,
			"to":        rec.ToVersion,
			"status":    rec.Status,
			"detail":    rec.Detail,
			"startedAt": rec.StartedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, r, http.StatusOK, map[string]interface{}{"history": out})
}

// ── Backup / export / import ───────────────────────────────────────────────

// snapshotTmpDir returns a directory the service can actually write large
// temporary backup files into, trying the configured TMP_DIR first, then the OS
// temp dir, then the database's own directory (guaranteed writable, since the DB
// lives there). This prevents export failures when TMP_DIR is unset or not
// writable under a hardened service sandbox.
func snapshotTmpDir() string {
	for _, d := range []string{config.Cfg.TmpDir, os.TempDir(), filepath.Dir(config.Cfg.DBPath)} {
		if strings.TrimSpace(d) == "" {
			continue
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			continue
		}
		probe, err := os.CreateTemp(d, ".vp-probe-*")
		if err != nil {
			continue
		}
		name := probe.Name()
		_ = probe.Close()
		_ = os.Remove(name)
		return d
	}
	return os.TempDir()
}

// handleOSBackupExport builds a full snapshot (.tar.gz) and serves it as a
// download. The archive is built to a temp file FIRST so that any failure
// returns a clean JSON error instead of a truncated 0-byte download; it is then
// served with http.ServeContent, which sets a real Content-Length (so the
// browser shows accurate progress) and streams from disk in constant memory
// regardless of size. The write deadline is lifted for large transfers.
func (a *App) handleOSBackupExport(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}

	tmpDir := snapshotTmpDir()
	archive, err := os.CreateTemp(tmpDir, "vp-backup-*.tar.gz")
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "tmp-error",
			"Could not create a temporary file for the backup: "+err.Error(), "")
		return
	}
	archivePath := archive.Name()
	defer os.Remove(archivePath)

	// Build the whole archive before sending any response header.
	exportErr := update.ExportSnapshot(r.Context(), archive, dbpkg.DB, config.Cfg.DBPath, tmpDir, Version)
	closeErr := archive.Close()
	if exportErr != nil {
		logging.LogError("update", "snapshot export failed", exportErr.Error())
		writeAPIError(w, r, http.StatusInternalServerError, "export-failed", "Backup failed: "+exportErr.Error(), "")
		return
	}
	if closeErr != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "export-failed", "Backup failed while flushing: "+closeErr.Error(), "")
		return
	}

	f, err := os.Open(archivePath)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "export-failed", "Backup file unreadable: "+err.Error(), "")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "export-failed", err.Error(), "")
		return
	}
	if fi.Size() == 0 {
		writeAPIError(w, r, http.StatusInternalServerError, "export-empty", "Backup produced an empty archive.", "")
		return
	}

	filename := fmt.Sprintf("vayupress-backup-v%s-%s.tar.gz", Version, time.Now().UTC().Format("20060102T150405Z"))
	// Lift the server WriteTimeout for a potentially large download.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Time{})
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")

	dbpkg.AuditLog("backup.export", dbpkg.AuditActor(r), filename,
		fmt.Sprintf("full snapshot exported via VayuOS (%d bytes)", fi.Size()))

	// ServeContent sets Content-Length, supports range/resume, and streams the
	// file from disk — constant memory, no size limit.
	http.ServeContent(w, r, filename, fi.ModTime(), f)
}

// handleOSBackupImport accepts a multipart upload of a snapshot, validates it,
// stages it for restore, and restarts the service to apply it. The read
// deadline is lifted and the upload is consumed via a streaming MultipartReader
// (never ParseMultipartForm), so there is no size limit and no buffering.
func (a *App) handleOSBackupImport(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}
	// Lift the server ReadTimeout for a potentially large upload.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetReadDeadline(time.Time{})
	}

	mr, err := r.MultipartReader()
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-multipart", "Expected a multipart file upload.", "")
		return
	}

	var manifest *update.SnapshotManifest
	found := false
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		if part.FormName() != "snapshot" {
			_ = part.Close()
			continue
		}
		found = true
		// Pass an empty tmpDir so StageRestore extracts into the database's own
		// directory — same filesystem as the pending-restore target, so the final
		// swap is an atomic rename rather than a cross-device copy.
		manifest, err = update.StageRestore(r.Context(), part, config.Cfg.DBPath, "")
		_ = part.Close()
		if err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "restore-invalid", err.Error(), "")
			return
		}
		break
	}
	if !found {
		writeAPIError(w, r, http.StatusBadRequest, "no-file", `No "snapshot" file field in the upload.`, "")
		return
	}

	detail := "snapshot staged for restore via VayuOS"
	if manifest != nil {
		detail = fmt.Sprintf("staged restore: app=%s created=%s settings=%d via VayuOS",
			manifest.AppVersion, manifest.CreatedAt.Format(time.RFC3339), manifest.SettingsCount)
	}
	dbpkg.AuditLog("backup.import", dbpkg.AuditActor(r), config.Cfg.DBPath, detail)
	logging.LogInfo("update", detail)

	// The staged DB is swapped in by ApplyPendingRestore at next startup; restart
	// now to complete the restore atomically.
	update.ScheduleRestart(1500*time.Millisecond, restartCleanup)
	resp := map[string]interface{}{
		"status": "restoring-restarting",
		"note":   "Backup validated and staged. The service is restarting to load the restored data.",
	}
	if manifest != nil {
		resp["createdAt"] = manifest.CreatedAt.UTC().Format(time.RFC3339)
		resp["appVersion"] = manifest.AppVersion
		resp["settingsCount"] = manifest.SettingsCount
	}
	writeJSON(w, r, http.StatusOK, resp)
}
