// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_vayukeep.go — the Backup & Recovery console (/os/vayukeep, ADR-0145).
//
// A full page under Operations, laid out like Monetization: a status banner, an
// at-a-glance strip, then collapsible cards grouped by section. It is reached
// from the Operations hub, not from a sidebar entry of its own.
//
// The page has one rule it must never break: it does not flatter. "Enabled" is a
// configuration value and worth nothing. What an operator needs to know is how
// much work they would lose right now, and whether anything has ever actually
// read a backup back. Those are the two headline figures, and both can — and
// must be able to — read badly.

import (
	"context"
	"encoding/json"
	"html"
	htmpl "html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/secrets"
	"github.com/johalputt/vayupress/internal/settings"
	"github.com/johalputt/vayupress/internal/vayukeep"
)

var iconArchive = svgIcon("M2.5 4.5h15V8h-15zM4 8h12v8H4zM8 11h4")

var iconKeep = svgIcon("M10 2.5l6 2v5c0 3.8-2.8 6.4-6 7.4-3.2-1-6-3.6-6-7.4v-5l6-2zM7.4 9.8l1.8 1.8 3.4-3.8")

// humanAgo renders "how long ago" in the shortest honest form. A zero time is
// "never" — deliberately not "—", which reads as "not applicable" when it
// actually means "this has not happened".
func humanAgo(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + " min ago"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + " h ago"
	}
	return strconv.Itoa(int(d.Hours()/24)) + " days ago"
}

// keepVerdict is the page's single source of truth for "how are we doing", so
// the banner, the title badge and the stat tiles can never disagree.
type keepVerdict struct {
	Tone     string // "ok" | "warn"
	Chip     string
	Headline string
}

func keepStatusVerdict(st vayukeep.Status, bootErr string, now time.Time) keepVerdict {
	switch {
	case bootErr != "":
		return keepVerdict{"warn", "Refused to start",
			"VayuKeep declined the settings it was given, so <strong>nothing is being backed up automatically</strong>. Your site is unaffected."}
	case !st.Enabled:
		return keepVerdict{"warn", "Not set up",
			"Automatic backup is <strong>off</strong>. Your only copies are the ones you take by hand. Turning it on takes a folder, a passphrase and one button."}
	case st.Paused:
		return keepVerdict{"warn", "Paused",
			"Backups are <strong>paused</strong>: " + html.EscapeString(st.PauseWhy) + ". Nothing new is being saved."}
	case st.LastDrill.IsZero():
		return keepVerdict{"warn", "Unverified",
			"Backups are being written, but <strong>none has been restored yet</strong>. Until a test restore passes, these are files rather than proven backups."}
	case !st.LastDrillOK:
		return keepVerdict{"warn", "Test restore FAILED",
			"The last test restore <strong>failed</strong>: " + html.EscapeString(st.LastDrillError) + ". Treat this as an outage of your recovery path."}
	case st.RPO(now) > 24*time.Hour:
		return keepVerdict{"warn", "Stale",
			"The newest backup is <strong>" + html.EscapeString(humanAgo(st.NewestGen, now)) + "</strong>. Check that writes are reaching the target."}
	}
	return keepVerdict{"ok", "Protected",
		"Backups are running and the last test restore <strong>passed</strong>. You would lose at most " +
			html.EscapeString(humanAgo(st.NewestGen, now)) + " of work."}
}

// osVayuKeepStats is the at-a-glance strip, in the Monetization idiom.
func osVayuKeepStats(st vayukeep.Status, now time.Time) string {
	tile := func(value, label, tone string) string {
		cls := "stat-card"
		if tone != "" {
			cls += " stat-card--" + tone
		}
		return `<div class="` + cls + `"><div class="stat-card__label">` + html.EscapeString(label) +
			`</div><div class="stat-card__value">` + html.EscapeString(value) + `</div></div>`
	}
	rpoVal, rpoTone := "never", "warn"
	if !st.NewestGen.IsZero() {
		rpoVal, rpoTone = humanAgo(st.NewestGen, now), ""
		if st.RPO(now) > 24*time.Hour {
			rpoTone = "warn"
		}
	}
	verVal, verTone := "never", "warn"
	if !st.LastDrill.IsZero() {
		verVal, verTone = humanAgo(st.LastDrill, now), ""
		if !st.LastDrillOK {
			verVal, verTone = "FAILED "+verVal, "warn"
		}
	}
	if !st.Enabled {
		rpoVal, verVal, rpoTone, verTone = "off", "off", "warn", "warn"
	}
	return `<div class="stat-grid">` +
		tile(rpoVal, "You would lose", rpoTone) +
		tile(verVal, "Last verified restore", verTone) +
		tile(strconv.Itoa(st.Generations), "Restore points", "") +
		tile(humanBytes(st.TotalBytes), "Space used", "") +
		`</div>`
}

// detailRow is one label/value line, reusing the connector panel's markup.
func detailRow(label, value string) string {
	return `<div class="cx-detail"><span class="cx-cap">` + html.EscapeString(label) +
		`</span><span>` + html.EscapeString(value) + `</span></div>`
}

// drillSummary renders the test-restore outcome as one honest phrase.
func drillSummary(st vayukeep.Status, now time.Time) string {
	if st.LastDrill.IsZero() {
		return "never — no backup has been restored yet"
	}
	if !st.LastDrillOK {
		return "FAILED " + humanAgo(st.LastDrill, now) + " — " + st.LastDrillError
	}
	s := "passed " + humanAgo(st.LastDrill, now)
	if st.LastDrillRows > 0 {
		s += " (" + strconv.FormatInt(st.LastDrillRows, 10) + " posts read back)"
	}
	return s
}

// ── Cards ────────────────────────────────────────────────────────────────────

// keepSetupCard is the setup form. Everything happens here — choose a folder,
// set a passphrase, press the button. No file editing and no service restart:
// asking an operator to SSH in to enable backups is how installs end up with
// none.
func keepSetupCard(bootErr, currentTarget string, envManaged bool) string {
	problem := ""
	if bootErr != "" {
		problem = `<p class="text-sm"><strong>Backups could not start with the current settings:</strong></p>
<p class="text-sm"><code>` + html.EscapeString(bootErr) + `</code></p>
<p class="text-sm muted">Refusing is deliberate — a backup system that started anyway and quietly did nothing would be worse. Fix it below.</p>
<div class="section-divider"></div>`
	}
	if envManaged {
		return problem + `<p class="text-sm">This install is configured by environment variables (<code>VAYUKEEP_TARGET</code>), so the console does not override it. Change it where those are set, or clear the variable to manage backups from here.</p>`
	}
	target := currentTarget
	if target == "" {
		target = "/var/backups/vayupress"
	}
	return problem + `<p class="text-sm">Pick a folder and a passphrase. VayuPress does the rest — it starts immediately, no restart needed.</p>
<div class="field">
  <label class="field-label" for="vk-target">Where to keep the backups</label>
  <input id="vk-target" class="input" type="text" value="` + html.EscapeString(target) + `" placeholder="/var/backups/vayupress" spellcheck="false">
  <div class="settings-row-hint">Must be outside your site's data folder. The suggested path already works with no other changes.</div>
</div>
<div class="field">
  <label class="field-label" for="vk-pass">Passphrase</label>
  <div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
    <input id="vk-pass" class="input" type="password" autocomplete="new-password" placeholder="At least 12 characters" spellcheck="false" style="flex:1 1 18rem">
    <button type="button" class="btn btn--sm" data-vk-gen>Generate one</button>
    <button type="button" class="btn btn--ghost btn--sm" data-vk-copy>Copy</button>
  </div>
  <div class="settings-row-hint">Make one up, or press <strong>Generate one</strong> for a strong random passphrase you can copy.</div>
  <div id="vk-pass-warn" class="settings-row-hint mt-2" hidden>
    <strong>Save this somewhere other than this server, now.</strong> VayuPress keeps an encrypted copy so backups can run unattended — but that copy lives on the machine your backups are protecting. If you lose the machine, that copy goes with it, and the backups become unreadable by any tool. A password manager, a note on your phone, a piece of paper. There is no reset.
  </div>
</div>
<div class="mt-3" style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
  <button type="button" class="btn btn--primary btn--sm" data-vk-setup>Turn on automatic backup</button>
  <span id="vk-setup-status" role="status" aria-live="polite" class="text-xs muted"></span>
</div>
<div class="section-divider"></div>
<div class="cx-details">` +
		detailRow("What gets saved", "Your whole site — database, media, mailboxes and settings — encrypted, every few minutes while you are working.") +
		detailRow("For real disaster recovery", "Use a separate disk or mounted volume. A copy on the same disk survives a bad edit or a failed migration, but not losing the disk.") +
		detailRow("If a folder is refused", "The service runs sandboxed and may not be allowed to write there. VayuPress tests the folder before saving and tells you exactly what went wrong.") +
		`</div>`
}

// keepStatusCard is the live operational detail plus the two controls.
func keepStatusCard(st vayukeep.Status, now time.Time) string {
	rows := detailRow("Backing up to", st.Target) +
		detailRow("Newest backup", humanAgo(st.NewestGen, now)) +
		detailRow("Last successful write", humanAgo(st.LastSuccess, now)) +
		detailRow("Last test restore", drillSummary(st, now)) +
		detailRow("Restore points kept", strconv.Itoa(st.Generations)+" ("+humanBytes(st.TotalBytes)+")") +
		detailRow("Newest backup size", humanBytes(st.LastGenBytes))
	if st.LastError != "" {
		rows += detailRow("Last error", st.LastError)
	}
	return `<div class="cx-details">` + rows + `</div>
<div class="mt-3" style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
  <button type="button" class="btn btn--primary btn--sm" data-vk-drill>Test restore now</button>
  <button type="button" class="btn btn--sm" data-vk-backup>Back up now</button>
  <button type="button" class="btn btn--ghost btn--sm" data-vk-disable>Turn off</button>
  <span id="vk-status" role="status" aria-live="polite" class="text-xs muted"></span>
</div>
<p class="text-xs muted mt-2"><strong>Test restore</strong> takes your newest backup, unpacks it into a temporary folder, opens the database inside it and checks every page, then deletes it. It never touches your live site. This is the only control on this page that proves a backup actually works.</p>`
}

// keepPointsCard lists the restore points with a per-row integrity check.
func keepPointsCard(gens []vayukeep.Generation, now time.Time) string {
	if len(gens) == 0 {
		return `<p class="text-sm muted">No restore points yet. One is written within a few minutes of your next change, or press <strong>Back up now</strong> above.</p>`
	}
	rows := ""
	for _, g := range gens {
		esc := html.EscapeString(g.Name)
		rows += `<tr><td><code>` + esc + `</code></td><td>` + html.EscapeString(g.Taken.Format("2 Jan 2006 15:04")) + ` UTC</td><td>` +
			html.EscapeString(humanAgo(g.Taken, now)) + `</td><td>` + html.EscapeString(humanBytes(g.Bytes)) + `</td>` +
			`<td><button type="button" class="btn btn--ghost btn--sm" data-vk-verify="` + esc + `">Check</button> ` +
			`<button type="button" class="btn btn--danger btn--sm" data-vk-restore="` + esc + `">Restore</button> ` +
			`<button type="button" class="btn btn--ghost btn--sm" data-vk-delete="` + esc + `">Delete</button></td></tr>`
	}
	return `<p class="text-sm muted">Each entry is a complete, independent copy of your whole site at that moment — database, media, mailboxes and settings. <strong>Check</strong> reads one end to end without writing anything.</p>
<div class="table-wrap"><table class="table">
<thead><tr><th>Restore point</th><th>Taken</th><th>Age</th><th>Size</th><th></th></tr></thead>
<tbody>` + rows + `</tbody></table></div>
<div class="mt-2"><span id="vk-verify-status" role="status" aria-live="polite" class="text-xs muted"></span></div>
<p class="text-xs muted mt-2"><strong>Restore</strong> puts your site back to that moment and restarts. Your current database is copied aside first, so it is reversible. It restores the database — posts, pages, settings, members, comments and mailbox accounts. Uploaded files and stored mail are left alone, because swapping those under a running site is how a half-restored install happens; use the command below for a complete one.</p>`
}

// keepManualCard is the hand-operated half: download a copy to your own machine,
// or restore one you already have. Moved here from Update & Backup so every way
// of protecting and recovering this install lives on one page — an operator
// hunting for "backup" should never have to guess which of two pages has it.
func keepManualCard() string {
	return `<p class="text-sm">Download your whole site as one file, or restore one you downloaded earlier — including onto a different server.</p>
<div class="settings-block-title mt-3">Download a copy</div>
<p class="text-sm muted mb-2">A consistent, checksummed snapshot of the database and every setting, saved to your computer. No size limit.</p>
<a class="btn btn--primary btn--sm" href="/os/api/backup/export" data-backup-export download>Download full backup</a>
<div class="section-divider mt-4"></div>
<div class="settings-block-title mt-4">Restore from a file</div>
<p class="text-sm muted mb-2">Your current database is copied aside first, then the service restarts to load the restored data. <strong>This replaces all current content and settings.</strong></p>
<div class="theme-actions" data-restore-wrap>
  <input type="file" id="backup-file" class="input upd-file" accept=".gz,.tgz,application/gzip,application/x-gzip" data-backup-file>
  <button type="button" class="btn btn--danger btn--sm" data-backup-import>Restore from file</button>
  <span class="text-xs muted" data-backup-msg role="status" aria-live="polite"></span>
</div>
<div class="progress mt-3" data-restore-progress hidden><div class="progress__bar progress__bar--ok w-0" data-restore-bar></div></div>`
}

// keepRetentionCard lets the operator set how much history is kept, so
// "auto-delete old backups" is a control rather than an environment variable.
func keepRetentionCard(gens, days int) string {
	return `<p class="text-sm">Old restore points are deleted automatically. A point survives if it is within <strong>either</strong> limit, so a quiet month cannot age out your only copy.</p>
<div class="field">
  <label class="field-label" for="vk-keep-n">Always keep at least this many</label>
  <input id="vk-keep-n" class="input" type="number" min="1" max="500" value="` + strconv.Itoa(gens) + `" style="max-width:9rem">
</div>
<div class="field">
  <label class="field-label" for="vk-keep-d">And anything from the last (days)</label>
  <input id="vk-keep-d" class="input" type="number" min="1" max="3650" value="` + strconv.Itoa(days) + `" style="max-width:9rem">
</div>
<div class="mt-3" style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
  <button type="button" class="btn btn--sm" data-vk-retention>Save</button>
  <button type="button" class="btn btn--ghost btn--sm" data-vk-prune>Clean up now</button>
  <span id="vk-retention-status" role="status" aria-live="polite" class="text-xs muted"></span>
</div>
<p class="text-xs muted mt-2">Deleting a restore point is permanent — the copy is gone, not moved to a bin.</p>`
}

// keepRestoreCard is the recovery runbook. It leads with the buttons, because an
// operator in trouble should not have to read a manual first; the commands stay
// for the one case the console genuinely cannot cover — a server that will not
// start, or recovering onto a different machine.
func keepRestoreCard(st vayukeep.Status) string {
	target := st.Target
	if target == "" {
		target = "/var/backups/vayupress"
	}
	t := html.EscapeString(target)
	return `<p class="text-sm"><strong>From this page.</strong> Open <em>Restore points</em> above, press <strong>Check</strong> on the one you want to confirm it is readable, then <strong>Restore</strong>. VayuPress copies your current database aside, puts the saved one in its place and restarts. Nothing to type but the confirmation.</p>
<div class="section-divider"></div>
<p class="text-sm"><strong>If this site will not start</strong>, or you are recovering onto a different machine, the console is not reachable — so the same job from a shell:</p>
<pre class="code-block"><code>vayupress restore -in ` + t + `/vk-YYYYMMDD-HHMMSS.vpbk -verify
sudo systemctl stop vayupress
vayupress restore -in ` + t + `/vk-YYYYMMDD-HHMMSS.vpbk -dest /var/lib/vayupress
sudo systemctl start vayupress</code></pre>
<p class="text-xs muted">That form also restores uploaded files and stored mail, which the one-click restore leaves alone.</p>
<div class="section-divider"></div>
<div class="cx-details">` +
		detailRow("Your old data is kept", "The restore moves your current data directory aside and prints where. Nothing is deleted until you delete it.") +
		detailRow("A failed restore is safe", "Files are unpacked into a staging folder and only moved into place once the whole archive verifies. A truncated or tampered file leaves your live site untouched.") +
		detailRow("Restoring to a moment in time", "Pick the newest restore point taken at or BEFORE the moment you want — never a later one, since that is the data you are trying to escape.") +
		detailRow("Restoring on a different server", "Copy the file across and run the same command. You need the passphrase; nothing else.") +
		`</div>`
}

// keepSpecCard states what the protection actually is, without overclaiming.
func keepSpecCard(st vayukeep.Status) string {
	rows := detailRow("Encryption", "AES-256-GCM. Each backup gets its own random key, sealed with an Argon2id key derived from your passphrase.") +
		detailRow("Tamper detection", "Every block is chained to the one before it and the file ends with an authenticated end marker, so a truncated, edited or reordered backup fails to open rather than restoring partially.") +
		detailRow("There is no unencrypted mode", "A copy carries member emails, mailbox contents and comment data. Making encryption optional would make the wrong thing easy.") +
		detailRow("Database consistency", "Captured with VACUUM INTO through a single read transaction, so a backup taken while the site is live is consistent. The service never needs stopping.") +
		detailRow("What is included", "Database, media, VayuMail mailboxes, settings and public PGP material.") +
		detailRow("What is excluded", "Keystore secrets never leave the machine, so a stolen backup cannot decrypt your stored third-party credentials.") +
		detailRow("Effect on site speed", "None on any page request. Change detection is two file checks, and both backup and test restore stand aside while the site is busy.")
	if st.Enabled {
		rows += detailRow("Changing the passphrase", "Future backups are sealed with the new one. Keep the old passphrase for as long as you keep backups made with it.")
	}
	return `<div class="cx-details">` + rows + `</div>`
}

// keepScheduleCard explains when it runs and what it keeps.
func keepScheduleCard() string {
	hrs := func(m int) string {
		if m >= 60 && m%60 == 0 {
			return strconv.Itoa(m/60) + " h"
		}
		return strconv.Itoa(m) + " min"
	}
	return `<div class="cx-details">` +
		detailRow("While you are writing", "A new restore point at most every "+hrs(config.Cfg.VayuKeepMinMin)+", and only when something actually changed.") +
		detailRow("While nothing changes", "It backs off to "+hrs(config.Cfg.VayuKeepMaxMin)+", so an idle site does no work at all.") +
		detailRow("Test restore", "Automatically every "+hrs(config.Cfg.VayuKeepDrillMin)+", plus whenever you press the button.") +
		detailRow("Before an update", "A restore point is taken automatically before an in-place update, so you can roll back to the moment before it.") +
		detailRow("How many are kept", strconv.Itoa(config.Cfg.VayuKeepRetainGen)+" restore points OR "+strconv.Itoa(config.Cfg.BackupRetainDays)+" days — whichever keeps more, so a quiet month cannot age out your only copy.") +
		detailRow("If the target breaks", "After repeated failures it stops trying and says so here, rather than retrying into a full disk. A failing backup never slows or blocks your site.") +
		`</div>
<p class="text-xs muted mt-2">Tune with <code>VAYUKEEP_MIN_MINUTES</code>, <code>VAYUKEEP_MAX_MINUTES</code>, <code>VAYUKEEP_DRILL_MINUTES</code>, <code>VAYUKEEP_RETAIN_GENERATIONS</code>. Turn it off with <code>VAYUKEEP_OFF=true</code>.</p>`
}

// ── Page ─────────────────────────────────────────────────────────────────────

// osVayuKeepBody builds the whole Backup & Recovery console.
func osVayuKeepBody(nonce string, st vayukeep.Status, bootErr string, gens []vayukeep.Generation, now time.Time, currentTarget string, envManaged bool) string {
	v := keepStatusVerdict(st, bootErr, now)
	bannerTone := "ok"
	if v.Tone == "warn" {
		bannerTone = "warn"
	}
	body := `<div class="page-header">
  <h1>Backup &amp; Recovery <span class="badge badge--` + bannerTone + `">` + html.EscapeString(v.Chip) + `</span></h1>
  <div class="page-actions"><span id="vk-page-status" role="status" aria-live="polite" class="text-xs muted"></span></div>
</div>
<p class="page-sub">Automatic, encrypted copies of your entire site — database, media, mailboxes and settings — checked on a schedule so you know they actually restore. Tap a card to expand it.</p>
<div class="card"><p class="text-sm">` + v.Headline + `</p></div>
` + osVayuKeepStats(st, now)

	if !st.Enabled || bootErr != "" {
		body += `<div class="section-head"><span class="section-head__title">Get protected</span><span class="section-head__hint">A folder, a passphrase, one button</span></div>
<div class="mon-stack">` +
			monAcc(iconKeep, "Set up automatic backup", "Choose a folder and a passphrase", `<span class="mon-chip">● Not set up</span>`, true, keepSetupCard(bootErr, currentTarget, envManaged)) +
			`</div>`
	} else {
		chipCls := "mon-chip mon-chip--on"
		if v.Tone == "warn" {
			chipCls = "mon-chip"
		}
		chip := `<span class="` + chipCls + `">● ` + html.EscapeString(v.Chip) + `</span>`
		body += `<div class="section-head"><span class="section-head__title">Protection</span><span class="section-head__hint">What is saved, and proof that it restores</span></div>
<div class="mon-stack">` +
			monAcc(iconKeep, "Status &amp; controls", "Back up now, or prove a restore works", chip, true, keepStatusCard(st, now)) +
			monAcc(iconVCB, "Restore points", strconv.Itoa(len(gens))+" saved · "+humanBytes(st.TotalBytes), "", false, keepPointsCard(gens, now)) +
			`</div>`
	}

	body += `<div class="section-head"><span class="section-head__title">Recovery</span><span class="section-head__hint">Exactly what to do when you need it</span></div>
<div class="mon-stack">` +
		monAcc(iconVCB, "How to restore", "One click here, or from a shell if the site will not start", "", false, keepRestoreCard(st)) +
		monAcc(iconArchive, "Manual backup &amp; restore", "Download a copy, or restore one you already have", "", false, keepManualCard()) +
		`</div>

<div class="section-head"><span class="section-head__title">How it works</span><span class="section-head__hint">The guarantees, stated plainly</span></div>
<div class="mon-stack">` +
		monAcc(iconKey, "Encryption &amp; safety", "What is protected, and what deliberately is not", "", false, keepSpecCard(st)) +
		monAcc(iconVCB, "Schedule &amp; retention", "When it runs and how much it keeps", "", false, keepScheduleCard()) +
		monAcc(iconArchive, "Housekeeping", "How long copies are kept, and deleting them", "", false,
			keepRetentionCard(config.Cfg.VayuKeepRetainGen, config.Cfg.BackupRetainDays)) +
		`</div>

<script nonce="` + nonce + `">
(function(){'use strict';
function csrf(){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
function toast(msg,kind){if(window.vpToast){window.vpToast(msg,kind);}}
// Every control reports the real outcome. The test restore is synchronous on
// purpose: an operator asking whether their backups work is owed the answer they
// waited for, not an optimistic "started" that a later failure never corrects.
function vkPost(url,payload,btn,working,outId){
  var out=document.getElementById(outId||'vk-status');
  var label=btn?btn.textContent:'';
  if(btn){btn.disabled=true;btn.textContent=working;}
  if(out){out.textContent='Working…';}
  fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify(payload||{})})
    .then(function(r){return r.json().catch(function(){return {ok:false,detail:'Unexpected response ('+r.status+').'};});})
    .then(function(d){
      if(out){out.textContent=d.detail||'';}
      toast(d.detail||'Done',d.ok?'success':'error');
      if(d.restart){
        setTimeout(function(){
          fetch('/os/api/power/restart',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:'{}'})
            .finally(function(){setTimeout(function(){location.reload();},6000);});
        },800);
      } else if(d.reload){setTimeout(function(){location.reload();},1500);}
    })
    .catch(function(e){
      var m='Request failed: '+e;
      if(out){out.textContent=m;}
      toast(m,'error');
    })
    .finally(function(){ if(btn){btn.disabled=false;btn.textContent=label;} });
}
var b=document.querySelector('[data-vk-backup]');
if(b){b.addEventListener('click',function(){vkPost('/os/api/vayukeep/backup',{},b,'Saving…');});}
var d=document.querySelector('[data-vk-drill]');
if(d){d.addEventListener('click',function(){vkPost('/os/api/vayukeep/drill',{},d,'Restoring…');});}
Array.prototype.forEach.call(document.querySelectorAll('[data-vk-verify]'),function(el){
  el.addEventListener('click',function(){
    vkPost('/os/api/vayukeep/verify',{name:el.getAttribute('data-vk-verify')},el,'Checking…','vk-verify-status');
  });
});
// Generate a passphrase in the browser so it never needs a round trip before
// the operator has it. 20 characters from a 32-symbol unambiguous alphabet is
// ~100 bits — and readable enough to copy onto paper, which is the point.
var genBtn=document.querySelector('[data-vk-gen]');
if(genBtn){genBtn.addEventListener('click',function(){
  var alpha='abcdefghjkmnpqrstuvwxyz23456789'; // no i/l/o/0/1 — they get mistranscribed
  var buf=new Uint8Array(20); (window.crypto||window.msCrypto).getRandomValues(buf);
  var out=''; for(var i=0;i<buf.length;i++){ if(i&&i%5===0)out+='-'; out+=alpha[buf[i]%alpha.length]; }
  var f=document.getElementById('vk-pass');
  if(f){f.type='text';f.value=out;f.focus();f.select();}
  var warn=document.getElementById('vk-pass-warn'); if(warn){warn.hidden=false;}
});}
var copyBtn=document.querySelector('[data-vk-copy]');
if(copyBtn){copyBtn.addEventListener('click',function(){
  var f=document.getElementById('vk-pass');
  if(!f||!f.value){toast('Nothing to copy yet — generate or type a passphrase first.','error');return;}
  f.type='text';f.select();
  var done=function(){toast('Passphrase copied. Save it somewhere other than this server.','success');
    var warn=document.getElementById('vk-pass-warn'); if(warn){warn.hidden=false;}};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(f.value).then(done,function(){document.execCommand('copy');done();});}
  else{document.execCommand('copy');done();}
});}
Array.prototype.forEach.call(document.querySelectorAll('[data-vk-delete]'),function(el){
  el.addEventListener('click',function(){
    var name=el.getAttribute('data-vk-delete');
    vpConfirm({title:'Delete restore point',message:'Delete '+name+' permanently? This copy is gone, not moved to a bin.',confirm:'Delete'},function(){
      vkPost('/os/api/vayukeep/delete',{name:name},el,'Deleting…','vk-verify-status');
    });
  });
});
var retBtn=document.querySelector('[data-vk-retention]');
if(retBtn){retBtn.addEventListener('click',function(){
  var n=document.getElementById('vk-keep-n'), d=document.getElementById('vk-keep-d');
  vkPost('/os/api/vayukeep/retention',{generations:parseInt(n?n.value:'0',10),days:parseInt(d?d.value:'0',10)},retBtn,'Saving…','vk-retention-status');
});}
var pruneBtn=document.querySelector('[data-vk-prune]');
if(pruneBtn){pruneBtn.addEventListener('click',function(){
  vpConfirm({title:'Prune restore points',message:'Delete every restore point that is outside both limits?',confirm:'Prune'},function(){
    vkPost('/os/api/vayukeep/prune',{},pruneBtn,'Cleaning…','vk-retention-status');
  });
});}
var setupBtn=document.querySelector('[data-vk-setup]');
if(setupBtn){setupBtn.addEventListener('click',function(){
  var t=document.getElementById('vk-target'), p=document.getElementById('vk-pass');
  vkPost('/os/api/vayukeep/setup',{target:t?t.value:'',passphrase:p?p.value:''},setupBtn,'Setting up…','vk-setup-status');
});}
var offBtn=document.querySelector('[data-vk-disable]');
if(offBtn){offBtn.addEventListener('click',function(){
  vpConfirm({title:'Turn automatic backup off?',message:'Your existing restore points are kept, but no new ones will be made.',confirm:'Turn off'},function(){
    vkPost('/os/api/vayukeep/disable',{},offBtn,'Turning off…');
  });
});}
Array.prototype.forEach.call(document.querySelectorAll('[data-vk-restore]'),function(el){
  el.addEventListener('click',function(){
    var name=el.getAttribute('data-vk-restore');
    // Typed confirmation, not a click. This replaces the live database.
    var typed=window.prompt('This puts your site back to '+name+' and restarts.\n\nYour current database is copied aside first, so it is reversible.\n\nType RESTORE to confirm:');
    if(typed!=='RESTORE')return;
    vkPost('/os/api/vayukeep/restore',{name:name,confirm:typed},el,'Restoring…','vk-verify-status');
  });
});
})();
</script>
<script nonce="` + nonce + `" src="/os/static/js/admin-os-update.js?v=` + assetVer("js/admin-os-update.js") + `"></script>`
	return body
}

// handleOSVayuKeep renders the Backup & Recovery console.
func (a *App) handleOSVayuKeep(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())
	csrfTokenFor(w, r)
	st := a.vayuKeepStatus()
	var gens []vayukeep.Generation
	if a.vayuKeep != nil {
		gens, _ = a.vayuKeep.List()
	}
	envManaged := strings.TrimSpace(config.Cfg.VayuKeepTarget) != ""
	writeOSHTML(w, r, adminOSLayout(nonce, "Backup & Recovery", "operations", cfg,
		htmpl.HTML(osVayuKeepBody(nonce, st, a.vayuKeepErr, gens, time.Now().UTC(),
			a.resolveKeepTarget(r.Context()), envManaged))))
}

// ── Endpoints ────────────────────────────────────────────────────────────────

// keepGuard rejects the request unless an admin is asking and replication runs.
func (a *App) keepGuard(w http.ResponseWriter, r *http.Request) bool {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "administrator access required", "")
		return false
	}
	if a.vayuKeep == nil || !config.Cfg.VayuKeepEnabled {
		writeAPIError(w, r, http.StatusServiceUnavailable, "vayukeep-off", "automatic backup is not set up", "")
		return false
	}
	return true
}

// handleOSVayuKeepBackup takes a restore point on demand.
func (a *App) handleOSVayuKeepBackup(w http.ResponseWriter, r *http.Request) {
	if !a.keepGuard(w, r) {
		return
	}
	a.vayuKeep.TriggerNow()
	writeJSON(w, r, http.StatusOK, map[string]any{
		"ok":     true,
		"reload": true,
		"detail": "A new restore point was requested — it appears in the list once written.",
	})
}

// handleOSVayuKeepDrill runs a test restore synchronously and reports the real
// outcome, then asks the page to reload so the status reflects it.
func (a *App) handleOSVayuKeepDrill(w http.ResponseWriter, r *http.Request) {
	if !a.keepGuard(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	res := a.vayuKeep.Drill(ctx)
	detail := "Test restore PASSED — your newest backup unpacked and its database checked out clean."
	if res.Rows > 0 {
		detail += " " + strconv.FormatInt(res.Rows, 10) + " posts were read back."
	}
	if !res.OK {
		detail = "Test restore FAILED — " + res.Err
	}
	writeJSON(w, r, http.StatusOK, map[string]any{
		"ok": res.OK, "detail": detail, "reload": true,
		"generation": res.Generation, "ms": res.Duration.Milliseconds(),
	})
}

// handleOSVayuKeepVerify reads one named restore point end to end without
// writing anything.
func (a *App) handleOSVayuKeepVerify(w http.ResponseWriter, r *http.Request) {
	if !a.keepGuard(w, r) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	// Resolve the name against our own listing rather than joining it onto a
	// path. The value arrives from the browser, so treating it as a filename
	// would make this a path-traversal primitive; matching it against generations
	// we already found means an unknown value is simply not found.
	gens, err := a.vayuKeep.List()
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "vayukeep-error", err.Error(), "")
		return
	}
	for _, g := range gens {
		if g.Name != body.Name {
			continue
		}
		if verr := a.vayuKeep.VerifyGeneration(g); verr != nil {
			writeJSON(w, r, http.StatusOK, map[string]any{
				"ok":     false,
				"detail": g.Name + " is NOT usable — " + verr.Error(),
			})
			return
		}
		writeJSON(w, r, http.StatusOK, map[string]any{
			"ok":     true,
			"detail": g.Name + " checks out: the passphrase is right, every block authenticates, the chain is unbroken and the file is complete.",
		})
		return
	}
	writeAPIError(w, r, http.StatusNotFound, "not-found", "no restore point by that name", "")
}

// handleOSVayuKeepSetup turns automatic backup on from the console: it validates
// the folder, seals the passphrase, saves the setting and restarts the engine —
// no file editing, no service restart.
func (a *App) handleOSVayuKeepSetup(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "administrator access required", "")
		return
	}
	if a.siteSettings == nil || a.secrets == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "settings storage is not ready", "")
		return
	}
	var body struct {
		Target     string `json:"target"`
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "Invalid request body", "")
		return
	}
	target := strings.TrimSpace(body.Target)
	pass := strings.TrimSpace(body.Passphrase)

	if target == "" {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": false, "detail": "Choose a folder to keep the backups in."})
		return
	}
	// Sanitise FIRST, and use only what comes back. Everything below — the
	// data-directory check, the write test, and what gets stored — operates on the
	// validated value, so no path derived from the request body ever reaches a
	// filesystem call unchecked.
	safeTarget, terr := sanitizeKeepTarget(target)
	if terr != nil {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": false, "detail": terr.Error()})
		return
	}
	target = safeTarget
	// A short passphrase on the one artefact that leaves the machine is not a
	// preference to respect. Refuse it here rather than let an operator believe
	// they are protected.
	existing := a.resolveKeepPassphrase(r.Context())
	if pass == "" && existing == "" {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": false, "detail": "Set a passphrase. It is the only key to these backups — without it nobody, including you, can read them."})
		return
	}
	if pass != "" && len(pass) < 12 {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": false, "detail": "Use at least 12 characters. This one passphrase protects every copy of your whole site."})
		return
	}

	// Reject a target inside the data directory before saving it, so the console
	// gives the same answer the engine would — with the reason.
	dataDir := filepath.Dir(config.Cfg.DBPath)
	if abs, err := filepath.Abs(filepath.Clean(target)); err == nil {
		if rel, rerr := filepath.Rel(dataDir, abs); rerr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			writeJSON(w, r, http.StatusOK, map[string]any{"ok": false,
				"detail": "That folder is inside your data directory. A copy on the disk it is meant to protect, replicating its own output, is not a backup — pick somewhere outside " + dataDir + "."})
			return
		}
	}
	if err := validateKeepTargetWritable(target); err != nil {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": false,
			"detail": "VayuPress cannot write to " + target + " — " + err.Error() + ". If this is a new location, add it to the service's ReadWritePaths."})
		return
	}

	if pass != "" {
		if _, err := a.secrets.Upsert(r.Context(), secrets.ProviderVayuKeep, "Backup passphrase", "", pass, true, false); err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "secrets-error", err.Error(), "")
			return
		}
	}
	if err := a.siteSettings.SetMany(r.Context(), settings.ForPrimary(), map[string]string{
		settings.KeyVayuKeepTarget:  target,
		settings.KeyVayuKeepEnabled: "true",
	}); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "settings-error", err.Error(), "")
		return
	}
	dbpkg.AuditLog("vayukeep.enable", dbpkg.AuditActor(r), target, "")

	if err := a.applyKeepConfig(r.Context()); err != nil {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": false, "detail": "Saved, but backups could not start: " + err.Error()})
		return
	}
	// Take the first one immediately so the operator sees proof rather than a promise.
	a.vayuKeep.TriggerNow()
	writeJSON(w, r, http.StatusOK, map[string]any{
		"ok": true, "reload": true,
		"detail": "Automatic backup is on. The first copy is being written now — then press Test restore to prove it works.",
	})
}

// handleOSVayuKeepDisable turns automatic backup off. Existing copies are left
// exactly where they are: turning the schedule off is not consent to delete
// what it already saved.
func (a *App) handleOSVayuKeepDisable(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "administrator access required", "")
		return
	}
	if a.siteSettings == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "settings storage is not ready", "")
		return
	}
	if err := a.siteSettings.SetMany(r.Context(), settings.ForPrimary(), map[string]string{settings.KeyVayuKeepEnabled: "false"}); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "settings-error", err.Error(), "")
		return
	}
	dbpkg.AuditLog("vayukeep.disable", dbpkg.AuditActor(r), "", "")
	_ = a.applyKeepConfig(r.Context())
	writeJSON(w, r, http.StatusOK, map[string]any{
		"ok": true, "reload": true,
		"detail": "Automatic backup is off. Your existing restore points are untouched.",
	})
}

// handleOSVayuKeepRestore stages a restore point's database and restarts, so a
// recovery is one click instead of an SSH session.
//
// It restores the DATABASE — posts, pages, settings, members, mailbox metadata,
// comments. Media files and mail message files on disk are not swapped from here,
// because doing that under a running process is how a half-restored install
// happens; the page says so rather than implying a completeness it cannot deliver.
//
// The mechanism is the one already proven for snapshot imports: stage the file
// beside the database, let the boot path swap it in atomically after taking a
// safety copy of the current one, then restart.
func (a *App) handleOSVayuKeepRestore(w http.ResponseWriter, r *http.Request) {
	if !a.keepGuard(w, r) {
		return
	}
	var body struct {
		Name    string `json:"name"`
		Confirm string `json:"confirm"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	// Typed confirmation. This replaces the live database; a misclick must not be
	// enough on its own.
	if strings.TrimSpace(body.Confirm) != "RESTORE" {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": false, "detail": "Type RESTORE to confirm."})
		return
	}

	gens, err := a.vayuKeep.List()
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "vayukeep-error", err.Error(), "")
		return
	}
	var chosen *vayukeep.Generation
	for i := range gens {
		if gens[i].Name == body.Name {
			chosen = &gens[i]
			break
		}
	}
	if chosen == nil {
		writeAPIError(w, r, http.StatusNotFound, "not-found", "no restore point by that name", "")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	staged, err := a.vayuKeepStageRestore(ctx, *chosen)
	if err != nil {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": false, "detail": "Restore could not be prepared — " + err.Error() + ". Nothing was changed."})
		return
	}
	dbpkg.AuditLog("vayukeep.restore", dbpkg.AuditActor(r), chosen.Name, staged)
	writeJSON(w, r, http.StatusOK, map[string]any{
		"ok": true, "restart": true,
		"detail": "Restore prepared from " + chosen.Name + ". Restarting now — your current database is copied aside first, so this is itself reversible.",
	})
}

// handleOSVayuKeepDelete removes one restore point permanently.
//
// Like Check and Restore, the name is resolved against the engine's own listing
// rather than joined onto a path — this endpoint deletes files, so treating a
// browser-supplied string as a filename would be the most dangerous traversal
// primitive on the page.
//
// It refuses to delete the last remaining copy. An operator clearing out old
// backups should not be able to click their way to having none, and the button
// that would do it looks identical to the one that removes the ninth of ten.
func (a *App) handleOSVayuKeepDelete(w http.ResponseWriter, r *http.Request) {
	if !a.keepGuard(w, r) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	gens, err := a.vayuKeep.List()
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "vayukeep-error", err.Error(), "")
		return
	}
	if len(gens) <= 1 {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": false,
			"detail": "That is your only restore point. Take a new one first if you really want to remove it."})
		return
	}
	for _, g := range gens {
		if g.Name != body.Name {
			continue
		}
		if derr := a.vayuKeep.Delete(g); derr != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "vayukeep-error", derr.Error(), "")
			return
		}
		dbpkg.AuditLog("vayukeep.delete", dbpkg.AuditActor(r), g.Name, humanBytes(g.Bytes))
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "reload": true,
			"detail": g.Name + " deleted (" + humanBytes(g.Bytes) + " freed)."})
		return
	}
	writeAPIError(w, r, http.StatusNotFound, "not-found", "no restore point by that name", "")
}

// handleOSVayuKeepRetention saves how much history to keep and applies it.
func (a *App) handleOSVayuKeepRetention(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "administrator access required", "")
		return
	}
	if a.siteSettings == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "settings storage is not ready", "")
		return
	}
	var body struct {
		Generations int `json:"generations"`
		Days        int `json:"days"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	// Both bounds must be at least one. Zero would mean "keep nothing", which no
	// operator means and which the form's own minimums already disallow — this is
	// the guard for anything that does not come from the form.
	if body.Generations < 1 || body.Days < 1 {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": false, "detail": "Both limits must be at least 1."})
		return
	}
	if err := a.siteSettings.SetMany(r.Context(), settings.ForPrimary(), map[string]string{
		settings.KeyVayuKeepRetainGen:  strconv.Itoa(body.Generations),
		settings.KeyVayuKeepRetainDays: strconv.Itoa(body.Days),
	}); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "settings-error", err.Error(), "")
		return
	}
	dbpkg.AuditLog("vayukeep.retention", dbpkg.AuditActor(r),
		strconv.Itoa(body.Generations)+" generations", strconv.Itoa(body.Days)+" days")
	_ = a.applyKeepConfig(r.Context())
	writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "reload": true,
		"detail": "Saved — keeping at least " + strconv.Itoa(body.Generations) + " restore points, and anything from the last " + strconv.Itoa(body.Days) + " days."})
}

// handleOSVayuKeepPrune applies retention immediately instead of at the next cycle.
func (a *App) handleOSVayuKeepPrune(w http.ResponseWriter, r *http.Request) {
	if !a.keepGuard(w, r) {
		return
	}
	before, _ := a.vayuKeep.List()
	if err := a.vayuKeep.Prune(); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "vayukeep-error", err.Error(), "")
		return
	}
	after, _ := a.vayuKeep.List()
	removed := len(before) - len(after)
	detail := "Nothing to clean up — every restore point is still within your limits."
	if removed > 0 {
		detail = strconv.Itoa(removed) + " restore point(s) removed."
		dbpkg.AuditLog("vayukeep.prune", dbpkg.AuditActor(r), strconv.Itoa(removed), "")
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "reload": removed > 0, "detail": detail})
}
