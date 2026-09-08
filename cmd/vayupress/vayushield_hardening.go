// SPDX-License-Identifier: Apache-2.0

package main

// vayushield_hardening.go — safe, in-panel activation of the Tier 2 (kernel
// nftables) and Tier 3 (nginx edge) network-hardening layers, WITHOUT giving
// the web app any privilege.
//
// Privilege separation (see ADR-0123): VayuPress runs as an unprivileged service
// and deliberately cannot touch the kernel firewall or reload nginx. So the panel
// never executes anything privileged. It only expresses INTENT by creating or
// removing an empty flag file in a control directory it owns
// (<state>/vayushield-control/tierN.want). A separate root "reconcile agent"
// (deploy/vayushield-agent.sh, installed once by the updater) polls those flags
// and runs ONLY the fixed, vetted scripts — taking no argument or content from
// the web app, so there is no injection surface. The agent writes back a status
// file (tierN.state) and a heartbeat (agent.alive) that the panel reads to show
// live state and to know whether the helper is installed.

import (
	"context"
	"errors"
	"html"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/safefetch"
	"github.com/johalputt/vayupress/internal/settings"
)

// shieldControlDir returns the directory the panel and the root agent use to
// exchange intent/status files. It defaults beside the state dir and is created
// (owned by the service user) so the unprivileged app can write flags there; the
// root agent only ever reads/writes into this app-owned directory.
func shieldControlDir() string {
	dir := strings.TrimSpace(os.Getenv("VAYUSHIELD_CONTROL_DIR"))
	if dir == "" {
		dir = "/var/lib/vayupress/vayushield-control"
	}
	_ = os.MkdirAll(dir, 0o750)
	return dir
}

// shieldAgentAlive reports whether the root reconcile agent is installed and
// running, by checking the freshness of its heartbeat file (updated every poll).
func shieldAgentAlive() bool {
	fi, err := os.Stat(filepath.Join(shieldControlDir(), "agent.alive"))
	if err != nil {
		return false
	}
	// The agent rewrites the heartbeat every few seconds; treat >45s as dead.
	return time.Since(fi.ModTime()) < 45*time.Second
}

// shieldTierWanted reports whether the operator has requested a tier ON (the
// intent flag exists).
func shieldTierWanted(tier int) bool {
	_, err := os.Stat(filepath.Join(shieldControlDir(), "tier"+strconv.Itoa(tier)+".want"))
	return err == nil
}

// shieldTierState returns the agent-reported state for a tier: "active",
// "inactive", "applying", "removing", "error", or "" (unknown / no agent).
func shieldTierState(tier int) string {
	b, err := os.ReadFile(filepath.Join(shieldControlDir(), "tier"+strconv.Itoa(tier)+".state"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// shieldTierReason returns the agent-recorded short failure reason for a tier
// (from tierN.reason), so the panel can show WHY a tier errored.
func shieldTierReason(tier int) string {
	b, err := os.ReadFile(filepath.Join(shieldControlDir(), "tier"+strconv.Itoa(tier)+".reason"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// shieldSetTierWant creates or removes the intent flag for a tier. This is the
// ONLY privileged-ish action the panel performs — and it is not privileged at
// all: it writes/removes an empty file the service user owns. The root agent
// does the actual apply/remove.
func shieldSetTierWant(tier int, want bool) error {
	flag := filepath.Join(shieldControlDir(), "tier"+strconv.Itoa(tier)+".want")
	if want {
		f, err := os.OpenFile(flag, os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			return err
		}
		return f.Close()
	}
	if err := os.Remove(flag); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// handleOSShieldTier is the admin/CSRF-gated endpoint behind the Tier 2/3
// toggles. It records intent (a flag file) and returns the refreshed hardening
// section so the panel updates in place; the root agent applies the change
// within its next poll and the section auto-refreshes to show the new state.
func (a *App) handleOSShieldTier(w http.ResponseWriter, r *http.Request) {
	tier, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("tier")))
	if tier != 2 && tier != 3 {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "tier must be 2 or 3", "")
		return
	}
	action := strings.TrimSpace(r.PostFormValue("action"))
	if action != "enable" && action != "disable" {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "action must be enable or disable", "")
		return
	}
	if err := shieldSetTierWant(tier, action == "enable"); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "control-error", "Could not record the request: "+err.Error(), "")
		return
	}
	// Return the refreshed section so the toggle updates in place (HTMX swaps the
	// body); the section also self-polls so applying → active appears on its own.
	writeOSFragment(w, a.shieldHardeningBody(r))
}

// ── Helper self-upgrade ──────────────────────────────────────────────────────
//
// The upgrade that used to need a shell. The panel's whole contribution is ONE
// BIT — an empty file — and that is not minimalism, it is the security property.
//
// The agent runs as root. If the web app could hand it code, a URL, a version or
// a path, then compromising the unprivileged web app would mean choosing what a
// root process executes, which is the exact escalation the separation in
// ADR-0123 exists to prevent. So the app says only "the operator asked", and the
// agent decides everything else: it fetches from a repository hardcoded in the
// root-owned script and verifies the signature before running any of it.

// shieldAgentUpgradeState returns the agent's report on the last upgrade
// request: "checking", "restarting", "unverifiable", "error", or "" when none
// has been made.
func shieldAgentUpgradeState() string {
	b, err := os.ReadFile(filepath.Join(shieldControlDir(), "agent.upgrade.state"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// shieldAgentUpgradeDetail returns the agent's explanation for that state.
func shieldAgentUpgradeDetail() string {
	b, err := os.ReadFile(filepath.Join(shieldControlDir(), "agent.upgrade.detail"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// binaryRepairNotice renders what the root agent reports about the binary at the
// install path, or "" when there is nothing to say — which is the case for every
// install that has never had a bad one written over it.
//
// The agent (reconcile_binaryhealth) restores <binary>.bak when the file systemd
// is meant to exec turns out not to be a program. That recovery happens while
// the panel is down, by definition, so the only place it can be reported is
// afterwards, here, on the page the operator opens to find out what went wrong.
// An install that quietly reverted to an older binary and said nothing would
// leave them reading a version number they did not choose.
func binaryRepairNotice() string {
	state, err := os.ReadFile(filepath.Join(shieldControlDir(), "binhealth.state"))
	if err != nil {
		return ""
	}
	detail := ""
	if b, derr := os.ReadFile(filepath.Join(shieldControlDir(), "binhealth.reason")); derr == nil {
		detail = strings.TrimSpace(string(b))
	}
	switch strings.TrimSpace(string(state)) {
	case "restored":
		msg := "An update left a file at the install path that this server could not run, so the " +
			"previous binary was restored automatically and the service was restarted. " +
			"The version shown above is the restored one — no data was affected."
		if detail != "" {
			msg += " Reported: " + html.EscapeString(detail) + "."
		}
		return `<div class="settings-callout">
    <strong>This install repaired itself after a failed update.</strong>
    <span class="text-sm muted">` + msg + `</span>
  </div>`
	case "unrecoverable", "error":
		msg := "The file at the install path is not a program this server can run, and it could not " +
			"be repaired automatically."
		if detail != "" {
			msg += " Reported: " + html.EscapeString(detail) + "."
		}
		return `<div class="settings-callout">
    <strong>The installed binary is not usable.</strong>
    <span class="text-sm muted">` + msg + `</span>
  </div>`
	}
	return ""
}

// dnsResolverNotice reports host-network trouble the console would otherwise
// render invisible: the system DNS resolver stopped answering (lookups are
// being served by a public resolver), and/or outbound dials are only
// succeeding through DNS-over-HTTPS re-resolution — the signature of a host
// whose route to a destination (GitHub's edges are the reported case) is
// blackholed. "" when neither condition is live.
//
// These exist because the failures are otherwise invisible in exactly the way
// that matters. When the host resolver stops answering, every published-range
// feed VayuShield relies on silently stops refreshing and the panel goes on
// presenting the protection as current. When the route to GitHub is dead, the
// update panel quietly works around it via the mirror and nothing ever says
// the host itself is sick. A control running on stale data — or working only
// through a rescue path — while describing itself as live is the same defect
// class as a posture verdict that overstates what is enforcing.
func dnsResolverNotice() string {
	var out strings.Builder
	if safefetch.DNSFallbackActive() {
		out.WriteString(`<div class="settings-callout">
    <strong>This server's own DNS stopped answering.</strong>
    <span class="text-sm muted">Name lookups are being served by a public resolver so that threat-intelligence
      feeds, verified-bot lists and outbound requests keep working — but the cause is on this machine, not in
      VayuPress, and it will affect anything else here that resolves a name. Set
      <code>VAYU_DNS_FALLBACK=off</code> to refuse the fallback and fail instead.</span>
  </div>`)
	}
	if n := safefetch.DoHDialCount(); n > 0 {
		out.WriteString(`<div class="settings-callout">
    <strong>Some outbound destinations are unreachable directly.</strong>
    <span class="text-sm muted">` + strconv.FormatInt(n, 10) + ` connection(s) succeeded only after re-resolving the name through a
      public DNS-over-HTTPS resolver — every address your server's own resolver returned for that destination could not be
      connected to. This is a route/firewall problem on the host or its provider (GitHub's API edges are the usual case),
      not a VayuPress fault; updates and other outbound traffic keep working through the mirror fallback. The count
      resets when this process restarts.</span>
  </div>`)
	}
	return out.String()
}

// shieldRescueFlag is the file the systemd path unit watches. Repairing the
// helper must not go through the helper: when its upgrade path is what broke —
// a missing cosign, an unwritable trust cache — the only thing that could fix
// the agent was the agent, and the operator needed a shell for the one component
// whose purpose is to remove the shell from these operations.
//
// systemd watches this instead and runs the on-disk script as a fresh root
// process, so a wedged or crash-looping daemon is irrelevant. The file is empty
// and its contents are never read: the request is its existence, which is what
// keeps an unprivileged app from choosing what root runs.
const shieldRescueFlag = "agent.rescue.request"

// handleOSShieldRescue records a repair request for the root-side path unit.
func (a *App) handleOSShieldRescue(w http.ResponseWriter, r *http.Request) {
	f, err := os.OpenFile(filepath.Join(shieldControlDir(), shieldRescueFlag),
		os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "control-error",
			"Could not record the repair request: "+err.Error(), "")
		return
	}
	_ = f.Close()
	writeOSFragment(w, a.shieldHardeningBody(r))
}

// shieldRescueRow offers the repair, and says plainly what makes it different
// from the upgrade button above it.
func shieldRescueRow() string {
	return `<div class="vs-adv vs-adv--open"><strong class="text-sm">Repair the helper</strong> ` +
		`<button type="button" class="btn btn--ghost btn--sm"` +
		` hx-post="/os/api/shield/rescue" hx-target="#vs-body-hardening" hx-swap="innerHTML">` +
		`Repair now</button> <span class="muted text-xs">Use this when the upgrade above reports a ` +
		`refusal it cannot get past. A root-side watcher runs the upgrade as a fresh process, so a ` +
		`helper that is stuck, crash-looping, or carrying the very fault being repaired does not have ` +
		`to work for this to. The same signature check applies — nothing unverified is installed.` +
		`</span></div>`
}

// shieldRequestAgentUpgrade asks the root agent to upgrade itself.
//
// Writes an EMPTY file. Nothing the web app produces is ever read as a command,
// an argument or a path by the privileged process — the request is carried
// entirely by the file's existence.
func shieldRequestAgentUpgrade() error {
	f, err := os.OpenFile(filepath.Join(shieldControlDir(), "agent.upgrade.want"),
		os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	return f.Close()
}

// handleOSShieldAgentUpgrade is the admin/CSRF-gated endpoint behind the
// "Upgrade the helper" button.
func (a *App) handleOSShieldAgentUpgrade(w http.ResponseWriter, r *http.Request) {
	if !shieldAgentAlive() {
		writeAPIError(w, r, http.StatusPreconditionFailed, "no-agent",
			"The helper is not running, so there is nothing to upgrade. Install it first.", "")
		return
	}
	if !shieldAgentSupportsSelfUpgrade() {
		writeAPIError(w, r, http.StatusPreconditionFailed, "agent-too-old",
			"The running helper predates the self-upgrade feature, so it would never see this "+
				"request. Upgrade it once from a shell; after that this becomes a button.", "")
		return
	}
	if err := shieldRequestAgentUpgrade(); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "control-error",
			"Could not record the request: "+err.Error(), "")
		return
	}
	dbpkg.AuditLog("vayushield.agent.upgrade", dbpkg.AuditActor(r), "shield",
		"requested a helper self-upgrade")
	writeOSFragment(w, a.shieldHardeningBody(r))
}

// shieldAgentSupportsSelfUpgrade reports whether the RUNNING helper is new
// enough to act on an upgrade request.
//
// This exists because the button was, briefly, a trap. An older helper has no
// code that reads the request flag, so the panel would have recorded the click,
// nothing would have acted on it, and no status would ever have appeared. The
// operator waits, concludes it is slow, and stops trusting the panel — and a
// control that silently does nothing is worse than one that is absent, because
// absence at least tells the truth.
//
// Read from what the helper itself advertises, never inferred from the app's own
// version: the whole point is that the two are upgraded independently, which is
// exactly why an old helper can be running under a new binary.
func shieldAgentSupportsSelfUpgrade() bool {
	b, err := os.ReadFile(filepath.Join(shieldControlDir(), "agent.caps"))
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "selfupgrade=1")
}

// shieldAgentVersion reports the running helper's version, or "unknown".
//
// "unknown" is the honest answer for two different installs — a helper predating
// the version stamp, and one installed from a checkout — and neither should be
// dressed up as a number. The value is filtered to the characters a version can
// contain and truncated, because it is read from a file on disk and rendered
// into the panel; it is escaped at the call site as well.
func shieldAgentVersion() string {
	b, err := os.ReadFile(filepath.Join(shieldControlDir(), "agent.version"))
	if err != nil {
		return "unknown"
	}
	v := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			return r
		case r == '.' || r == '-' || r == '+':
			return r
		}
		return -1
	}, string(b))
	if len(v) > 32 {
		v = v[:32]
	}
	if v == "" {
		return "unknown"
	}
	return v
}

// shieldAgentUpgradeRow renders the button and whatever the agent last said.
//
// The state is reported in the agent's own words rather than as a spinner that
// resolves to nothing. "unverifiable" in particular is a REFUSAL and is written
// as one: the helper declined to install code it could not check, which is the
// system working, and phrasing it as a failure would push an operator toward
// finding a way around it.
func shieldAgentUpgradeRow() string {
	var b strings.Builder
	if !shieldAgentSupportsSelfUpgrade() {
		// No button at all. Offering one that cannot work, and explaining the
		// caveat underneath, still leaves an operator clicking it first.
		return `<p class="muted text-sm">Your running helper predates the self-upgrade feature, so ` +
			`this one upgrade still needs the command below &mdash; after it, the button appears and ` +
			`later upgrades are one click. There is no way around this: the code that would act on a ` +
			`request from this panel is the code you do not have yet.</p>`
	}
	// vs-adv--open, not bare vs-adv. The bare class is an ADVANCED DISCLOSURE:
	// `display:none` until a master toggle above it is checked. The Network
	// hardening section has no master toggle, so this button rendered into the
	// DOM and was never once visible — which is why an operator could read
	// "press the button again" in its own status line with no button to press.
	// A control that exists and cannot be seen is worse than one that is absent.
	b.WriteString(`<div class="vs-adv vs-adv--open"><button type="button" class="btn btn--ghost btn--sm"` +
		` hx-post="/os/api/shield/agent-upgrade" hx-target="#vs-body-hardening" hx-swap="innerHTML">` +
		`Check for a helper upgrade</button> <span class="muted text-xs">The helper fetches the signed bundle ` +
		`from the release itself and verifies the signature before installing. This panel only records ` +
		`that you asked &mdash; it never supplies the code, which is what keeps an unprivileged web app ` +
		`from being able to choose what a root process runs.</span>`)

	// Which helper is actually running. Without this the upgrade button could not
	// be checked: an operator pressed it, the posture report did not change, and
	// nothing anywhere distinguished "the helper upgraded and the finding is
	// real" from "the upgrade silently did not happen". The capability string
	// cannot settle it — it is identical across releases that change behaviour.
	//
	// Shown beside the app's own version on purpose. The two upgrade separately,
	// so a helper older than the binary is the normal state after an app update
	// and is exactly what an operator needs to see.
	b.WriteString(`<p class="text-xs muted">Helper <strong>` + html.EscapeString(shieldAgentVersion()) +
		`</strong> &middot; this app <strong>` + html.EscapeString(Version) + `</strong>. ` +
		`They upgrade separately &mdash; server-level fixes ship in the helper, so a helper older than ` +
		`the app has not picked them up yet.</p>`)

	// Closed after the status, for the same reason as shieldFixRow: a verdict
	// rendered outside its own card belongs, visually, to whatever follows it.
	state, detail := shieldAgentUpgradeState(), shieldAgentUpgradeDetail()
	if state == "" {
		b.WriteString(`</div>`)
		return b.String()
	}
	label := map[string]string{
		"checking":     "▲ Checking",
		"restarting":   "▲ Verified &mdash; installing and restarting",
		"done":         "● Upgraded",
		"unverifiable": "▲ Refused &mdash; nothing was installed",
		"error":        "✕ Could not upgrade",
	}[state]
	if label == "" {
		label = "○ " + html.EscapeString(state)
	}
	cls := "is-work"
	switch state {
	case "done":
		cls = "is-on"
	case "error":
		cls = "is-err"
	}
	b.WriteString(`<p class="text-sm"><span class="vs-hard-state ` + cls + `">` + label + `</span>`)
	if detail != "" {
		b.WriteString(` <span class="muted">` + html.EscapeString(detail) + `</span>`)
	}
	b.WriteString(`</p></div>`)
	return b.String()
}

// ── Posture remediations ─────────────────────────────────────────────────────
//
// Two posture rows told an operator what was wrong and then left them to fix it
// in a terminal. That is a defect of the same kind as a wrong number: the panel
// is the product, and a finding it cannot act on is a finding it has delegated
// back to the person who came here to avoid the command line.
//
// Both follow the tier toggles exactly. The panel writes ONE BIT — an empty
// file it owns as an unprivileged user — and the root agent decides what that
// means and writes the config itself. Nothing typed or derived here reaches an
// nginx file.

// shieldFix describes one remediation the agent can perform.
// Every filename is spelled out rather than derived. Deriving the state file
// from the flag ("defaulthost.want" minus ".want", plus ".state") would still be
// a path built by concatenation, and the reason that shape keeps getting flagged
// is that it is safe only for as long as its input stays constant — which is a
// property of today's callers, not of the code.
type shieldFix struct {
	Flag    string // intent file the panel creates
	State   string // status file the agent writes
	Reason  string // failure detail the agent writes
	Cap     string // capability token the agent must advertise
	Title   string
	Button  string
	Explain string
}

// shieldFixes is keyed by the value the form sends. As with shieldCDNAllowFlags,
// the caller's string is only ever a lookup KEY: the filename that reaches a
// path is a constant from this table. Building it by concatenation would be safe
// only for as long as the validation stayed exactly where it is, and code
// scanning was right to flag that shape once already.
var shieldFixes = map[string]shieldFix{
	"defaulthost": {
		Flag:   "defaulthost.want",
		State:  "defaulthost.state",
		Reason: "defaulthost.reason",
		Cap:    "defaulthost=1",
		Title:  "Unknown-Host requests",
		Button: "Add the catch-all server",
		Explain: "Installs a default server for 443 so a request naming a hostname this install does " +
			"not serve is closed without a response, instead of being handed to whichever vhost is " +
			"listed first. The helper validates the config and reloads; if nginx refuses it, the " +
			"previous config is restored and this row says so.",
	},
	"mcpsurface": {
		Flag:   "mcpsurface.want",
		State:  "mcpsurface.state",
		Reason: "mcpsurface.reason",
		Cap:    "mcpsurface=1",
		Title:  "MCP host surface",
		Button: "Narrow the MCP host",
		Explain: "Rewrites the catch-all location on the dedicated MCP host to return 404, leaving only " +
			"the MCP, OAuth and health endpoints. Your other vhosts are not touched. The helper backs " +
			"the file up first and restores it if nginx refuses the result.",
	},
	// FINDING, and it is the reason this entry exists: the agent capability
	// shipped WITHOUT a control that asks for it.
	//
	// A root-side action was added, verified, gated and released — and no button
	// anywhere wrote its flag, so nothing could ever request it. That is the
	// same defect as a button that does nothing, arrived at from the opposite
	// direction, and it cost an operator another round of being told to press
	// something that was not there.
	//
	// The failure it repairs: the provisioning helper's reload step discarded
	// its exit status, so nginx had gone FOUR DAYS without reloading while vhosts
	// were written minutes earlier. Every certificate on the install failed with
	// an unexplained connection error, and the one-line fix could not reach a
	// root-owned script through an updater that swaps the binary.
	"provisionhelpers": {
		Flag:   "provisionhelpers.want",
		State:  "provisionhelpers.state",
		Reason: "provisionhelpers.reason",
		Cap:    "provisionhelpers=1",
		Title:  "Certificate helpers",
		Button: "Repair the certificate helpers",
		Explain: "Installs the current, signature-verified provisioning helpers and performs the " +
			"nginx reload they may have skipped. Use this when a site's console reports that nginx " +
			"has not reloaded since its vhost was written: the config on disk is already correct and " +
			"the running server has simply never read it. The helper verifies the bundle's signature " +
			"before unpacking it, tests the configuration before reloading, and reports a failed " +
			"reload instead of discarding it — which is the defect being repaired.",
	},

	// The posture row for this one had no button at all, which made it the
	// longest-standing example of the thing this section exists to stop: a report
	// that names a live fault and hands it back to the operator as homework.
	"realip": {
		Flag:   "realip.want",
		State:  "realip.state",
		Reason: "realip.reason",
		Cap:    "realip=1",
		Title:  "Real visitor IP",
		Button: "Resolve the real visitor address",
		Explain: "Writes set_real_ip_from for your proxy's published ranges, so nginx resolves the " +
			"visitor before VayuPress sees the request. Until this is done every per-IP control here " +
			"is metering your edge rather than your readers: one abuser cannot be isolated because " +
			"they share a bucket with everyone, and one busy minute challenges the whole audience at " +
			"once. Allowlist your proxy's ranges first — this uses that same list, and never takes an " +
			"address from this page. The helper validates the config and restores it if nginx refuses.",
	},
}

// shieldAgentSupportsFix reports whether the running helper advertises the
// capability a fix needs. An older agent gets no button rather than a button
// that writes a flag nothing will ever read.
func shieldAgentSupportsFix(cap string) bool {
	b, err := os.ReadFile(filepath.Join(shieldControlDir(), "agent.caps"))
	if err != nil {
		return false
	}
	return strings.Contains(string(b), cap)
}

// shieldControlRead reads one control file. The name is always a constant from
// shieldFixes, never a value that arrived in a request.
func shieldControlRead(name string) string {
	b, err := os.ReadFile(filepath.Join(shieldControlDir(), name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// shieldFixReport returns each remediation's key, title, state and the reason
// the root helper last recorded — the same facts the panel renders, in a form a
// read-only caller can consume.
//
// Sorted, because a map's order changes between calls and a report that reorders
// itself cannot be diffed against the last one.
func shieldFixReport() []map[string]string {
	keys := make([]string, 0, len(shieldFixes))
	for k := range shieldFixes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		fix := shieldFixes[k]
		row := map[string]string{"key": k, "title": fix.Title}
		// "supported" distinguishes a helper too old to offer the fix from one
		// that offers it and has never been asked. Collapsing those two into an
		// empty state is how an operator ends up pressing a button that is not
		// there.
		if !shieldAgentSupportsFix(fix.Cap) {
			row["state"] = "unsupported"
			row["reason"] = "the running helper predates this fix; upgrade the helper"
		} else {
			st := shieldControlRead(fix.State)
			if st == "" {
				st = "never-run"
			}
			row["state"] = st
			if reason := shieldControlRead(fix.Reason); reason != "" {
				row["reason"] = reason
			}
		}
		out = append(out, row)
	}
	return out
}

// handleOSShieldFix records the operator's request for one remediation.
func (a *App) handleOSShieldFix(w http.ResponseWriter, r *http.Request) {
	fix, ok := shieldFixes[strings.TrimSpace(r.PostFormValue("fix"))]
	if !ok {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "unknown fix", "")
		return
	}
	if !shieldAgentSupportsFix(fix.Cap) {
		writeAPIError(w, r, http.StatusConflict, "agent-too-old",
			"The running helper cannot perform this yet. Upgrade the helper above, then try again.", "")
		return
	}
	f, err := os.OpenFile(filepath.Join(shieldControlDir(), fix.Flag), os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "control-error",
			"Could not record the request: "+err.Error(), "")
		return
	}
	_ = f.Close()
	writeOSFragment(w, a.shieldHardeningBody(r))
}

// shieldFixRow renders one remediation: the button when it can work, and
// whatever the agent last said about it.
func shieldFixRow(key string) string {
	fix, ok := shieldFixes[key]
	if !ok {
		return ""
	}
	var b strings.Builder
	// vs-adv--open — see shieldAgentUpgradeRow. This section has no master toggle
	// to reveal a bare vs-adv, so the row would be invisible.
	b.WriteString(`<div class="vs-adv vs-adv--open"><strong class="text-sm">` + html.EscapeString(fix.Title) + `</strong> `)
	if !shieldAgentSupportsFix(fix.Cap) {
		b.WriteString(`<span class="muted text-xs">Your running helper predates this fix. ` +
			`Upgrade the helper above and it appears here.</span></div>`)
		return b.String()
	}
	b.WriteString(`<button type="button" class="btn btn--ghost btn--sm"` +
		` hx-post="/os/api/shield/fix" hx-vals='{"fix":"` + html.EscapeString(key) + `"}'` +
		` hx-target="#vs-body-hardening" hx-swap="innerHTML">` + html.EscapeString(fix.Button) + `</button> ` +
		`<span class="muted text-xs">` + fix.Explain + `</span>`)

	// The status closes the card, it does not follow it.
	//
	// This used to write </div> here and then append the state paragraph after
	// it, so "● Applied" rendered OUTSIDE the bordered row it belonged to and
	// sat loose against whatever came next — an operator reading down the page
	// cannot tell which control a floating verdict refers to, and on this page
	// the next thing along is a different remediation.
	state := shieldControlRead(fix.State)
	if state == "" {
		b.WriteString(`</div>`)
		return b.String()
	}
	label := map[string]string{
		"applying": "▲ Applying",
		"active":   "● Applied",
		"error":    "✕ Could not apply",
	}[state]
	if label == "" {
		label = "○ " + html.EscapeString(state)
	}
	cls := "is-work"
	switch state {
	case "active":
		cls = "is-on"
	case "error":
		cls = "is-err"
	}
	b.WriteString(`<p class="text-sm"><span class="vs-hard-state ` + cls + `">` + label + `</span>`)
	if reason := shieldControlRead(fix.Reason); reason != "" {
		b.WriteString(` <span class="muted">` + html.EscapeString(reason) + `</span>`)
	}
	b.WriteString(`</p></div>`)
	return b.String()
}

// shieldCDNAllowFlags maps a proxy vendor to the EXACT flag filename the root
// agent looks for. The value is a constant; a caller-supplied name is only ever
// used as a lookup KEY and never becomes part of a path.
//
// That indirection is the point. The first version validated the name against an
// allowlist and then built the path by concatenation —
// "cdnallow." + vendor + ".want" — which is safe only for as long as the
// validation stays exactly where it is and stays an exact match. Code scanning
// flagged it as uncontrolled data in a path expression, and it was right to: the
// guard was real but the shape invited a future refactor (a prefix match, a
// second caller, an extra vendor added carelessly) to turn it into a traversal
// into a directory a root agent reads. Deriving the filename from a constant
// removes the class rather than the symptom.
//
// The agent independently re-checks the vendor against its own copy of the list —
// the web app is unprivileged and its output must never be able to widen what a
// root process will run.
var shieldCDNAllowFlags = map[string]string{
	"cloudflare": "cdnallow.cloudflare.want",
}

// shieldCDNAllowFlag returns the constant flag filename for a vendor, and whether
// the vendor is one this build supports.
func shieldCDNAllowFlag(vendor string) (string, bool) {
	name, ok := shieldCDNAllowFlags[vendor]
	return name, ok
}

// shieldCDNAllowState returns the agent-reported state of the last allowlist
// fetch: "applying", "active", "error" or "" when it has never been asked.
func shieldCDNAllowState() string {
	b, err := os.ReadFile(filepath.Join(shieldControlDir(), "cdnallow.state"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// shieldRequestCDNAllow asks the root agent to populate the Tier 2 proxy
// allowlist. It writes an EMPTY file whose NAME carries the vendor, so no content
// the web app produces is ever read as a command or an argument.
func shieldRequestCDNAllow(vendor string) error {
	// The vendor selects a constant filename; it never reaches the path itself.
	flag, ok := shieldCDNAllowFlag(vendor)
	if !ok {
		return errors.New("unknown proxy vendor")
	}
	f, err := os.OpenFile(filepath.Join(shieldControlDir(), flag),
		os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	return f.Close()
}

// handleOSShieldCDNAllow is the admin/CSRF-gated endpoint behind the "Allowlist
// the edge ranges" button.
func (a *App) handleOSShieldCDNAllow(w http.ResponseWriter, r *http.Request) {
	vendor := strings.ToLower(strings.TrimSpace(r.PostFormValue("vendor")))
	// Validated here as well as in shieldRequestCDNAllow: this endpoint is
	// reachable directly with any POST body, so the button sending good values is
	// not validation.
	if _, ok := shieldCDNAllowFlag(vendor); !ok {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "unknown proxy vendor", "")
		return
	}
	if err := shieldRequestCDNAllow(vendor); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "control-error", "Could not record the request: "+err.Error(), "")
		return
	}
	writeOSFragment(w, a.shieldHardeningBody(r))
}

// shieldCDNVendors maps a request header to the proxy that sets it. Any of these
// means a CDN terminated the visitor's connection, so what reaches this server is
// the CDN's address rather than the reader's.
//
// X-Forwarded-For is deliberately NOT in this list. A local nginx reverse proxy
// sets it on every request, so treating it as a CDN signal would report a CDN in
// front of every normal install — the opposite of the honesty this is for.
var shieldCDNVendors = []struct{ header, vendor string }{
	{"CF-Ray", "Cloudflare"},
	{"CF-Connecting-IP", "Cloudflare"},
	{"X-Amz-Cf-Id", "CloudFront"},
	{"Fastly-Client-IP", "Fastly"},
	{"X-Azure-Ref", "Azure Front Door"},
	{"True-Client-IP", "a proxy"},
	{"CDN-Loop", "a proxy"}, // RFC 8586 — the standard, vendor-neutral marker
}

// cdnSeenUnix / cdnSeenVendor record the last time ANY request arrived through a
// proxy. This is the signal that answers the question the panel actually needs
// answered — "is this SITE proxied?" — as opposed to "did the request I am
// currently serving come through a proxy?", which is all the headers can tell us.
//
// The two differ precisely when an administrator reaches the console another way,
// and that is not an edge case: pointing a hosts entry at the origin so the panel
// stays reachable when the CDN is having a bad day is ordinary practice. The one
// person guaranteed to read this notice is therefore the one most likely to be
// bypassing the edge, which is how the first version of this came to tell a
// Cloudflare-proxied site that nothing was in front of it.
var (
	cdnSeenUnix   atomic.Int64
	cdnSeenVendor atomic.Value // string
	// Whether ordinary traffic resolved to a reader's address, and when that was
	// last sampled. Separate from the sighting above: "a proxy is in front" and
	// "the reader's address is getting through it" are different facts, and the
	// second is the one every per-IP control and every country rule depends on.
	visitorResolvedOK   atomic.Bool
	visitorResolvedUnix atomic.Int64
)

// cdnObservationTTL bounds how long an observation stays meaningful. Long enough
// that a quiet site does not forget between visits to the panel, short enough
// that turning a proxy off is noticed within a day.
const cdnObservationTTL = 24 * time.Hour

// noteCDNObservation records a proxy sighting from ordinary traffic. Called from
// the request path, so it is written to be nearly free: once a sighting is fresh
// it does not look at headers again for two minutes.
//
// It deliberately does NOT verify that the header is genuine. Anyone connecting
// straight to the origin could forge one and make the panel believe a proxy is in
// front. The consequence is that the panel shows the Tier 2 kernel warning to
// someone who does not need it — a paragraph of unnecessary advice. The opposite
// error hides that warning from someone whose firewall is silently dropping their
// CDN's connections. Erring toward showing it is the right direction, so the
// cheap check stands.
func noteCDNObservation(r *http.Request) {
	if time.Since(time.Unix(cdnSeenUnix.Load(), 0)) < 2*time.Minute {
		return
	}
	if ok, vendor := shieldDetectCDN(r); ok {
		cdnSeenVendor.Store(vendor)
		cdnSeenUnix.Store(time.Now().Unix())
	}
}

// noteVisitorResolution records, from ORDINARY traffic, whether the address the
// per-IP controls will key on turned out to be the reader's.
//
// It exists because the posture report had no answer at all when there was no
// request to look at. `vayushield_posture` over the connector calls
// shieldAuditInputs(nil), and the comment there says the row "reports from
// recent visitor traffic rather than from a request that does not exist" — but
// nothing did. ClientIPResolved simply stayed false, which on a proxied install
// pins the row to FAIL whatever the truth is. A whole diagnosis was run off that
// row before anyone noticed it could not say anything else.
//
// Sampled at most every two minutes, like the CDN sighting above, so the request
// path stays free. The operator's own console is excluded: they commonly reach it
// without going through their proxy, and that request is the least representative
// one on the site.
func noteVisitorResolution(r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/os") {
		return
	}
	if time.Since(time.Unix(visitorResolvedUnix.Load(), 0)) < 2*time.Minute {
		return
	}
	visitorResolvedOK.Store(shieldAddressIsTheReaders(r))
	visitorResolvedUnix.Store(time.Now().Unix())
}

// lastVisitorResolution reports what recent ordinary traffic showed, and whether
// anything was seen inside the TTL at all.
func lastVisitorResolution() (resolved, seen bool) {
	at := visitorResolvedUnix.Load()
	if at == 0 || time.Since(time.Unix(at, 0)) > cdnObservationTTL {
		return false, false
	}
	return visitorResolvedOK.Load(), true
}

// lastCDNObservation returns the vendor seen on recent ordinary traffic, or "" if
// none has been seen inside the TTL.
func lastCDNObservation() string {
	at := cdnSeenUnix.Load()
	if at == 0 || time.Since(time.Unix(at, 0)) > cdnObservationTTL {
		return ""
	}
	v, _ := cdnSeenVendor.Load().(string)
	return v
}

// shieldDetectCDN reports whether THIS request arrived through a CDN proxy, and
// which one.
//
// Read the asymmetry carefully: a header present is proof a proxy is in front; a
// header absent proves nothing at all about the site, only about this one
// connection. Callers must never turn a false return into a positive claim that
// the origin is unproxied — see shieldCDNAdvisory, which combines this with the
// operator's setting and with sightings from real traffic.
func shieldDetectCDN(r *http.Request) (bool, string) {
	if r == nil {
		return false, ""
	}
	for _, v := range shieldCDNVendors {
		if strings.TrimSpace(r.Header.Get(v.header)) != "" {
			return true, v.vendor
		}
	}
	return false, ""
}

// shieldHardeningBody renders the Network-hardening section body: live Tier 2/3
// state with real toggles when the root agent is installed, or a clear
// explanation + copy-paste fallback when it is not yet.
//
// It takes the request so it can report the CDN situation truthfully. The copy
// here used to assert, unconditionally, that the origin served visitors directly
// with no proxy in front — on a proxied install that is simply false, and it is
// false in the most misleading direction, because it tells the operator the
// per-IP limits they just enabled are "fully effective" when those limits are in
// fact measuring a handful of CDN edge addresses.
func (a *App) shieldHardeningBody(r *http.Request) string {
	var b strings.Builder
	b.WriteString(vsRefresh("hardening", "vs-body-hardening", ""))
	b.WriteString(`<p class="muted text-sm">The toggles above are <strong>Tier 1</strong> — VayuShield's in-binary defenses. <strong>Tier 2</strong> (kernel firewall) and <strong>Tier 3</strong> (nginx edge) sit below and in front of the app; they drop abuse before it reaches VayuPress, so they <strong>improve</strong> performance under attack rather than degrade it, with no cost to legitimate visitors.</p>`)

	if shieldAgentAlive() {
		b.WriteString(`<p class="muted text-xs">✅ Privileged helper installed — you can switch these on and off right here, no terminal needed. VayuPress itself stays unprivileged; a separate root agent applies only the vetted scripts.</p>`)
		b.WriteString(shieldAgentStaleNotice())
		// The upgrade control belongs on the HEALTHY path too, not only inside the
		// stale-agent warning.
		//
		// That warning fires on one specific symptom — an agent too old to write an
		// enforcement digest. A helper that is merely a few versions behind shows
		// none of it, so putting the only upgrade control inside the warning meant
		// the button existed exactly once in a helper's life and then vanished for
		// good. "There is nothing to upgrade right now" and "there is no way to
		// upgrade" are different states and looked identical.
		b.WriteString(shieldAgentUpgradeRow())
		b.WriteString(shieldTierRow(2, "🛡️ Tier 2 · Kernel firewall (nftables)", "Per-IP connection/packet rate limits + SYN-flood cookies, enforced in the Linux kernel. Turning this on also activates the L1 live offload below."))
		b.WriteString(shieldTierRow(3, "🌐 Tier 3 · Edge shaping (nginx)", "Per-IP request/connection shaping + slow-loris timeouts at the reverse proxy."))
		b.WriteString(a.shieldOffloadRow())
		// The two posture rows an operator could previously only fix by hand. They
		// sit here rather than on the posture report because this is where every
		// other privileged action already lives, and one place to press a button is
		// worth more than each finding carrying its own.
		b.WriteString(shieldRescueRow())
		b.WriteString(shieldFixRow("defaulthost"))
		b.WriteString(shieldFixRow("mcpsurface"))
		b.WriteString(shieldFixRow("realip"))
		b.WriteString(shieldFixRow("provisionhelpers"))
		b.WriteString(a.shieldCDNAdvisory(r))
		b.WriteString(`<p class="muted text-xs">Both tiers are fully reversible from here.</p>`)
	} else {
		b.WriteString(`<div class="vs-tier"><div class="vs-tier-head">One-time setup — enable the in-panel switches</div>`)
		b.WriteString(`<p class="muted text-sm">A true in-panel toggle needs a tiny <strong>root helper</strong> installed once. The <strong>in-app one-click updater cannot install it</strong> — that updater is unprivileged by design (which is exactly what keeps VayuPress safe). Install it with <strong>one command as root</strong> from your VayuPress checkout, then this section turns into on/off switches (no terminal afterwards):</p>`)
		b.WriteString(shieldCmdRow("vs-cmd-agent", shieldAgentCmd("install")))
		b.WriteString(`<p class="muted text-xs">` + shieldCheckoutHint() +
			` Running your normal root updater (<code>scripts/update-vayupress.sh</code>) installs it too, so most operators never need this command at all. Undo any time with <code>` +
			html.EscapeString(shieldAgentCmd("uninstall")) + `</code>.</p>`)
		b.WriteString(`<p class="muted text-sm">Prefer to apply Tier 2/3 by hand instead? (idempotent &amp; reversible)</p>`)
		b.WriteString(`<div class="vs-cmd"><code id="vs-cmd-t2">sudo bash deploy/vayushield-firewall.sh apply</code><button type="button" class="vs-copy-btn" data-copy="vs-cmd-t2">Copy</button></div>`)
		b.WriteString(`<div class="vs-cmd"><code id="vs-cmd-t3">sudo cp deploy/nginx-vayushield.conf /etc/nginx/conf.d/ &amp;&amp; sudo nginx -t &amp;&amp; sudo systemctl reload nginx</code><button type="button" class="vs-copy-btn" data-copy="vs-cmd-t3">Copy</button></div>`)
		b.WriteString(`<p class="muted text-xs">Undo: <code>… vayushield-firewall.sh remove</code>; delete the nginx conf + reload.</p></div>`)
	}
	b.WriteString(`<p class="muted text-sm">A true volumetric flood still needs anycast/scrubbing capacity no single host provides; Tiers 1–3 handle what a typical publisher actually faces.</p>`)
	return b.String()
}

// shieldCDNAdvisory states what is actually in front of this origin and what
// that means for each tier, because the three tiers do NOT behave the same way
// behind a proxy and conflating them is what leaves an operator throttling their
// own CDN:
//
//   - Tier 1 (in-binary) reads the visitor from CF-Connecting-IP once the
//     "Behind Cloudflare / a CDN" switch is on. Only genuine edge addresses are
//     trusted, so the header cannot be spoofed.
//   - Tier 3 (nginx) needs set_real_ip_from + real_ip_header to see the visitor.
//   - Tier 2 (nftables) can NEVER see the visitor. It runs in the kernel, before
//     any HTTP header exists, so its per-IP limits key on the proxy's addresses
//     no matter what any setting says. The only fix is to allowlist the edge
//     ranges — which is why this is called out separately rather than folded in
//     with the other two.
func (a *App) shieldCDNAdvisory(r *http.Request) string {
	// Three independent signals, deliberately combined rather than ranked by
	// convenience. `here` is the strongest evidence FOR a proxy and no evidence
	// against one; `seen` is what actually describes the site; `declared` is the
	// operator telling us directly, and outranks a silent absence of the other two.
	here, hereVendor := shieldDetectCDN(r)
	seen := lastCDNObservation()
	declared := false
	if a.siteSettings != nil {
		declared = a.siteSettings.Get(r.Context(), settings.ForPrimary(), settings.KeyShieldBehindCDN) == "on"
	}

	vendor := hereVendor
	if vendor == "" {
		vendor = seen
	}
	if vendor == "" {
		vendor = "a proxy"
	}

	// Nothing points at a proxy. Say only that — an absence of signal is not a
	// finding. The previous version turned it into "no proxy detected … limits
	// are fully effective", which is the reassurance that stops an operator
	// allowlisting the ranges their kernel is dropping.
	if !here && seen == "" && !declared {
		return `<p class="muted text-xs">No proxy signal has reached this server — not on your own request, and not on recent visitor traffic. If nothing is in front of this origin, Tier 2 and Tier 3 per-IP limits apply to real visitor addresses and are effective. Treat that as the absence of a signal rather than proof: put a CDN in front later and this notice updates on its own.</p>`
	}

	var b strings.Builder
	switch {
	case here:
		b.WriteString(`<p class="muted text-xs"><strong>` + html.EscapeString(vendor) +
			` is proxying this origin</strong> — detected from the headers on this very request. That changes what the tiers below can see.</p>`)
	case seen != "":
		// The case that produced this whole design. The site IS proxied — real
		// visitor traffic proves it — while the administrator reads the panel over
		// a connection that skips the edge, usually a hosts entry pointing at the
		// origin so the console stays reachable when the CDN is unwell. Naming the
		// cause here saves the hours it otherwise takes to work out why the panel
		// and the DNS disagree.
		b.WriteString(`<p class="muted text-xs"><strong>` + html.EscapeString(vendor) +
			` is proxying this site</strong> — seen on recent visitor traffic. <strong>Your own connection is not going through it</strong>, which normally means a <code>hosts</code> entry (or split-horizon DNS) pointing this domain at the origin address. That is a reasonable thing to have; it just means what you see here is not what your readers get.</p>`)
	default:
		b.WriteString(`<p class="muted text-xs">You have marked this site as being <strong>behind a proxy</strong>, but no proxy header has arrived — not on this request, nor on visitor traffic in the last day. Either the proxy is no longer in front, or the site is too quiet to have shown one yet. The guidance below assumes your setting is right, since acting on it costs a paragraph and ignoring it costs dropped traffic.</p>`)
	}

	if !declared {
		b.WriteString(`<p class="muted text-xs">⚠️ <strong>“Behind Cloudflare / a CDN” is switched off above.</strong> VayuShield is therefore treating each proxy edge address as if it were one visitor, so your whole audience looks like a handful of IPs — which trips the rate limit and can show everyone a challenge page. Turn that switch on: it reads the real visitor from the proxy's header, and only genuine edge addresses are trusted, so it cannot be spoofed.</p>`)
	} else if config.IsCloudflareIP(net.ParseIP(auth.ClientIP(r))) {
		// The switch is on, but the address this request resolves to is itself an
		// edge address — so the visitor was never recovered and every reader is
		// being counted as one of a handful of edge nodes. That is the pooling
		// failure the switch exists to prevent, and it is otherwise invisible:
		// nothing errors, the limits simply apply to the wrong subject.
		//
		// It happens when a local reverse proxy sits between the edge and
		// VayuPress. VayuPress will not read CF-Connecting-IP across that hop —
		// it cannot distinguish a header the edge set from one a visitor typed,
		// and trusting it there let any client choose its own identity. nginx can
		// tell, because it sees the real peer, so nginx has to do the resolving.
		b.WriteString(`<p class="muted text-xs">⚠️ <strong>The switch is on, but this request still resolves to an edge address</strong> — so your readers are being counted as a handful of proxy nodes, which is exactly what trips the rate limit for everyone. Your reverse proxy needs to recover the visitor before VayuPress sees the request: add <code>set_real_ip_from</code> for your proxy's ranges plus <code>real_ip_header</code> to nginx (the generator command is in <code>deploy/nginx-vayupress.conf</code>), then reload. VayuPress will not read the edge header across a local proxy hop itself, because at that point it cannot tell a header your CDN set from one a visitor typed.</p>`)
	} else {
		b.WriteString(`<p class="muted text-xs">✅ Tier 1 is reading the real visitor address, so in-binary rate limiting applies per reader rather than per edge node.</p>`)
	}

	b.WriteString(`<p class="muted text-xs"><strong>Tier 2 is different, and no switch fixes it.</strong> The kernel firewall runs before any HTTP header exists, so its per-IP limits always see the proxy's addresses — a busy edge node easily exceeds a per-visitor connection cap and gets dropped, which reads as intermittent failures you cannot reproduce. The fix is to allowlist the edge ranges, which also sharpens the firewall: anything arriving from outside them skipped the proxy and still meets the full ruleset.</p>`)
	b.WriteString(a.shieldCDNAllowRow(vendor))
	b.WriteString(`<p class="muted text-xs"><strong>Tier 3</strong> needs <code>set_real_ip_from</code> for your proxy's ranges plus <code>real_ip_header</code>, or nginx's per-IP shaping keys on the edge too. The SYN-flood and slow-loris protections in both tiers are unaffected either way — those do not depend on identifying the visitor.</p>`)
	return b.String()
}

// shieldCDNAllowRow renders the one-click allowlist control. Without the root
// agent there is nothing to click, so it degrades to the exact command instead of
// showing a button that would silently do nothing.
func (a *App) shieldCDNAllowRow(vendor string) string {
	// Only vendors the agent can actually fetch get a button. Anything else —
	// including a proxy detected only by the vendor-neutral CDN-Loop header — gets
	// the manual path, because pretending to support it would be worse than saying
	// so.
	key := strings.ToLower(strings.TrimSpace(vendor))
	if _, ok := shieldCDNAllowFlag(key); !ok {
		return `<p class="muted text-xs">Write your proxy's published ranges to <code>/etc/vayushield/cdn-allow.conf</code>, one CIDR per line, then re-apply Tier 2.</p>`
	}
	if !shieldAgentAlive() {
		return `<div class="vs-cmd"><code id="vs-cmd-cdnallow">sudo bash deploy/vayushield-firewall.sh cdn-allow ` + html.EscapeString(key) +
			` &amp;&amp; sudo bash deploy/vayushield-firewall.sh apply</code><button type="button" class="vs-copy-btn" data-copy="vs-cmd-cdnallow">Copy</button></div>`
	}
	switch shieldCDNAllowState() {
	case "applying":
		return `<p class="muted text-xs"><span class="vs-hard-state is-work">◐ Fetching the edge ranges…</span></p>`
	case "active":
		return `<p class="muted text-xs"><span class="vs-hard-state is-on">● Edge ranges allowlisted</span> — re-run after your proxy publishes new ranges. <button type="button" class="btn btn--sm" hx-post="/os/api/shield/cdn-allow" hx-vals='{"vendor":"` + html.EscapeString(key) + `"}' hx-target="#vs-body-hardening" hx-swap="innerHTML">Refresh ranges</button></p>`
	case "error":
		return `<p class="muted text-xs"><span class="vs-hard-state is-err">✕ Could not fetch the edge ranges</span> — the previous allowlist, if any, is unchanged. <button type="button" class="btn btn--sm" hx-post="/os/api/shield/cdn-allow" hx-vals='{"vendor":"` + html.EscapeString(key) + `"}' hx-target="#vs-body-hardening" hx-swap="innerHTML">Retry</button></p>`
	}
	return `<p class="muted text-xs"><button type="button" class="btn btn--primary btn--sm" hx-post="/os/api/shield/cdn-allow" hx-vals='{"vendor":"` + html.EscapeString(key) + `"}' hx-target="#vs-body-hardening" hx-swap="innerHTML">Allowlist ` + html.EscapeString(vendor) + `'s edge ranges</button> Fetches the published ranges and re-applies Tier 2. Survives reboots — the agent re-applies on boot.</p>`
}

// shieldOffloadStatus returns the agent-reported L1 offload state ("active",
// "inactive", "error" or "") and the current in-kernel ban count ("0" when
// unknown), for the hardening row and the Aegis layer map.
func shieldOffloadStatus() (state, count string) {
	if b, err := os.ReadFile(filepath.Join(shieldControlDir(), "offload.state")); err == nil {
		state = strings.TrimSpace(string(b))
	}
	count = "0"
	if b, err := os.ReadFile(filepath.Join(shieldControlDir(), "offload.count")); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			count = v
		}
	}
	return state, count
}

// shieldOffloadReason returns the agent's one-line explanation for a non-active
// offload state, truncated so a runaway nft error cannot fill the row.
func shieldOffloadReason() string {
	b, err := os.ReadFile(filepath.Join(shieldControlDir(), "offload.reason"))
	if err != nil {
		return ""
	}
	reason := strings.TrimSpace(string(b))
	// Truncate on runes, not bytes: the reason can carry an nft error verbatim,
	// and slicing mid-rune emits invalid UTF-8 into the page.
	if r := []rune(reason); len(r) > 160 {
		return string(r[:160]) + "…"
	}
	return reason
}

// shieldOffloadRow renders the L1 dynamic-offload status line: whether the
// agent is enforcing the shield's live jail verdicts in-kernel, and how many
// IPs are currently banned there. Read-only — the offload follows Tier 2
// automatically (on when Tier 2 is on), so there is nothing to configure.
// shieldAutoBlockOn reports whether the setting that FEEDS the kernel offload is
// enabled. Without it the offload table exists and stays empty forever.
func (a *App) shieldAutoBlockOn() bool {
	if a.siteSettings == nil {
		return false
	}
	return a.siteSettings.Get(context.Background(), settings.ForPrimary(), settings.KeyShieldAutoBlock) == "on"
}

func (a *App) shieldOffloadRow() string {
	state, count := shieldOffloadStatus()
	var pill string
	switch state {
	case "active":
		pill = `<span class="vs-hard-state is-on">● Enforcing — ` + html.EscapeString(count) + ` IP(s) banned in-kernel</span>`
	case "degraded":
		// The agent applied the flush and then each ban individually because the
		// atomic batch was rejected. Enforcement IS running and pardons DID lift,
		// so this is not an error — but some bans are missing, and falling through
		// to the "Idle" default would hide that behind a reassuring pill.
		pill = `<span class="vs-hard-state is-work">▲ Enforcing ` + html.EscapeString(count) +
			` IP(s) — some bans were rejected. ` + html.EscapeString(shieldOffloadReason()) + `</span>`
	case "error":
		pill = `<span class="vs-hard-state is-err">✕ ` + html.EscapeString(shieldOffloadReason()) + `</span>`
	default:
		pill = `<span class="vs-hard-state is-off">○ Idle — no jail verdicts to push</span>`
	}
	// The offload only ever receives verdicts from auto-block-guarded paths, and
	// "Auto-block abusive IPs" defaults OFF. So on a default install this ships
	// INERT: the table is created, nothing is ever added to it, and the row used
	// to read "Follows Tier 2 — turns on with it", which describes a dependency
	// that is real but not sufficient. Turning Tier 2 on does not populate it.
	// Saying so is the difference between an operator who knows they have one
	// more switch to flip and one who believes the layer is working.
	note := ``
	if !a.shieldAutoBlockOn() {
		note = `<p class="muted text-xs">⚠️ Nothing reaches this layer yet: it is fed by <strong>Auto-block abusive IPs</strong>, which is switched off above. Tier 2 alone does not populate it.</p>`
	}
	return `<div class="vs-tier"><div class="vs-hard-row"><div><div class="vs-tier-head">⚡ L1 · Live kernel offload (Aegis)</div><p class="muted text-sm">VayuShield's own jail verdicts (confirmed bad actors, reputation sentences) are pushed into a kernel nftables timeout-set — and an XDP filter where available — so a banned attacker's packets are dropped before a connection even exists. Bans expire on their own.</p>` + note + `</div><div class="vs-hard-ctl">` + pill + `</div></div></div>`
}

// shieldTierRow renders one tier's status pill + enable/disable toggle button.
func shieldTierRow(tier int, title, desc string) string {
	state := shieldTierState(tier)
	wanted := shieldTierWanted(tier)
	var pill, btn string
	switch state {
	case "active":
		pill = `<span class="vs-hard-state is-on">● Active</span>`
		btn = shieldTierBtn(tier, "disable", "Turn off", "btn--sm")
	case "applying":
		pill = `<span class="vs-hard-state is-work">◐ Applying…</span>`
		btn = shieldTierBtn(tier, "disable", "Cancel", "btn--sm")
	case "removing":
		pill = `<span class="vs-hard-state is-work">◐ Turning off…</span>`
		btn = ""
	case "error":
		reason := shieldTierReason(tier)
		label := "Error — check the agent log"
		if reason != "" {
			if len(reason) > 160 {
				reason = reason[:160] + "…"
			}
			label = "Error: " + reason
		}
		pill = `<span class="vs-hard-state is-err">✕ ` + html.EscapeString(label) + `</span>`
		if wanted {
			btn = shieldTierBtn(tier, "disable", "Turn off", "btn--sm") + ` ` + shieldTierBtn(tier, "enable", "Retry", "btn--sm")
		} else {
			btn = shieldTierBtn(tier, "enable", "Retry", "btn--sm")
		}
	default: // inactive / unknown
		if wanted {
			pill = `<span class="vs-hard-state is-work">◐ Requested…</span>`
			btn = shieldTierBtn(tier, "disable", "Cancel", "btn--sm")
		} else {
			pill = `<span class="vs-hard-state is-off">○ Inactive</span>`
			btn = shieldTierBtn(tier, "enable", "Turn on", "btn--sm btn--primary")
		}
	}
	return `<div class="vs-tier"><div class="vs-hard-row"><div><div class="vs-tier-head">` + title + `</div><p class="muted text-sm">` + desc + `</p></div><div class="vs-hard-ctl">` + pill + btn + `</div></div></div>`
}

// shieldTierBtn builds an HTMX toggle button that posts the intent and swaps the
// refreshed hardening section in place.
func shieldTierBtn(tier int, action, label, cls string) string {
	return `<button type="button" class="btn ` + cls + `" hx-post="/os/api/shield/tier" hx-vals='{"tier":"` + strconv.Itoa(tier) + `","action":"` + action + `"}' hx-target="#vs-body-hardening" hx-swap="innerHTML">` + label + `</button>`
}

// shieldAgentStaleNotice warns when the helper is RUNNING but too old to write
// an enforcement digest.
//
// This case had no notice at all, and it is the one an operator actually hits.
// The install prompt below renders only when the agent is missing entirely, so a
// stale agent — toggles working, tiers reported active, nothing verified —
// offered no upgrade path anywhere on the page. The posture report meanwhile
// showed four warnings whose single shared cause was exactly this, without ever
// naming it. Four rows saying "unverified" and no row saying "here is why, and
// here is the fix" is a diagnosis left as an exercise.
func shieldAgentStaleNotice() string {
	if readShieldDigest().Present {
		return ""
	}
	return `<div class="vs-tier"><div class="vs-tier-head">⚠️ The helper is running, but it is an older build</div>` +
		`<p class="muted text-sm">It applies Tier 2 and Tier 3 correctly — the switches above work — but it predates the ` +
		`<strong>enforcement digest</strong>, so it cannot report back what is actually in force. That is why the posture ` +
		`report marks the tier rows <em>unverified</em> rather than green: absent evidence is never counted as a pass. ` +
		`Your defences are almost certainly fine; what is missing is the proof.</p>` +
		shieldAgentUpgradeRow() +
		`<p class="muted text-xs">Prefer to do it yourself? This command is the same operation by hand. ` +
		shieldCheckoutHint() + `</p>` +
		shieldCmdRow("vs-cmd-agent-up", shieldAgentCmd("install")) +
		`<p class="muted text-xs">Pull your checkout first so it installs the newest agent. It is idempotent — re-running it on a current ` +
		`agent changes nothing. This one step cannot be a button here: VayuPress is unprivileged by design, and an ` +
		`unprivileged process being able to replace a root one is the exact escalation that separation exists to ` +
		`prevent.</p></div>`
}

// shieldCheckoutHint tells the operator how to find their own checkout rather
// than printing a placeholder path.
//
// The previous copy read "cd /path/to/VayuPress", which is not a command — it is
// a diagram of one, and pasting it produces "No such file or directory". An
// instruction an operator cannot paste is an instruction that has not been given.
func shieldCheckoutHint() string {
	return `The command needs no checkout and works from any directory. It downloads the published ` +
		`agent, verifies its SHA-256 before running anything, and installs it. That is a weaker check ` +
		`than the signature the helper verifies on its own later upgrades &mdash; this one is the ` +
		`bootstrap, run by hand on a machine that may not have <code>cosign</code> yet, and it is worth ` +
		`saying so rather than implying more. Find <code>find /</code> useful instead? ` +
		`<code>sudo find / -name vayushield-agent.sh -path '*/deploy/*'</code>.`
}

// shieldAgentPath is where the updater installs the agent.
//
// A var rather than a const so a test can point it at a file that exists. That
// is not gratuitous: the test guarding against "install runs the already
// installed script" could only observe the bug on a machine where this path is
// present, so in CI it passed against a faithful reintroduction of the bug. A
// test whose verdict depends on the host is not a test of the code.
var shieldAgentPath = "/usr/local/lib/vayushield/vayushield-agent.sh"

// shieldAgentCmd returns an install/uninstall command that runs from ANY
// directory.
//
// The panel used to print `sudo bash deploy/vayushield-agent.sh install`, which
// is a relative path: it works only if the operator's shell happens to be
// sitting in the checkout, and fails with "No such file or directory" everywhere
// else — including the home directory every SSH session starts in. That is the
// same defect as the `/path/to/VayuPress` placeholder this file already fixed
// once: an instruction that cannot be pasted is an instruction that has not been
// given, and a COPY BUTTON makes the promise explicit.
//
// Two forms. When the updater has already placed the agent at its stable path,
// the command is a plain absolute one anybody can read and check before running
// as root. Otherwise it is self-locating — a `find` that prints what it will run
// before running it, because a root command that silently executes whatever a
// filesystem search turned up is not something to hand somebody.
func shieldAgentCmd(action string) string {
	if action == "uninstall" {
		if _, err := os.Stat(shieldAgentPath); err == nil {
			return "sudo bash " + shieldAgentPath + " uninstall"
		}
		return shieldAgentLocateCmd("uninstall")
	}
	// INSTALL is not "run the script that is already there".
	//
	// That was the bug this replaced, and it failed silently, which is the worst
	// way for an installer to fail. install_agent copies from the directory the
	// script lives in — so pointing it at the installed copy copies those files
	// onto themselves, prints "✓ VayuShield agent installed and started", and
	// upgrades nothing. An operator upgrading a stale helper ran it, saw success,
	// and had exactly the same stale helper.
	//
	// Pointing at a checkout is no better as a default: the updater clones to a
	// temporary directory, so the checkout an operator finds is usually older than
	// the release they are running.
	//
	// So the install command fetches the agent from the RELEASE. It is always the
	// newest, it works from any directory, and it does not depend on a clone
	// existing at all.
	return shieldAgentBootstrapCmd()
}

// shieldAgentBootstrapCmd fetches, checks and installs the published agent.
//
// The checksum is verified before anything is executed. That is weaker than the
// signature check the installed helper performs on its own upgrades, and the
// difference is stated in the panel rather than glossed: this is the bootstrap
// step, run by a human with root on a machine that may not have cosign yet, and
// claiming more than a checksum here would be the same overstatement this
// project's posture report exists to avoid.
func shieldAgentBootstrapCmd() string {
	base := "https://github.com/" + shieldAgentRepo + "/releases/latest/download"
	return `sudo bash -c 'd=$(mktemp -d) && cd "$d" && ` +
		`curl -fsSLO ` + base + `/vayushield-agent.tar.gz && ` +
		`curl -fsSL -O ` + base + `/vayushield-agent.tar.gz.sha256 && ` +
		// sha256sum -c reads the file directly now. It used to be
		// `echo "$(cat sum)  vayushield-agent.tar.gz" | sha256sum -c -`, because
		// the release emitted a BARE hash with no filename — a format the standard
		// tool cannot check, so this command hand-assembled the missing half.
		// The release emits "<hash>  <name>" now, and hand-assembling on top of
		// that would append the name twice and fail the check. The two move
		// together; TestTheAgentBootstrapReadsTheChecksumFormatWePublish binds them.
		`sha256sum -c vayushield-agent.tar.gz.sha256 && ` +
		`tar -xzf vayushield-agent.tar.gz && bash ./vayushield-agent.sh install; rm -rf "$d"'`
}

// shieldAgentLocateCmd finds the script on disk and runs it, printing what it
// found first — a root command that silently executes whatever a filesystem
// search turned up is not something to hand somebody.
func shieldAgentLocateCmd(action string) string {
	return `sudo bash -c 's=$(find / -name vayushield-agent.sh -path "*/deploy/*" -print -quit 2>/dev/null); ` +
		`echo "agent script: ${s:-NOT FOUND}"; [ -n "$s" ] && bash "$s" ` + action + `'`
}

// shieldAgentRepo is the repository the published agent bundle comes from. It
// matches the constant in the root-owned script; a test pins the pair, because a
// panel telling operators to install from one place while the helper upgrades
// itself from another is two supply chains where everyone believes there is one.
const shieldAgentRepo = "johalputt/VayuPress"

// shieldCmdRow renders one copyable command block.
func shieldCmdRow(id, cmd string) string {
	return `<div class="vs-cmd"><code id="` + id + `">` + html.EscapeString(cmd) +
		`</code><button type="button" class="vs-copy-btn" data-copy="` + id + `">Copy</button></div>`
}
