// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_messages.go — VayuOS "Messages" surface: the contact-form inbox.
//
// Every public contact submission is persisted to contact_messages (see
// migration 046) so operators always have a durable record, even if SMTP
// delivery is unconfigured or fails. This page lists them newest-first with
// mark-read and delete controls. Unread messages are highlighted and counted.
//
// CSP posture matches the rest of VayuOS: no inline styles, the only inline
// <script> carries the per-request nonce, every dynamic string is escaped.

import (
	"encoding/csv"
	"html"
	htmpl "html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/render"
)

func (a *App) handleOSMessages(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())

	csrfTokenFor(w, r)

	// Filters: free-text search across name/email/message, and an unread-only
	// toggle. Both are applied in SQL so the list scales past the render cap.
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 120 {
		q = q[:120]
	}
	unreadOnly := r.URL.Query().Get("unread") == "1"
	from := normalizeDateParam(r.URL.Query().Get("from"))
	to := normalizeDateParam(r.URL.Query().Get("to"))
	filtersActive := q != "" || unreadOnly || from != "" || to != ""

	type msgRow struct {
		ID, Name, Email, Message, Page string
		Country, City                  string
		Read                           bool
		Created                        time.Time
	}
	var msgs []msgRow
	unread := 0 // total unread, independent of the active filter (header + badge)
	if dbpkg.DB != nil {
		_ = dbpkg.Reader().QueryRowContext(r.Context(), `SELECT COUNT(1) FROM contact_messages WHERE is_read=0`).Scan(&unread)

		where := []string{}
		args := []any{}
		if q != "" {
			where = append(where, "(name LIKE ? OR email LIKE ? OR message LIKE ?)")
			like := "%" + q + "%"
			args = append(args, like, like, like)
		}
		if unreadOnly {
			where = append(where, "is_read=0")
		}
		if from != "" {
			where = append(where, "date(created_at) >= ?")
			args = append(args, from)
		}
		if to != "" {
			where = append(where, "date(created_at) <= ?")
			args = append(args, to)
		}
		clause := ""
		if len(where) > 0 {
			clause = " WHERE " + strings.Join(where, " AND ")
		}
		if rows, err := dbpkg.Reader().QueryContext(r.Context(),
			`SELECT id,name,email,message,page,country,city,is_read,created_at FROM contact_messages`+clause+` ORDER BY created_at DESC LIMIT 500`, args...); err == nil {
			defer rows.Close() //nolint:errcheck
			for rows.Next() {
				var m msgRow
				var read int
				if rows.Scan(&m.ID, &m.Name, &m.Email, &m.Message, &m.Page, &m.Country, &m.City, &read, &m.Created) == nil {
					m.Read = read != 0
					msgs = append(msgs, m)
				}
			}
			_ = rows.Err()
		}
	}

	// Filter toolbar: a GET search form + an unread-only toggle link that
	// preserves the current query. Plain links/forms → CSP-safe, JS-free.
	// The unread toggle preserves the active search + date range. Build its href
	// from the current params, flipping only the unread flag.
	uv := url.Values{}
	if q != "" {
		uv.Set("q", q)
	}
	if from != "" {
		uv.Set("from", from)
	}
	if to != "" {
		uv.Set("to", to)
	}
	if !unreadOnly {
		uv.Set("unread", "1")
	}
	unreadHref := "/os/messages"
	if enc := uv.Encode(); enc != "" {
		unreadHref = "/os/messages?" + enc
	}
	unreadCls := "btn btn--ghost btn--sm"
	if unreadOnly {
		unreadCls = "btn btn--primary btn--sm"
	}
	// The unread flag rides the search form via a hidden field so a search keeps
	// the unread filter on.
	unreadHidden := ""
	if unreadOnly {
		unreadHidden = `<input type="hidden" name="unread" value="1">`
	}
	filterBar := `<div class="card"><div class="toolbar-row">
  <form method="GET" action="/os/messages" class="vm-row" style="flex:1;gap:.5rem;flex-wrap:wrap">
    ` + unreadHidden + `
    <input type="search" name="q" class="input" style="flex:1;min-width:160px" value="` + html.EscapeString(q) + `" placeholder="Search name, email or message…" aria-label="Search messages">
    <label class="text-xs muted">From <input type="date" name="from" class="input input--sm" value="` + html.EscapeString(from) + `" aria-label="From date"></label>
    <label class="text-xs muted">To <input type="date" name="to" class="input input--sm" value="` + html.EscapeString(to) + `" aria-label="To date"></label>
    <button type="submit" class="btn btn--sm">Apply</button>
  </form>
  <a class="` + unreadCls + `" href="` + unreadHref + `">Unread only</a>
  ` + filterClearLink(filtersActive) + `
</div></div>`

	var body string
	if len(msgs) == 0 && !filtersActive {
		body = `<div class="page-header"><h1>Messages</h1>
  <p class="text-sm muted">Submissions from your contact form land here — a durable record, even if email delivery fails.</p></div>
<div class="card empty-state"><div class="empty-icon">📨</div>
  <div class="empty-title">No messages yet</div>
  <div class="empty-sub">When a visitor sends a message through a page's contact form, it appears here. Add a contact form from the Pages section.</div></div>`
	} else if len(msgs) == 0 {
		body = messagesHeader(0, unread) + filterBar +
			`<div class="card empty-state"><div class="empty-icon">🔍</div>
  <div class="empty-title">No matching messages</div>
  <div class="empty-sub">No messages match your search or filter. <a href="/os/messages">Clear filters</a>.</div></div>`
	} else {
		rows := ""
		for _, m := range msgs {
			rowCls := "row-title"
			pill := ""
			if !m.Read {
				pill = `<span class="status-pill status-pill--draft">● New</span> `
			}
			pageCell := ""
			if m.Page != "" {
				pageCell = `<a href="` + html.EscapeString(m.Page) + `" target="_blank" rel="noopener">` + html.EscapeString(m.Page) + `</a>`
			}
			readBtn := ""
			if !m.Read {
				readBtn = `<button type="button" class="btn btn--ghost btn--sm" data-msg-read data-id="` + html.EscapeString(m.ID) + `">Mark read</button>`
			}
			rows += `<tr data-msg-row>
  <td class="` + rowCls + `">` + pill + `<a href="/os/messages/` + html.EscapeString(m.ID) + `"><strong>` + html.EscapeString(m.Name) + `</strong></a>
    <div class="row-meta"><a href="mailto:` + html.EscapeString(m.Email) + `">` + html.EscapeString(m.Email) + `</a></div></td>
  <td style="white-space:pre-wrap;max-width:40ch">` + html.EscapeString(m.Message) + `</td>
  <td>` + pageCell + `</td>
  <td class="text-sm">` + geoDisplayHTML(m.Country, m.City) + `</td>
  <td class="muted text-sm">` + config.FormatSite(m.Created, "2 Jan 2006 15:04") + `</td>
  <td class="row-actions">
    <a class="btn btn--ghost btn--sm" href="mailto:` + html.EscapeString(m.Email) + `?subject=Re:%20your%20message">Reply</a>
    ` + readBtn + `
    <button type="button" class="btn btn--ghost btn--sm" data-msg-delete data-id="` + html.EscapeString(m.ID) + `">Delete</button>
  </td>
</tr>`
		}
		body = messagesHeader(len(msgs), unread) + filterBar + `
<div class="card"><div class="table-wrap"><table class="table">
  <thead><tr><th>From</th><th>Message</th><th>Page</th><th>Location</th><th>When</th><th></th></tr></thead>
  <tbody>` + rows + `</tbody>
</table></div></div>
<div id="msg-status" class="text-sm muted" role="status" aria-live="polite"></div>
<script nonce="` + nonce + `">
(function(){'use strict';
function csrf(){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
var st=document.getElementById('msg-status');
function show(t){if(st)st.textContent=t;}
document.querySelectorAll('[data-msg-read]').forEach(function(b){
  b.addEventListener('click',function(){
    b.disabled=true;show('Saving…');
    fetch('/os/api/messages/'+encodeURIComponent(b.getAttribute('data-id'))+'/read',{method:'PUT',headers:{'X-CSRF-Token':csrf()}})
      .then(function(r){if(r.ok){location.reload();}else{b.disabled=false;show('Could not update');}})
      .catch(function(e){b.disabled=false;show('Error: '+e);});
  });
});
document.querySelectorAll('[data-msg-delete]').forEach(function(b){
  b.addEventListener('click',function(){
    vpConfirm({title:'Delete message',message:'Delete this message? This cannot be undone.',confirm:'Delete'},function(){
    b.disabled=true;show('Deleting…');
    fetch('/os/api/messages/'+encodeURIComponent(b.getAttribute('data-id')),{method:'DELETE',headers:{'X-CSRF-Token':csrf()}})
      .then(function(r){if(r.ok){var row=b.closest('[data-msg-row]');if(row)row.remove();show('Deleted');}else{b.disabled=false;show('Could not delete');}})
      .catch(function(e){b.disabled=false;show('Error: '+e);});
    });
  });
});
var readAll=document.querySelector('[data-msg-readall]');
if(readAll)readAll.addEventListener('click',function(){
  readAll.disabled=true;show('Marking all read…');
  fetch('/os/api/messages/read-all',{method:'POST',headers:{'X-CSRF-Token':csrf()}})
    .then(function(r){if(r.ok){location.reload();}else{readAll.disabled=false;show('Could not update');}})
    .catch(function(e){readAll.disabled=false;show('Error: '+e);});
});
var delRead=document.querySelector('[data-msg-deleteread]');
if(delRead)delRead.addEventListener('click',function(){
  vpConfirm({title:'Clear read messages',message:'Delete all messages already marked read? This cannot be undone.',confirm:'Delete read'},function(){
  delRead.disabled=true;show('Clearing read…');
  fetch('/os/api/messages/delete-read',{method:'POST',headers:{'X-CSRF-Token':csrf()}})
    .then(function(r){if(r.ok){location.reload();}else{delRead.disabled=false;show('Could not clear');}})
    .catch(function(e){delRead.disabled=false;show('Error: '+e);});
  });
});
})();
</script>`
	}

	writeOSHTML(w, r, adminOSLayout(nonce, "Messages", "messages", cfg, htmpl.HTML(body)))
}

// handleOSMessageDetail shows a single contact message in full, and marks it
// read on open so the badge/count stay accurate. Reply/delete actions are
// surfaced; delete redirects back to the inbox.
func (a *App) handleOSMessageDetail(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())
	id := chi.URLParam(r, "id")

	csrfTokenFor(w, r)

	var name, eml, msg, page, country, region, city string
	var created time.Time
	var read int
	found := false
	if dbpkg.DB != nil {
		if err := dbpkg.Reader().QueryRowContext(r.Context(),
			`SELECT name,email,message,page,country,region,city,is_read,created_at FROM contact_messages WHERE id=?`, id).
			Scan(&name, &eml, &msg, &page, &country, &region, &city, &read, &created); err == nil {
			found = true
		}
	}
	if !found {
		body := `<div class="page-header"><h1>Message</h1></div>
<div class="card empty-state"><div class="empty-icon">🔍</div>
  <div class="empty-title">Message not found</div>
  <div class="empty-sub">It may have been deleted. <a href="/os/messages">Back to inbox</a>.</div></div>`
		writeOSHTML(w, r, adminOSLayout(nonce, "Message", "messages", cfg, htmpl.HTML(body)))
		return
	}

	// Opening a message marks it read (best-effort).
	if read == 0 {
		_, _ = dbpkg.WDB.ExecContext(r.Context(), `UPDATE contact_messages SET is_read=1 WHERE id=?`, id)
	}

	pageRow := ""
	if page != "" {
		pageRow = `<div class="kv-row"><span class="kv-key">Page</span><span class="kv-val"><a href="` + html.EscapeString(page) + `" target="_blank" rel="noopener">` + html.EscapeString(page) + `</a></span></div>`
	}
	// GDPR-safe location instead of a raw IP: coarse country + city + region,
	// captured at submit time (no IP is ever stored or shown).
	locVal := geoDisplayHTML(country, city)
	if strings.TrimSpace(region) != "" && strings.TrimSpace(city) == "" && strings.TrimSpace(country) != "" {
		locVal = countryDisplayHTML(country) + ` <span class="muted">· ` + html.EscapeString(region) + `</span>`
	}
	ipRow := `<div class="kv-row"><span class="kv-key">Location</span><span class="kv-val">` + locVal + `</span></div>`
	replyURL := "mailto:" + html.EscapeString(eml) + "?subject=" + url.QueryEscape("Re: your message") +
		"&body=" + url.QueryEscape("\n\n— On "+config.FormatSite(created, "2 Jan 2006")+", "+name+" wrote:\n> "+msg)

	body := `<div class="page-header">
  <div><h1>Message from ` + html.EscapeString(name) + `</h1>
    <p class="text-sm muted">` + config.FormatSite(created, "2 Jan 2006 15:04 MST") + `</p></div>
  <div class="page-actions">
    <a class="btn btn--ghost btn--sm" href="/os/messages">← Inbox</a>
    <a class="btn btn--primary btn--sm" href="` + replyURL + `">Reply</a>
    <button type="button" class="btn btn--ghost btn--sm" data-msg-detail-delete data-id="` + html.EscapeString(id) + `">Delete</button>
  </div>
</div>
<div class="card">
  <div class="kv-row"><span class="kv-key">From</span><span class="kv-val"><strong>` + html.EscapeString(name) + `</strong> &lt;<a href="mailto:` + html.EscapeString(eml) + `">` + html.EscapeString(eml) + `</a>&gt;</span></div>
  ` + pageRow + ipRow + `
</div>
<div class="card">
  <div class="text-sm muted mb-2">Message</div>
  <div style="white-space:pre-wrap;line-height:1.6">` + html.EscapeString(msg) + `</div>
</div>
<div id="msg-status" class="text-sm muted" role="status" aria-live="polite"></div>
<script nonce="` + nonce + `">
(function(){'use strict';
function csrf(){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
var b=document.querySelector('[data-msg-detail-delete]');
if(b)b.addEventListener('click',function(){
  vpConfirm({title:'Delete message',message:'Delete this message? This cannot be undone.',confirm:'Delete'},function(){
  b.disabled=true;
  fetch('/os/api/messages/'+encodeURIComponent(b.getAttribute('data-id')),{method:'DELETE',headers:{'X-CSRF-Token':csrf()}})
    .then(function(r){if(r.ok){window.location.href='/os/messages';}else{b.disabled=false;var s=document.getElementById('msg-status');if(s)s.textContent='Could not delete';}})
    .catch(function(e){b.disabled=false;var s=document.getElementById('msg-status');if(s)s.textContent='Error: '+e;});
  });
});
})();
</script>`

	writeOSHTML(w, r, adminOSLayout(nonce, "Message", "messages", cfg, htmpl.HTML(body)))
}

// messagesHeader renders the Messages page header with the count, unread tally
// and the bulk/export actions. Shared by the list and filtered-empty views.
func messagesHeader(count, unread int) string {
	return `<div class="page-header">
  <h1>Messages <span class="count-pill">` + intToStr(count) + `</span></h1>
  <div class="page-actions">
    <span class="text-sm muted">` + intToStr(unread) + ` unread</span>
    <a class="btn btn--ghost btn--sm" href="/os/api/messages/export.csv" download>Export CSV</a>
    <button type="button" class="btn btn--ghost btn--sm" data-msg-readall>Mark all read</button>
    <button type="button" class="btn btn--ghost btn--sm" data-msg-deleteread>Clear read</button>
  </div>
</div>
<p class="page-sub">Submissions from your contact forms land here — a durable record, even if email delivery fails. Search, filter, reply and export.</p>`
}

// filterClearLink renders a "Clear" link when any filter is active.
func filterClearLink(active bool) string {
	if !active {
		return ""
	}
	return `<a class="btn btn--ghost btn--sm" href="/os/messages">Clear</a>`
}

// handleOSMessageRead marks a contact message read.
func (a *App) handleOSMessageRead(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := dbpkg.WDB.ExecContext(r.Context(), `UPDATE contact_messages SET is_read=1 WHERE id=?`, id); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "db-error", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// handleOSMessageDelete removes a contact message.
func (a *App) handleOSMessageDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := dbpkg.WDB.ExecContext(r.Context(), `DELETE FROM contact_messages WHERE id=?`, id); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "db-error", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// handleOSMessagesReadAll marks every message read in one go.
func (a *App) handleOSMessagesReadAll(w http.ResponseWriter, r *http.Request) {
	if _, err := dbpkg.WDB.ExecContext(r.Context(), `UPDATE contact_messages SET is_read=1 WHERE is_read=0`); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "db-error", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// handleOSMessagesDeleteRead clears out every already-read message (an
// "empty trash" for processed submissions). Unread messages are kept.
func (a *App) handleOSMessagesDeleteRead(w http.ResponseWriter, r *http.Request) {
	if _, err := dbpkg.WDB.ExecContext(r.Context(), `DELETE FROM contact_messages WHERE is_read=1`); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "db-error", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// handleOSMessagesExportCSV streams every contact message as a downloadable CSV
// (RFC 4180 via encoding/csv, which quotes/escapes commas, quotes and newlines).
func (a *App) handleOSMessagesExportCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="contact-messages.csv"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"created_at", "name", "email", "page", "country", "region", "city", "read", "message"})
	if dbpkg.DB == nil {
		return
	}
	rows, err := dbpkg.Reader().QueryContext(r.Context(),
		`SELECT created_at,name,email,page,country,region,city,is_read,message FROM contact_messages ORDER BY created_at DESC`)
	if err != nil {
		return
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var created time.Time
		var name, eml, page, country, region, city, msg string
		var read int
		if rows.Scan(&created, &name, &eml, &page, &country, &region, &city, &read, &msg) != nil {
			continue
		}
		readStr := "no"
		if read != 0 {
			readStr = "yes"
		}
		_ = cw.Write([]string{created.UTC().Format(time.RFC3339), name, eml, page, country, region, city, readStr, msg})
	}
	_ = rows.Err()
}
