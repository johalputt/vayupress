/*
 * admin-os-update.js — Update & Backup panel for VayuOS.
 *
 * Strict CSP: no eval, no innerHTML with server data. All DOM text is set via
 * textContent; class changes only. Every write carries the vp_csrf token.
 *
 * Capabilities:
 *   - Check for updates (GET /os/api/update/check)
 *   - One-click update with auto-restart (POST /os/api/update/apply {restart})
 *   - Roll back to the previous binary (POST /os/api/update/rollback)
 *   - Restore from an uploaded snapshot with upload progress
 *     (POST /os/api/backup/import, multipart "snapshot")
 * After any action that restarts the service, the panel waits for the server to
 * cycle and then reloads itself.
 */
(function () {
  'use strict';

  function csrf() {
    var m = document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : '';
  }

  // readResponse reads a fetch Response defensively. The server (or the reverse
  // proxy in front of it) can return a NON-JSON body — an nginx 502/504 HTML
  // page while the service is restarting mid-update, or a login page if the
  // session lapsed. Calling r.json() on that throws "Unexpected token '<'", so we
  // read the text first and only parse when it is actually JSON. Returns
  // { ok, status, isJSON, d }.
  function readResponse(r) {
    return r.text().then(function (t) {
      var d = {};
      var isJSON = false;
      if (t) {
        try { d = JSON.parse(t); isJSON = true; } catch (e) { isJSON = false; }
      } else {
        isJSON = true; // empty body is acceptable (treated as {})
      }
      return { ok: r.ok, status: r.status, isJSON: isJSON, d: d };
    });
  }

  // errText pulls the human-readable message out of a response. The API returns
  // errors as {"error":{"code,message,...}}, so the message lives at
  // d.error.message — earlier code read d.detail/d.title, which never existed,
  // collapsing every failure to a bare fallback. Fall back through the older
  // shapes and finally to a caller-supplied default.
  function errText(res, fallback) {
    var d = (res && res.d) || {};
    if (d.error && d.error.message) return d.error.message;
    if (d.message) return d.message;
    if (d.detail) return d.detail;
    if (d.title) return d.title;
    if (res && res.status) return fallback + ' (HTTP ' + res.status + ')';
    return fallback;
  }

  // ── Release notes ──────────────────────────────────────────────────────────
  //
  // The notes are the GitHub release body, which now carries this version's
  // CHANGELOG section. Previously it was dumped as raw text, so the operator was
  // shown either a bare compare link or a wall of markdown — in both cases they had
  // to leave the page to find out what they were about to install.
  //
  // This turns it into a short, readable summary. It is a deliberately tiny
  // renderer, not a markdown parser: the notes are EXTERNAL content, so every
  // string goes in via textContent and nothing is ever assigned to innerHTML.

  // parseNotes returns [{ heading, items: [{ lead, rest }] }]. A changelog entry is
  // "- **Lead sentence.** the rest, wrapped over several indented lines", so
  // continuation lines are folded back into the item they belong to.
  function parseNotes(text) {
    var lines = String(text || '').split('\n');
    var sections = [], cur = null, item = null;

    function pushItem() {
      if (cur && item && item.raw) { cur.items.push(splitLead(item.raw)); }
      item = null;
    }
    function section(name) { pushItem(); cur = { heading: name, items: [] }; sections.push(cur); }

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var trimmed = line.trim();

      // Everything from GitHub's own generated tail is noise here: it repeats the
      // release name and links back out to the page we are trying to replace.
      if (/^#{1,3}\s*What'?s Changed/i.test(trimmed)) { break; }
      if (/^\*\*Full Changelog\*\*/i.test(trimmed)) { break; }

      var head = trimmed.match(/^#{2,4}\s+(.+?)\s*$/);
      if (head) {
        var name = head[1].replace(/^\[|\]$/g, '');
        // Skip a "## [3.15.38] — date" heading: the version is already on the card.
        if (!/^\[?\d+\.\d+\.\d+/.test(name)) { section(name); }
        continue;
      }
      if (trimmed === '' || trimmed === '---') { pushItem(); continue; }

      var bullet = trimmed.match(/^(?:[-*]|\d+\.)\s+(.*)$/);
      if (bullet) {
        pushItem();
        if (!cur) { section(''); }
        item = { raw: bullet[1] };
        continue;
      }
      // An indented continuation line belongs to the item above it. The lead is
      // worked out AFTER the whole item is joined: a changelog line wraps at ~80
      // columns, so splitting on the first physical line would cut a sentence in
      // half — which is exactly what it did.
      if (item && /^\s/.test(line)) {
        item.raw += ' ' + trimmed;
      }
    }
    pushItem();
    return sections.filter(function (s) { return s.items.length; });
  }

  // splitLead separates an item's headline from its detail. Changelog entries lead
  // with "**A bold sentence.**"; when one does not, fall back to the first real
  // sentence so the headline is still a whole thought.
  function splitLead(raw) {
    var m = raw.match(/^\*\*(.+?)\*\*\s*([\s\S]*)$/);
    if (m) { return { lead: clean(m[1]), rest: clean(m[2]) }; }
    var text = clean(raw);
    // ". " followed by a capital is a sentence end; ignore one that would leave an
    // implausibly short headline (an abbreviation, a version number).
    var at = -1, from = 0;
    while (true) {
      var i = text.indexOf('. ', from);
      if (i === -1) { break; }
      if (i >= 24 && /[A-Z"“(]/.test(text.charAt(i + 2))) { at = i; break; }
      from = i + 2;
    }
    if (at === -1) { return { lead: text, rest: '' }; }
    return { lead: text.slice(0, at + 1), rest: text.slice(at + 2).trim() };
  }

  // clean strips the markdown that would otherwise show up as literal punctuation.
  function clean(s) {
    return String(s || '')
      .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1') // [text](url) → text
      .replace(/\*\*/g, '')                     // bold
      .replace(/(^|[\s(])\*(\S[^*]*?)\*(?=[\s.,;:)]|$)/g, '$1$2') // italics
      .replace(/`/g, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  // renderNotes builds the summary. MAX_ITEMS keeps the card scannable; anything
  // beyond it is counted, never silently dropped.
  var MAX_ITEMS = 5;
  function renderNotes(el, text, version) {
    el.textContent = '';
    var sections = parseNotes(text);
    if (!sections.length) {
      // Not in changelog shape (an older release, or a hand-written body). Show it
      // as-is rather than showing nothing.
      var raw = clean(text);
      if (!raw) { el.hidden = true; return; }
      el.appendChild(withClass('div', 'upd-notes__raw', raw));
      el.hidden = false;
      return;
    }

    el.appendChild(withClass('div', 'upd-notes__title',
      version ? "What's in " + version : "What's in this update"));

    var shown = 0, hidden = 0;
    for (var s = 0; s < sections.length; s++) {
      var sec = sections[s];
      var remaining = MAX_ITEMS - shown;
      if (remaining <= 0) { hidden += sec.items.length; continue; }

      if (sec.heading) { el.appendChild(withClass('div', 'upd-notes__head', sec.heading)); }
      var list = withClass('ul', 'upd-notes__list', '');
      for (var i = 0; i < sec.items.length; i++) {
        if (i >= remaining) { hidden += sec.items.length - i; break; }
        var it = sec.items[i];
        var li = document.createElement('li');
        li.className = 'upd-notes__item';
        li.appendChild(withClass('span', 'upd-notes__lead', it.lead));
        if (it.rest) { li.appendChild(withClass('span', 'upd-notes__rest', truncate(it.rest, 180))); }
        list.appendChild(li);
        shown++;
      }
      el.appendChild(list);
    }
    if (hidden > 0) {
      el.appendChild(withClass('div', 'upd-notes__more',
        '+ ' + hidden + ' more ' + (hidden === 1 ? 'change' : 'changes') + ' in the full changelog'));
    }
    el.hidden = false;
  }

  function withClass(tag, cls, text) {
    var n = document.createElement(tag);
    n.className = cls;
    if (text) { n.textContent = text; }
    return n;
  }

  function truncate(s, max) {
    if (s.length <= max) { return s; }
    var cut = s.slice(0, max);
    var sp = cut.lastIndexOf(' ');
    return (sp > max * 0.6 ? cut.slice(0, sp) : cut) + '…';
  }

  var card = document.querySelector('[data-update-card]');
  if (!card) return;

  var latestEl = document.querySelector('[data-latest-version]');
  var statusEl = document.querySelector('[data-update-status]');
  var notesEl = document.querySelector('[data-update-notes]');
  var msgEl = document.querySelector('[data-update-msg]');
  var checkBtn = document.querySelector('[data-update-check]');
  var applyBtn = document.querySelector('[data-update-apply]');
  var rollbackBtn = document.querySelector('[data-update-rollback]');

  function setMsg(el, text, isErr) {
    if (!el) return;
    el.textContent = text || '';
    el.classList.toggle('is-error', !!isErr);
  }

  // Poll a cheap endpoint until the service has clearly cycled (one failure
  // followed by a success), then reload so the operator sees the new state.
  function waitForRestartThenReload(el) {
    var sawDown = false;
    var tries = 0;
    var max = 90; // ~3 minutes at 2s
    var timer = setInterval(function () {
      tries++;
      fetch('/os/api/update/history', { cache: 'no-store' })
        .then(function (r) {
          if (r.ok) {
            if (sawDown) {
              clearInterval(timer);
              setMsg(el, 'Service is back online — reloading…', false);
              setTimeout(function () { location.reload(); }, 800);
            }
          } else {
            sawDown = true;
          }
        })
        .catch(function () { sawDown = true; })
        .finally(function () {
          if (tries >= max) {
            clearInterval(timer);
            setMsg(el, 'Still restarting — reload the page in a moment.', true);
          }
        });
    }, 2000);
  }

  // ── Check for updates ──────────────────────────────────────────────────────
  function prereleaseOn() {
    var el = document.querySelector('[data-update-prerelease]');
    return !!(el && el.checked);
  }

  function doCheck() {
    if (checkBtn) checkBtn.disabled = true;
    setMsg(msgEl, 'Checking GitHub for the latest release…', false);
    var checkURL = '/os/api/update/check' + (prereleaseOn() ? '?prerelease=1' : '');
    fetch(checkURL, { headers: { 'X-Requested-With': 'XMLHttpRequest' }, cache: 'no-store' })
      .then(readResponse)
      .then(function (res) {
        if (!res.isJSON) {
          // HTML/empty body → the update service is unreachable (often a brief
          // window while it restarts behind the proxy). Don't surface raw HTML.
          setMsg(msgEl, 'The update service is unavailable right now — it may be restarting. Try Check again in a moment.', true);
          return;
        }
        if (!res.ok) {
          setMsg(msgEl, errText(res, 'Check failed'), true);
          return;
        }
        var d = res.d;
        if (latestEl) latestEl.textContent = d.latest || '—';
        if (statusEl) {
          statusEl.textContent = d.available ? 'Update available' : 'Up to date';
          // Keep the premium chip class; drive its colour via data-state.
          statusEl.className = 'upd-status';
          statusEl.setAttribute('data-state', d.available ? 'available' : 'uptodate');
          // Which endpoint in the chain answered (github / mirror / cdn). A
          // non-GitHub source means this server's direct route to GitHub is
          // unhealthy — the pill makes that visible without alarming anyone.
          statusEl.setAttribute('data-source', d.source || 'github');
        }
        var viaNote = '';
        if (d.source === 'mirror') {
          viaNote = ' Checked via the official mirror — this server could not reach GitHub directly this time.';
        } else if (d.source === 'cdn') {
          viaNote = ' Checked via the release CDN — this server could not reach GitHub or the mirror. The version is confirmed, but installing it needs a reachable download path.';
        }
        if (notesEl) {
          if (d.notes) {
            renderNotes(notesEl, d.notes, d.latest);
          } else {
            notesEl.hidden = true;
          }
        }
        if (applyBtn) {
          applyBtn.disabled = !(d.canApply && d.available);
        }
        if (!d.available) {
          setMsg(msgEl, 'You are running the latest release.' + viaNote, false);
        } else if (!d.canApply) {
          setMsg(msgEl, 'Version ' + d.latest + ' is available, but updates are paused while the system mode is ' + (d.mode || 'restricted') + '.' + viaNote, false);
        } else {
          var chan = d.prerelease ? ' pre-release build' : '';
          var verify = d.signed ? 'checksum + signature verified' : 'checksum verified';
          setMsg(msgEl, 'Version ' + d.latest + chan + ' is ready to install (' + verify + ').' + viaNote, false);
        }
      })
      .catch(function () { setMsg(msgEl, 'Could not reach the update service — check your connection and try again.', true); })
      .finally(function () { if (checkBtn) checkBtn.disabled = false; });
  }

  // ── Apply update (one-click, auto-restart) ──────────────────────────────────
  function doApply() {
    var backupEl = document.querySelector('[data-update-backup]');
    var doBackup = !backupEl || backupEl.checked;
    var prompt = doBackup
      ? 'Install the latest release now? Your database will be backed up first, then the service restarts to finish. This usually takes under a minute (longer for very large databases).'
      : 'Install the latest release now WITHOUT a database backup? A binary update does not change your database, and the previous binary is kept for rollback. The service will restart to finish.';
    if (!window.confirm(prompt)) {
      return;
    }
    if (applyBtn) applyBtn.disabled = true;
    if (checkBtn) checkBtn.disabled = true;
    setMsg(msgEl, doBackup ? 'Backing up, downloading and verifying the release… do not close this tab.' : 'Downloading and verifying the release… do not close this tab.', false);
    fetch('/os/api/update/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
      body: JSON.stringify({ restart: true, backup: doBackup, prerelease: prereleaseOn() })
    })
      .then(readResponse)
      .then(function (res) {
        // A genuine, pre-restart failure (e.g. checksum/signature, paused mode)
        // comes back as a JSON error — show it and re-enable the buttons.
        if (res.isJSON && !res.ok) {
          setMsg(msgEl, errText(res, 'Update failed'), true);
          if (applyBtn) applyBtn.disabled = false;
          if (checkBtn) checkBtn.disabled = false;
          return;
        }
        // Otherwise the update was accepted. Whether we got the JSON success body
        // or a non-JSON body (the service already cycled behind the proxy, or a
        // gateway timeout while it installs+restarts), the right thing is to wait
        // for the service to come back — NOT to report an error.
        if (res.isJSON && res.ok && res.d.version) {
          setMsg(msgEl, 'Installed v' + res.d.version + '. Restarting to activate…', false);
        } else {
          setMsg(msgEl, 'Update applied — the service is restarting to activate it…', false);
        }
        waitForRestartThenReload(msgEl);
      })
      .catch(function () {
        // A dropped connection right after POSTing is the expected restart, not a
        // failure — wait for the service to return rather than alarming the user.
        setMsg(msgEl, 'The service is restarting to finish the update…', false);
        waitForRestartThenReload(msgEl);
      });
  }

  // ── Roll back to the previous binary ────────────────────────────────────────
  function doRollback() {
    if (!window.confirm('Roll back to the previous binary and restart? This undoes the most recent update.')) {
      return;
    }
    if (rollbackBtn) rollbackBtn.disabled = true;
    setMsg(msgEl, 'Rolling back and restarting…', false);
    fetch('/os/api/update/rollback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() }
    })
      .then(readResponse)
      .then(function (res) {
        if (res.isJSON && !res.ok) {
          setMsg(msgEl, errText(res, 'Rollback failed'), true);
          if (rollbackBtn) rollbackBtn.disabled = false;
          return;
        }
        // Accepted (JSON success or a non-JSON body from the cycling service) →
        // wait for the restart rather than reporting a false error.
        setMsg(msgEl, 'Rolled back — the service is restarting…', false);
        waitForRestartThenReload(msgEl);
      })
      .catch(function () {
        setMsg(msgEl, 'The service is restarting to finish the rollback…', false);
        waitForRestartThenReload(msgEl);
      });
  }

  // ── Restore from an uploaded snapshot (with upload progress) ────────────────
  var fileInput = document.querySelector('[data-backup-file]');
  var importBtn = document.querySelector('[data-backup-import]');
  var backupMsg = document.querySelector('[data-backup-msg]');
  var progWrap = document.querySelector('[data-restore-progress]');
  var progBar = document.querySelector('[data-restore-bar]');

  function setBar(pct) {
    if (!progBar) return;
    // Bucketed width class keeps us CSP-clean (no inline style).
    var buckets = [0, 10, 20, 25, 30, 40, 50, 60, 70, 75, 80, 90, 100];
    var chosen = 0;
    for (var i = 0; i < buckets.length; i++) {
      if (pct >= buckets[i]) chosen = buckets[i];
    }
    progBar.className = 'progress__bar progress__bar--ok w-' + chosen;
  }

  function doImport() {
    var f = fileInput && fileInput.files && fileInput.files[0];
    if (!f) { setMsg(backupMsg, 'Choose a backup file first.', true); return; }
    if (!window.confirm('Restore from "' + f.name + '"? This REPLACES all current content and settings. Your current database is backed up automatically, then the service restarts.')) {
      return;
    }
    if (importBtn) importBtn.disabled = true;
    if (progWrap) progWrap.hidden = false;
    setBar(0);
    setMsg(backupMsg, 'Uploading…', false);

    var fd = new FormData();
    fd.append('snapshot', f, f.name);

    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/os/api/backup/import', true);
    xhr.setRequestHeader('X-CSRF-Token', csrf());
    xhr.upload.onprogress = function (e) {
      if (e.lengthComputable) {
        var pct = Math.round((e.loaded / e.total) * 100);
        setBar(pct);
        setMsg(backupMsg, 'Uploading… ' + pct + '%', false);
      }
    };
    xhr.onload = function () {
      var d = {};
      try { d = JSON.parse(xhr.responseText); } catch (e) { d = {}; }
      if (xhr.status >= 200 && xhr.status < 300) {
        setBar(100);
        setMsg(backupMsg, 'Backup validated. Restoring and restarting…', false);
        waitForRestartThenReload(backupMsg);
      } else {
        setMsg(backupMsg, errText({ d: d, status: xhr.status }, 'Restore failed'), true);
        if (importBtn) importBtn.disabled = false;
      }
    };
    xhr.onerror = function () {
      setMsg(backupMsg, 'Upload failed — network error.', true);
      if (importBtn) importBtn.disabled = false;
    };
    xhr.send(fd);
  }

  if (checkBtn) checkBtn.addEventListener('click', doCheck);
  if (applyBtn) applyBtn.addEventListener('click', doApply);
  if (rollbackBtn) rollbackBtn.addEventListener('click', doRollback);
  if (importBtn) importBtn.addEventListener('click', doImport);

  // ── Subdomain provisioning ────────────────────────────────────────────────
  // Installing an update swaps the binary only; the service is unprivileged and
  // cannot obtain a certificate or reload nginx. This asks a root-side systemd
  // unit to do that step, then polls until it reports back — so the operator
  // sees the outcome here instead of having to read a log over SSH.
  (function () {
    var btn = document.querySelector('[data-provision-run]');
    var out = document.querySelector('[data-provision-status]');
    if (!btn || !out) return;

    var polls = 0;
    function poll() {
      // Bounded: a request nothing consumes must not spin forever. If the
      // helper is missing the server says so and we stop with that message,
      // rather than showing "running..." indefinitely.
      if (polls++ > 60) { out.textContent = 'Still running — reload to see the result.'; return; }
      fetch('/os/api/provision/status', { credentials: 'same-origin' })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          if (j && j.pending) { out.textContent = 'Running…'; setTimeout(poll, 3000); return; }
          if (j && j.result && j.result.finished_at) {
            var f = j.result.failed || 0;
            out.textContent = f > 0
              ? 'Finished — ' + f + ' helper(s) reported a problem. Reload for detail.'
              : 'Finished cleanly. Reload to see the summary.';
          } else {
            out.textContent = 'Finished. Reload to see the summary.';
          }
          btn.disabled = false;
        })
        .catch(function () { out.textContent = 'Could not read status.'; btn.disabled = false; });
    }

    btn.addEventListener('click', function () {
      btn.disabled = true;
      out.textContent = 'Requesting…';
      polls = 0;
      fetch('/os/api/provision/run', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() }
      })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          if (!res.ok) {
            out.textContent = (res.j && (res.j.detail || res.j.message)) || 'Request failed.';
            btn.disabled = false;
            return;
          }
          out.textContent = 'Running…';
          setTimeout(poll, 3000);
        })
        .catch(function () { out.textContent = 'Request failed.'; btn.disabled = false; });
    });
  })();

  // Auto-check on load so the operator immediately sees whether an update exists.
  doCheck();

  // Copy the one privileged install command. Delegated from document because the
  // card renders on two pages and only one of them has the run button.
  (function () {
    document.addEventListener('click', function (e) {
      var b = e.target && e.target.closest ? e.target.closest('[data-provision-copy]') : null;
      if (!b) return;
      var code = document.querySelector('[data-provision-cmd]');
      if (!code) return;
      var text = code.textContent || '';
      var was = b.textContent;
      var done = function (msg) { b.textContent = msg; setTimeout(function () { b.textContent = was; }, 2000); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { done('Copied'); }).catch(function () {
          // Clipboard needs a secure context and a permission some browsers
          // refuse; select the text so Ctrl-C still works rather than leaving a
          // button that silently did nothing.
          selectText(code); done('Press Ctrl-C');
        });
      } else { selectText(code); done('Press Ctrl-C'); }
    });
    function selectText(el) {
      try {
        var r = document.createRange(); r.selectNodeContents(el);
        var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
      } catch (err) { /* selection unavailable — nothing further to try */ }
    }
  })();
})();
