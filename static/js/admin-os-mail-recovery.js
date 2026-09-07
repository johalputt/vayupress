/*
 * admin-os-mail-recovery.js — enrolment controls for VayuMail account recovery.
 *
 * Strict CSP: no eval, nothing from the server is ever assigned as markup. Every
 * value goes in through textContent, because this panel renders mail addresses
 * and server error strings.
 *
 * The recovery codes are shown exactly once, in the response to the generate
 * call — the server keeps only Argon2id hashes and cannot show them again. So
 * the one job that matters here is making sure they are not lost between the
 * response arriving and the operator writing them down.
 */
(function () {
  'use strict';

  // Every mailbox card carries its own panel, so there are as many of these on
  // the Accounts page as there are mailboxes. Each one is bound independently
  // against its own elements — a single module-level `panel` would have wired
  // only the first card and left the rest inert.
  function bindPanel(panel) {
    if (panel.getAttribute('data-rec-bound') === '1') { return; }
    panel.setAttribute('data-rec-bound', '1');

    var mailbox = panel.querySelector('[data-rec-mailbox]');
    var statusEl = panel.querySelector('[data-rec-status]');
    var codesEl = panel.querySelector('[data-rec-codes]');
    var contactEl = panel.querySelector('[data-rec-contact]');
    var msgEl = panel.querySelector('[data-rec-msg]');

    function csrf() {
      var m = document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);
      return m ? decodeURIComponent(m[1]) : '';
    }

    function setMsg(text, isErr) {
      if (!msgEl) { return; }
      msgEl.textContent = text || '';
      msgEl.classList.toggle('is-error', !!isErr);
    }

    function post(url, payload) {
      return fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
        body: JSON.stringify(payload)
      }).then(function (r) {
        return r.text().then(function (t) {
          var d = {};
          try { d = t ? JSON.parse(t) : {}; } catch (e) { d = {}; }
          return { ok: r.ok, d: d };
        });
      });
    }

    function errText(res, fallback) {
      var d = (res && res.d) || {};
      if (d.error && d.error.message) { return d.error.message; }
      if (d.message) { return d.message; }
      return fallback;
    }

    function current() { return (mailbox && mailbox.value) || ''; }

    // renderStatus states plainly whether this mailbox could actually be recovered.
    // "Ready" is reserved for a CONFIRMED factor: a pending address is not one.
    function renderStatus(st) {
      if (!statusEl) { return; }
      statusEl.textContent = '';
      if (!st) { return; }

      var line = document.createElement('div');
      var parts = [];
      if (st.codes_remaining > 0) {
        parts.push(st.codes_remaining + ' unused recovery code' + (st.codes_remaining === 1 ? '' : 's'));
      }
      if (st.contact) { parts.push('verified address ' + st.contact); }
      if (st.contact_pending) { parts.push('address ' + st.contact_pending + ' awaiting verification'); }

      if (st.ready) {
        line.textContent = '✓ Can be recovered — ' + parts.join('; ') + '.';
      } else if (parts.length) {
        line.textContent = '✕ Cannot be recovered yet — ' + parts.join('; ') +
          '. An address only counts once it is verified.';
      } else {
        line.textContent = '✕ Cannot be recovered — nothing is enrolled. If this holder forgets their ' +
          'password, only a server operator with shell access can help.';
      }
      statusEl.appendChild(line);

      if (contactEl) { contactEl.value = st.contact || st.contact_pending || ''; }
      // NOTE: this must NOT clear the codes. renderStatus also runs immediately
      // after a successful generate (to refresh the remaining count), so clearing
      // here wiped the one and only display of the codes a moment after showing
      // them — the panel looked like the button did nothing. Clearing belongs to
      // the mailbox-change handler, which is the case it was written for.
    }

    // clearCodes drops any codes on screen. Bound to mailbox selection: a set left
    // over from the previous mailbox belongs to a different account and would be
    // written down against the wrong one.
    function clearCodes() {
      if (codesEl) { codesEl.textContent = ''; codesEl.hidden = true; }
    }

    function loadStatus() {
      var m = current();
      if (!m) { return; }
      fetch('/os/api/vayuos/mail/recovery/status?email=' + encodeURIComponent(m),
        { credentials: 'same-origin', cache: 'no-store' })
        .then(function (r) { return r.json(); })
        .then(renderStatus)
        .catch(function () { setMsg('Could not load recovery status.', true); });
    }

    // showCodes renders the one and only time these exist in readable form.
    function showCodes(codes) {
      if (!codesEl) { return; }
      codesEl.textContent = '';

      var warn = document.createElement('p');
      warn.className = 'rec-codes__warn';
      warn.textContent = 'Save these now — they cannot be shown again. Each code works once. ' +
        'Any previous codes for this mailbox have stopped working.';
      codesEl.appendChild(warn);

      var grid = document.createElement('div');
      grid.className = 'rec-codes__grid';
      codes.forEach(function (c) {
        var cell = document.createElement('code');
        cell.className = 'rec-codes__code';
        cell.textContent = c;
        grid.appendChild(cell);
      });
      codesEl.appendChild(grid);

      var actions = document.createElement('div');
      actions.className = 'rec-codes__actions';

      var copy = document.createElement('button');
      copy.type = 'button';
      copy.className = 'btn btn--sm btn--ghost';
      copy.textContent = 'Copy all';
      copy.addEventListener('click', function () {
        var text = codeSheet(codes);
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            copy.textContent = 'Copied';
          }).catch(function () { copy.textContent = 'Copy failed — use Download instead'; });
        } else {
          // The clipboard API needs a secure context and a permission that some
          // browsers refuse. Download always works, so say so rather than leaving
          // the operator with a button that did nothing.
          copy.textContent = 'Clipboard unavailable — use Download instead';
        }
      });
      actions.appendChild(copy);

      var dl = document.createElement('button');
      dl.type = 'button';
      dl.className = 'btn btn--sm btn--ghost';
      dl.textContent = 'Download .txt';
      dl.addEventListener('click', function () { downloadCodes(codes); });
      actions.appendChild(dl);

      var print = document.createElement('button');
      print.type = 'button';
      print.className = 'btn btn--sm btn--ghost';
      print.textContent = 'Print';
      print.addEventListener('click', function () { printCodes(codes); });
      actions.appendChild(print);

      codesEl.appendChild(actions);
      codesEl.hidden = false;
    }

    // codeSheet is the text written to the clipboard, the file and the printout.
    //
    // It carries the mailbox, the server and the URL the codes are used at, because
    // a bare list of twelve-character strings found in a drawer two years from now
    // tells its owner nothing about what it unlocks or where to take it.
    function codeSheet(codes) {
      var mb = current();
      var lines = [
        'VayuMail recovery codes',
        '=======================',
        '',
        'Mailbox : ' + mb,
        'Server  : ' + location.host,
        'Created : ' + new Date().toISOString().slice(0, 10),
        '',
        'Each code can be used ONCE to set a new password for this mailbox at:',
        '  ' + location.origin + '/mail/recover/code',
        ''
      ];
      codes.forEach(function (c) { lines.push('  ' + c); });
      lines.push(
        '',
        'Keep this somewhere you can reach WITHOUT this mailbox — a password',
        'manager, a printout, or another device. Anyone holding these codes can',
        'take over the mailbox, so treat them exactly like the password itself.',
        '',
        'Generating a new set invalidates every code above.',
        ''
      );
      return lines.join('\n');
    }

    // safeFileName keeps the mailbox recognisable in the filename without letting
    // an address shape a path.
    function safeFileName(mb) {
      return (mb || 'mailbox').replace(/[^A-Za-z0-9._@-]/g, '-').slice(0, 64);
    }

    function downloadCodes(codes) {
      var blob = new Blob([codeSheet(codes)], { type: 'text/plain;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'vayumail-recovery-codes-' + safeFileName(current()) + '.txt';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      // Revoke promptly. A blob: URL stays resolvable for the life of the document,
      // so leaving it alive would keep the codes fetchable from this tab long after
      // the panel was closed.
      setTimeout(function () { URL.revokeObjectURL(url); }, 30000);
    }

    // printCodes opens the sheet in its own window. Recovery codes belong in a
    // drawer as much as in a password manager, and printing from the console page
    // itself would print the whole mailbox list around them.
    function printCodes(codes) {
      var w = window.open('', '_blank', 'width=640,height=760');
      if (!w) {
        setMsg('Your browser blocked the print window — use Download .txt instead.', true);
        return;
      }
      // Built as text in a <pre>, not as markup: the codes and the mailbox go in
      // through textContent so nothing here can become HTML.
      var doc = w.document;
      doc.title = 'VayuMail recovery codes';
      var pre = doc.createElement('pre');
      pre.style.font = '13px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace';
      pre.style.padding = '24px';
      pre.style.whiteSpace = 'pre-wrap';
      pre.textContent = codeSheet(codes);
      doc.body.appendChild(pre);
      w.focus();
      w.print();
    }

    if (mailbox) {
      mailbox.addEventListener('change', function () { setMsg(''); clearCodes(); loadStatus(); });
    }

    var genBtn = panel.querySelector('[data-rec-gen]');
    if (genBtn) {
      genBtn.addEventListener('click', function () {
        var m = current();
        if (!m) { return; }
        // Regeneration destroys the previous set, so it is worth one confirmation:
        // an operator who does this by accident has just invalidated the sheet the
        // holder is carrying.
        vpConfirm({ title: 'Generate new codes', message: 'Generate new codes for ' + m + '? Any codes already given to this holder will stop working.', confirm: 'Generate' }, function () {
          genBtn.disabled = true;
          setMsg('Generating…', false);
          post('/os/api/vayuos/mail/recovery/codes', { email: m }).then(function (res) {
            if (!res.ok) { setMsg(errText(res, 'Could not generate codes.'), true); return; }
            showCodes(res.d.codes || []);
            setMsg('', false);
            loadStatus();
          }).catch(function () {
            setMsg('Could not reach the server.', true);
          }).finally(function () { genBtn.disabled = false; });
        });
      });
    }

    function contactAction(action, needValue) {
      var m = current();
      if (!m) { return; }
      var payload = { email: m, action: action };
      if (needValue) { payload.contact = (contactEl && contactEl.value) || ''; }
      setMsg('Saving…', false);
      post('/os/api/vayuos/mail/recovery/contact', payload).then(function (res) {
        if (!res.ok) { setMsg(errText(res, 'That did not work.'), true); return; }
        renderStatus(res.d);
        setMsg(action === 'verify' ? 'Address verified — it is now a working recovery factor.'
          : action === 'clear' ? 'Recovery address removed.'
            : 'Saved. It does not count as recovery until you mark it verified.', false);
      }).catch(function () { setMsg('Could not reach the server.', true); });
    }

    var setBtn = panel.querySelector('[data-rec-set]');
    if (setBtn) { setBtn.addEventListener('click', function () { contactAction('set', true); }); }
    var verifyBtn = panel.querySelector('[data-rec-verify]');
    if (verifyBtn) { verifyBtn.addEventListener('click', function () { contactAction('verify', false); }); }
    var clearBtn = panel.querySelector('[data-rec-clear]');
    if (clearBtn) {
      clearBtn.addEventListener('click', function () {
        vpConfirm({ title: 'Remove recovery address', message: 'Remove the recovery address for ' + current() + '?', confirm: 'Remove' }, function () {
          contactAction('clear', false);
        });
      });
    }

      // Load the status LAZILY. An install with thirty mailboxes has thirty of
      // these panels, and fetching every one at page load would fire thirty
      // requests for cards nobody has opened. The <details> toggle is the moment
      // the operator actually wants to know.
      if (panel.tagName === 'DETAILS') {
        panel.addEventListener('toggle', function () {
          if (panel.open && panel.getAttribute('data-rec-loaded') !== '1') {
            panel.setAttribute('data-rec-loaded', '1');
            loadStatus();
          }
        });
        if (panel.open) { panel.setAttribute('data-rec-loaded', '1'); loadStatus(); }
      } else {
        loadStatus();
      }
  }

  function bindAll() {
    var panels = document.querySelectorAll('[data-recovery-panel]');
    for (var i = 0; i < panels.length; i++) { bindPanel(panels[i]); }
  }

  // The assisted-recovery queue lives on the summary card, once for the page.
  function bindQueue() {
    var body = document.querySelector('[data-rec-queue]');
    if (!body || body.getAttribute('data-rec-bound') === '1') { return; }
    body.setAttribute('data-rec-bound', '1');
    var out = document.querySelector('[data-rec-approved]');

    function csrfTok() {
      var m = document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);
      return m ? decodeURIComponent(m[1]) : '';
    }

    body.addEventListener('click', function (ev) {
      var approve = ev.target.closest('[data-rec-approve]');
      var decline = ev.target.closest('[data-rec-decline]');
      if (!approve && !decline) { return; }
      var row = ev.target.closest('[data-rec-req]');
      if (!row) { return; }
      var id = parseInt(row.getAttribute('data-rec-req'), 10);
      var mb = (row.firstElementChild && row.firstElementChild.textContent) || 'this mailbox';

      // Approval is the step an attacker would try to talk an administrator
      // through, so it asks out loud who they have actually spoken to.
      function decide() {
        fetch('/os/api/vayuos/mail/recovery/decide', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfTok() },
          body: JSON.stringify({ id: id, action: approve ? 'approve' : 'decline' })
        }).then(function (r) { return r.json(); }).then(function (d) {
          row.parentNode.removeChild(row);
          if (!approve || !out) { return; }
          // The link is returned once and never stored in readable form, so it gets
          // the same loud treatment as the codes.
          out.textContent = '';
          var p = document.createElement('p');
          p.className = 'rec-codes__warn';
          p.textContent = d.warning ? d.warning
            : 'One-time reset link for ' + (d.email || mb) + ' — shown once. ' +
              'Hand it over in person or on a call you placed yourself.';
          out.appendChild(p);
          if (d.link) {
            var code = document.createElement('code');
            code.className = 'rec-codes__code';
            code.style.display = 'block';
            code.style.textAlign = 'left';
            code.textContent = d.link;
            out.appendChild(code);
          }
          out.hidden = false;
        }).catch(function () { /* the row stays; the operator can retry */ });
      }
      if (approve) {
        vpConfirm({ title: 'Approve recovery', message: 'Approve recovery for ' + mb + '? Only do this if you have confirmed, on a channel you trust, that you are talking to the real holder.', confirm: 'Approve' }, decide);
      } else {
        decide();
      }
    });
  }

  function start() {
    bindAll();
    bindQueue();
    // The accounts list is an HTMX fragment: every inline action swaps the whole
    // list, replacing all the panels with fresh, unbound copies. Without this the
    // recovery controls work until the first alias or forwarding change and then
    // quietly stop.
    document.body.addEventListener('htmx:afterSwap', bindAll);
  }

  // Wait for the document. This script tag is emitted by the summary card at the
  // TOP of the page, above the mailbox list, so at execution time none of the
  // per-card panels exist yet — binding immediately found nothing and every
  // control stayed dead. (document.body is not guaranteed either, which is the
  // second half of the same bug.)
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
