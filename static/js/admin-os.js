/* VayuPress VayuOS — Bootstrap
 * Sovereign · Self-hosted · Zero-CDN · Strict-CSP
 * No eval, no new Function, no innerHTML with untrusted data.
 * All DOM mutation via textContent / createElement / appendChild.
 */
'use strict';
(function () {

/* ── Helpers ─────────────────────────────────────────────────── */
const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
const on = (el, ev, fn) => el && el.addEventListener(ev, fn);

/* ── Theme ───────────────────────────────────────────────────── */
(function initTheme() {
  // The theme attribute lives on the .vp-os element itself (<body>), so the
  // .vp-os[data-theme] token overrides win over the base .vp-os tokens. Go
  // renders data-theme + data-admin-theme on <body>; default to auto (follows
  // the OS). The toggle cycles light → dark → auto and persists to settings.
  const el = document.body;
  if (!el.dataset.theme) { el.dataset.theme = el.dataset.adminTheme || 'auto'; }

  const btn = $('.topbar-theme-btn');
  if (!btn) return;
  btn.title = 'Theme: ' + el.dataset.theme;
  btn.addEventListener('click', function () {
    const themes = ['light', 'dark', 'auto'];
    const cur = themes.indexOf(el.dataset.theme);
    const next = themes[(cur + 1) % themes.length];
    el.dataset.theme = next;
    btn.title = 'Theme: ' + next;
    // Persist via API (fire-and-forget)
    const csrf = cookie('vp_csrf');
    fetch('/os/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ key: 'admin.theme', value: next }),
    }).catch(function () {});
  });
})();

/* ── Cookies ─────────────────────────────────────────────────── */
function cookie(name) {
  // Take everything after the first '=' so base64 values keep any '=' padding.
  var row = document.cookie.split('; ').find(function (r) { return r.startsWith(name + '='); });
  return row ? row.slice(name.length + 1) : '';
}

/* ── Shared JSON POST (Wave 3.11) ──────────────────────────────
   window.vpPost: one CSRF-carrying JSON POST helper for the console. The
   per-page inline scripts have their own (ops-block) variant that reloads on
   success; this one takes callbacks and never reloads, so island-style
   handlers can update in place. Every error path toasts — a silent catch is a
   lie by omission. */
window.vpPost = function (url, body, onok, onerr) {
  fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': cookie('vp_csrf') },
    body: JSON.stringify(body || {}),
  })
    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
    .then(function (res) {
      if (res.ok) { if (onok) onok(res.d); return; }
      var msg = (res.d && (res.d.detail || res.d.title || res.d.error || res.d.message)) || 'Request failed';
      if (onerr) onerr(res.d, msg); else toast(msg, 'error');
    })
    .catch(function (e) {
      if (onerr) onerr(null, String(e)); else toast('Network error', 'error');
    });
};

/* ── Toast system ────────────────────────────────────────────── */
function toast(msg, kind) {
  kind = kind || 'info';
  var container = $('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  var el = document.createElement('div');
  el.className = 'toast toast--' + kind;

  var icon = document.createElement('span');
  icon.textContent = kind === 'ok' ? '✓' : kind === 'error' ? '✕' : kind === 'warn' ? '⚠' : 'ℹ';
  icon.setAttribute('aria-hidden', 'true');

  var text = document.createElement('span');
  text.textContent = msg;

  el.appendChild(icon);
  el.appendChild(text);
  container.appendChild(el);

  setTimeout(function () {
    el.classList.add('leaving');
    setTimeout(function () { el.remove(); }, 200);
  }, 3800);
  return el; // callers may attach a click handler (e.g. the new-mail notifier)
}
window.vpToast = toast;

/* ── Sidebar drawer (mobile) ─────────────────────────────────
   Single source of truth for the slide-in nav. Binds every toggle (the topbar
   hamburger AND the bottom-bar "Menu" button — anything matching .menu-toggle
   or [data-action="toggle-sidebar"]). The drawer closes on overlay tap, on Esc,
   when a nav link is followed, and when the viewport grows back to desktop.
   Keeping all toggles here avoids the previous double-handling (a second
   document-level handler that cancelled the open). */
(function initSidebar() {
  var sidebar = $('.sidebar');
  if (!sidebar) return;
  var overlay = $('.sidebar-overlay');
  var toggles = $$('.menu-toggle, [data-action="toggle-sidebar"]');
  var body = document.body;
  var desktop = window.matchMedia('(min-width: 769px)');
  var KEY = 'vp_nav_collapsed';

  function setExpanded(v) {
    toggles.forEach(function (b) { b.setAttribute('aria-expanded', v ? 'true' : 'false'); });
  }
  function store(v) { try { localStorage.setItem(KEY, v ? '1' : '0'); } catch (e) {} }
  function stored() { try { return localStorage.getItem(KEY) === '1'; } catch (e) { return false; } }

  // ── Mobile: slide-in drawer (locks scroll while open) ──────────────────────
  function openDrawer() {
    sidebar.classList.add('open');
    if (overlay) overlay.classList.add('open');
    body.style.overflow = 'hidden';
    setExpanded(true);
  }
  function closeDrawer() {
    sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('open');
    body.style.overflow = '';
    setExpanded(false);
  }

  // ── Desktop: collapse the sidebar (persisted; never locks scroll) ──────────
  function setCollapsed(v) {
    body.classList.toggle('nav-collapsed', v);
    setExpanded(!v);
    store(v);
  }

  function toggle() {
    if (desktop.matches) {
      setCollapsed(!body.classList.contains('nav-collapsed'));
    } else {
      sidebar.classList.contains('open') ? closeDrawer() : openDrawer();
    }
  }

  // Restore the persisted desktop collapse state on load (desktop only).
  if (desktop.matches && stored()) { body.classList.add('nav-collapsed'); }
  setExpanded(!(desktop.matches && body.classList.contains('nav-collapsed')));

  toggles.forEach(function (b) {
    on(b, 'click', function (e) { e.preventDefault(); toggle(); });
  });
  if (overlay) on(overlay, 'click', closeDrawer);
  // On mobile, following a nav link closes the drawer; on desktop the sidebar
  // stays as-is (collapsed or not) so navigation doesn't fight the toggle.
  $$('.sidebar .nav-link').forEach(function (a) { on(a, 'click', function () { if (!desktop.matches) closeDrawer(); }); });
  on(document, 'keydown', function (e) { if (e.key === 'Escape' && !desktop.matches) closeDrawer(); });

  // Crossing the breakpoint: entering desktop closes any open mobile drawer and
  // applies the persisted collapse; entering mobile drops the desktop collapse
  // class (the drawer owns visibility there) and unlocks scroll.
  var onChange = function (e) {
    if (e.matches) {
      closeDrawer();
      body.classList.toggle('nav-collapsed', stored());
    } else {
      body.classList.remove('nav-collapsed');
      body.style.overflow = '';
    }
  };
  if (desktop.addEventListener) desktop.addEventListener('change', onChange);
  else if (desktop.addListener) desktop.addListener(onChange);
})();

/* ── Bottom bar: active state + role-aware quick links ───────
   The drawer is already role-scoped server-side; mirror that on the bottom bar
   by hiding any quick link whose destination isn't present in the sidebar for
   this session. Then highlight the item matching the current route. The "Menu"
   button (no data-nav) is always kept. */
(function initBottomNav() {
  var nav = $('.bottom-nav');
  if (!nav) return;
  var items = $$('.bottom-nav-item[data-nav]', nav);
  if (!items.length) return;

  var sideHrefs = $$('.sidebar .nav-link').map(function (a) { return a.getAttribute('href'); });
  // Only filter when we actually have a sidebar to compare against.
  if (sideHrefs.length) {
    items.forEach(function (it) {
      var href = it.getAttribute('data-nav');
      if (href && sideHrefs.indexOf(href) === -1) it.hidden = true;
    });
  }

  var path = location.pathname;
  var best = null, bestLen = -1;
  items.forEach(function (it) {
    if (it.hidden) return;
    var href = it.getAttribute('data-nav');
    if (!href) return;
    var match = path === href || (href !== '/os' && path.indexOf(href) === 0);
    if (match && href.length > bestLen) { best = it; bestLen = href.length; }
  });
  if (best) best.setAttribute('aria-current', 'page');
})();

/* ── Responsive data tables → cards ──────────────────────────
   Generic, zero-config: for every .table-wrap > table.table, copy each column
   header into its body cells as data-label and flag the wrapper .vp-stackable.
   CSS then folds the table into labelled cards on phones. Skips tables that opt
   out (data-no-stack), have fewer than two columns, or lead with a selection
   checkbox (management grids that read better as a horizontal scroll).

   Runs on first load AND after every HTMX swap, scoped to the swapped subtree —
   so tables delivered by HTMX (analytics, VayuShield sections, the mailbox
   list) get the same phone-friendly card layout as server-rendered ones,
   instead of a wide horizontal scroll. Idempotent: cells already labelled and
   wrappers already flagged are skipped, so repeated swaps never re-walk work. */
  function stackTablesIn(root) {
    var scope = (root && root.querySelectorAll) ? root : document;
    var tables = scope.querySelectorAll('.table-wrap > table.table');
    // A swap target may itself BE the table's wrapper; include that case.
    Array.prototype.forEach.call(tables, function (table) {
      var wrap = table.parentElement;
      if (wrap.classList.contains('vp-stackable')) return;
      if (wrap.hasAttribute('data-no-stack') || table.hasAttribute('data-no-stack')) return;

      var heads = $$('thead th', table);
      if (heads.length < 2) return;
      if (heads[0].querySelector('input')) return; // select-all column → keep scroll

      var labels = heads.map(function (th) { return th.textContent.trim(); });
      $$('tbody tr', table).forEach(function (tr) {
        var cells = tr.children;
        if (cells.length !== labels.length) return; // colspan / empty-state rows
        for (var i = 0; i < cells.length; i++) {
          if (!cells[i].hasAttribute('data-label')) cells[i].setAttribute('data-label', labels[i]);
        }
      });
      wrap.classList.add('vp-stackable');
    });
  }
  stackTablesIn(document);
  document.body.addEventListener('htmx:afterSwap', function (e) {
    stackTablesIn(e.target || document);
  });

/* ── Client-side action registry (Wave 1: palette actions moved off
     window[fn] string lookup into a small explicit map). */
window.vpActions = {
  newPost: function () { location.href = '/os/editor'; },
  goSEO: function () { location.href = '/os/seo'; },
  regenSEO: function () {
    fetch('/os/api/seo/regenerate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      body: JSON.stringify({})
    }).then(function (r) {
      if (!r.ok) throw new Error('SEO regen failed (' + r.status + ')');
      return r.json();
    }).then(function () {
      if (window.vpToast) window.vpToast('Sitemap, RSS & robots regenerated', 'ok');
    }).catch(function (err) {
      if (window.vpToast) window.vpToast('Could not regenerate: ' + err.message, 'danger');
    });
  }
};

/* ── Command palette (Cmd+K / Ctrl+K) ───────────────────────── */
(function initCommandPalette() {
  var backdrop = $('#cmd-backdrop');
  var input = $('#cmd-input');
  var results = $('#cmd-results');
  if (!backdrop || !input || !results) return;

  var index = null; // Loaded lazily
  var activeIdx = -1;
  var items = [];

  function open() {
    backdrop.removeAttribute('hidden');
    input.value = '';
    input.focus();
    loadIndex();
    render('');
  }
  function close() {
    backdrop.setAttribute('hidden', '');
    activeIdx = -1;
  }

  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      backdrop.hasAttribute('hidden') ? open() : close();
    }
    if (!backdrop.hasAttribute('hidden')) {
      if (e.key === 'Escape') close();
      if (e.key === 'ArrowDown') { e.preventDefault(); moveActive(1); }
      if (e.key === 'ArrowUp')   { e.preventDefault(); moveActive(-1); }
      if (e.key === 'Enter')     { e.preventDefault(); activateCurrent(); }
    }
  });
  backdrop.addEventListener('click', function (e) {
    if (e.target === backdrop) close();
  });

  var cmdBtn = $('.topbar-cmd');
  if (cmdBtn) cmdBtn.addEventListener('click', open);

  input.addEventListener('input', function () { render(input.value); });

  function loadIndex() {
    if (index !== null) return;
    var cached = null;
    try { cached = JSON.parse(sessionStorage.getItem('vp3_cmd_index_v1')); } catch (e) {}
    if (cached) { index = cached; return; }
    fetch('/os/api/cmd-index')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        index = data;
        try { sessionStorage.setItem('vp3_cmd_index_v1', JSON.stringify(data)); } catch (e) {}
        render(input.value);
      })
      .catch(function () { index = { posts: [], actions: [], settings: [] }; });
  }

  function render(q) {
    q = q.toLowerCase().trim();
    results.innerHTML = '';
    items = [];
    activeIdx = -1;

    if (!index) {
      var loading = document.createElement('div');
      loading.className = 'cmd-group-label';
      loading.textContent = 'Loading…';
      results.appendChild(loading);
      return;
    }

    var sections = [
      { label: 'Posts', key: 'posts', icon: '✍', href: function(i){ return '/os/editor/' + i.slug; } },
      { label: 'Quick Actions', key: 'actions', icon: '⚡', fn: function(i){ return i.fn; } },
      { label: 'Settings', key: 'settings', icon: '⚙', href: function(i){ return i.href; } },
    ];

    sections.forEach(function (sec) {
      var list = (index[sec.key] || []).filter(function (item) {
        return !q || item.label.toLowerCase().includes(q) || (item.slug && item.slug.includes(q));
      }).slice(0, 6);
      if (!list.length) return;

      var label = document.createElement('div');
      label.className = 'cmd-group-label';
      label.textContent = sec.label;
      results.appendChild(label);

      list.forEach(function (item) {
        var el = sec.href
          ? document.createElement('a')
          : document.createElement('button');
        el.className = 'cmd-item';
        if (sec.href) el.href = sec.href(item);

        var icon = document.createElement('div');
        icon.className = 'cmd-item__icon';
        icon.textContent = item.icon || sec.icon;

        var lbl = document.createElement('div');
        lbl.className = 'cmd-item__label';
        lbl.textContent = item.label || item.title || '';

        el.appendChild(icon);
        el.appendChild(lbl);

        if (item.hint) {
          var hint = document.createElement('div');
          hint.className = 'cmd-item__hint';
          hint.textContent = item.hint;
          el.appendChild(hint);
        }

        if (!sec.href && item.fn) {
          el.addEventListener('click', function () {
            close();
            var fn = window.vpActions && window.vpActions[item.fn];
            if (typeof fn === 'function') { fn(); return; }
            if (item.href) location.href = item.href;
          });
        } else {
          el.addEventListener('click', close);
        }

        results.appendChild(el);
        items.push(el);
      });
    });

    if (!items.length && q) {
      var empty = document.createElement('div');
      empty.className = 'cmd-group-label';
      empty.textContent = 'No results for "' + q + '"';
      results.appendChild(empty);
    }
  }

  function moveActive(dir) {
    if (!items.length) return;
    var cur = $('.cmd-item--active', results);
    if (cur) cur.classList.remove('cmd-item--active');
    activeIdx = (activeIdx + dir + items.length) % items.length;
    items[activeIdx].classList.add('cmd-item--active');
    items[activeIdx].scrollIntoView({ block: 'nearest' });
  }

  function activateCurrent() {
    if (activeIdx >= 0 && items[activeIdx]) items[activeIdx].click();
  }
})();

/* ── Posts search (client-side) ────────────────────────────────
   Removed (Wave 3.11): the HTMX server-side search replaced this, and its
   input hooks no longer exist in the Go templates — a handler for a selector
   nothing renders is dead weight that pretends a feature exists. The
   selector-parity test pins this. */

/* ── Quick compose ───────────────────────────────────────────── */
(function initQuickCompose() {
  var input = $('#quick-compose-input');
  if (!input) return;
  input.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter') return;
    var title = input.value.trim();
    if (!title) return;
    input.disabled = true;
    var csrf = cookie('vp_csrf');
    fetch('/os/api/posts/quick-create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ title: title }),
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.slug) {
        window.location.href = '/os/editor/' + data.slug;
      } else {
        toast(data.error || 'Could not create post', 'error');
        input.disabled = false;
      }
    })
    .catch(function () { toast('Network error', 'error'); input.disabled = false; });
  });
})();

/* ── Data-action dispatcher ──────────────────────────────────
   Generic click router for [data-action] buttons. Note: 'toggle-sidebar' is
   intentionally NOT handled here — initSidebar binds those elements directly so
   the drawer open/close (with overlay + scroll-lock) has a single owner. */
document.addEventListener('click', function (e) {
  var el = e.target.closest('[data-action]');
  if (!el) return;
  var action = el.dataset.action;
  var actions = {
    // (room for future generic actions)
  };
  if (actions[action]) { e.preventDefault(); actions[action](el); }
});

/* ── Relative time ───────────────────────────────────────────── */
function relativeTime(iso) {
  var d = new Date(iso);
  var diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60)  return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
  return d.toLocaleDateString();
}
window.vpRelTime = relativeTime;

/* ── Activity feed ───────────────────────────────────────────── */
(function initActivityFeed() {
  var feed = $('#activity-feed');
  if (!feed) return;
(function initActivityFeed() {
  var feed = $('#activity-feed');
  if (!feed) return;
  var feedTimer = null;

  function renderError() {
    feed.innerHTML = '';
    var err = document.createElement('div');
    err.className = 'table-empty';
    err.textContent = 'Activity feed is unavailable right now — it will retry shortly.';
    feed.appendChild(err);
  }

  function loadFeed() {
    fetch('/os/api/activity')
      .then(function (r) { if (!r.ok) throw new Error('feed ' + r.status); return r.json(); })
      .then(function (data) {
        feed.innerHTML = '';
        if (!data || !data.length) {
          var empty = document.createElement('div');
          empty.className = 'table-empty';
          empty.textContent = 'No recent activity.';
          feed.appendChild(empty);
          return;
        }
        data.forEach(function (item) {
          // Every row that knows where the work happens is a link to it —
          // a feed you cannot act on is a log, not a feed.
          var row = document.createElement(item.href ? 'a' : 'div');
          row.className = 'activity-item';
          if (item.href) row.href = item.href;

          var icon = document.createElement('div');
          icon.className = 'activity-icon activity-icon--' + (item.kind || 'system');
          icon.textContent = item.icon || '·';
          icon.setAttribute('aria-hidden', 'true');

          var body = document.createElement('div');
          body.className = 'activity-body';

          var text = document.createElement('div');
          text.className = 'activity-text';
          text.textContent = item.text || '';

          var time = document.createElement('div');
          time.className = 'activity-time';
          time.textContent = item.time ? relativeTime(item.time) : '';

          body.appendChild(text);
          body.appendChild(time);
          row.appendChild(icon);
          row.appendChild(body);
          feed.appendChild(row);
        });
      })
      .catch(renderError);
  }

  loadFeed();
  // Relative timestamps go stale in place ("just now" for an hour); re-render
  // every minute so the words always match the clock.
  feedTimer = setInterval(loadFeed, 60000);
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible' && feedTimer) {
      loadFeed();
    }
  });
})();

/* ── Settings toggle rows ────────────────────────────────────── */
$$('[data-setting-key]').forEach(function (el) {
  el.addEventListener('change', function () {
    var key = el.dataset.settingKey;
    var val = el.type === 'checkbox' ? (el.checked ? 'true' : 'false') : el.value;
    vpPost('/os/api/settings', { key: key, value: val }, function () { toast('Saved', 'ok'); }, function () { toast('Error saving setting', 'error'); });
  });
});

/* ── Media library (Phase 4) ─────────────────────────────────── */
(function initMedia() {
  var grid = $('[data-media-grid]');
  if (!grid) return;
  var dropzone = $('[data-media-dropzone]');
  var input = $('[data-media-input]');

  function relTime(unix) {
    var s = Math.floor(Date.now() / 1000) - unix;
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  function fmtSize(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(0) + ' KB';
    return (b / 1048576).toFixed(1) + ' MB';
  }

  function card(item) {
    var el = document.createElement('figure');
    el.className = 'media-card';

    var thumb = document.createElement('div');
    thumb.className = 'media-card__thumb';

    // Selection checkbox for bulk delete.
    var sel = document.createElement('input');
    sel.type = 'checkbox';
    sel.className = 'media-card__select';
    sel.setAttribute('data-media-select', '');
    sel.value = item.name;
    sel.setAttribute('aria-label', 'Select ' + item.name);
    sel.addEventListener('change', updateSelCount);
    thumb.appendChild(sel);

    if (item.isPdf) {
      var badge = document.createElement('span');
      badge.className = 'media-card__pdf';
      badge.textContent = 'PDF';
      thumb.appendChild(badge);
    } else {
      var img = document.createElement('img');
      img.loading = 'lazy';
      img.src = item.url;
      img.alt = item.alt || item.name;
      thumb.appendChild(img);
    }
    el.appendChild(thumb);

    var meta = document.createElement('figcaption');
    meta.className = 'media-card__meta';
    var size = document.createElement('span');
    size.textContent = fmtSize(item.size) + ' · ' + relTime(item.mod);
    meta.appendChild(size);

    // Alt-text editor (images only) — saves on blur.
    if (!item.isPdf) {
      var altI = document.createElement('input');
      altI.type = 'text';
      altI.className = 'media-card__alt';
      altI.placeholder = 'Alt text…';
      altI.value = item.alt || '';
      altI.maxLength = 300;
      altI.setAttribute('aria-label', 'Alt text for ' + item.name);
      altI.addEventListener('blur', function () {
        if (altI.value === (item.alt || '')) return;
        item.alt = altI.value;
        vpPost('/os/api/media/alt', { name: item.name, alt: altI.value }, function () { toast('Alt text saved', 'ok'); }, function () { toast('Could not save alt', 'error'); });
      });
      meta.appendChild(altI);
    }

    var copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'media-card__copy';
    copy.textContent = 'Copy URL';
    copy.addEventListener('click', function () {
      var full = window.location.origin + item.url;
      if (navigator.clipboard) {
        navigator.clipboard.writeText(full).then(function () { toast('URL copied', 'ok'); });
      } else {
        toast(full, 'ok');
      }
    });
    meta.appendChild(copy);
    el.appendChild(meta);
    return el;
  }

  var allItems = [];
  var search = $('[data-media-search]');
  var emptyMsg = $('[data-media-empty]');
  var typeFilter = 'all';

  function applyFilter() {
    while (grid.firstChild) grid.removeChild(grid.firstChild);
    if (!allItems.length) {
      var empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No media yet. Upload your first image or PDF.';
      grid.appendChild(empty);
      if (emptyMsg) emptyMsg.hidden = true;
      return;
    }
    var q = (search && search.value || '').trim().toLowerCase();
    var shown = allItems.filter(function (it) {
      if (typeFilter === 'image' && it.isPdf) return false;
      if (typeFilter === 'pdf' && !it.isPdf) return false;
      if (q && (it.name || '').toLowerCase().indexOf(q) === -1) return false;
      return true;
    });
    shown.forEach(function (it) { grid.appendChild(card(it)); });
    if (emptyMsg) emptyMsg.hidden = shown.length > 0;
    updateSelCount();
  }

  function load() {
    fetch('/os/api/media', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        allItems = (data && data.items) || [];
        applyFilter();
      })
      .catch(function () { toast('Could not load media', 'error'); });
  }

  if (search) search.addEventListener('input', applyFilter);
  document.querySelectorAll('[data-media-filter]').forEach(function (b) {
    b.addEventListener('click', function () {
      document.querySelectorAll('[data-media-filter]').forEach(function (x) { x.classList.remove('is-active'); });
      b.classList.add('is-active');
      typeFilter = b.getAttribute('data-media-filter');
      applyFilter();
    });
  });

  // ── Bulk delete ───────────────────────────────────────────────────────────
  var delBtn = $('[data-media-delete-selected]');
  var selCount = $('[data-media-sel-count]');
  function selectedNames() {
    return Array.prototype.slice.call(grid.querySelectorAll('[data-media-select]:checked')).map(function (c) { return c.value; });
  }
  function updateSelCount() {
    var n = selectedNames().length;
    if (selCount) selCount.textContent = String(n);
    if (delBtn) delBtn.disabled = n === 0;
  }
  if (delBtn) delBtn.addEventListener('click', function () {
    var names = selectedNames();
    if (!names.length) return;
    vpConfirm({
      title: 'Delete files',
      message: 'Delete ' + names.length + ' file' + (names.length > 1 ? 's' : '') + '? This cannot be undone.',
      confirm: 'Delete',
    }, function () {
      delBtn.disabled = true;
      fetch('/os/api/media/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': cookie('vp_csrf') },
        body: JSON.stringify({ names: names }),
      }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          if (res.ok) { toast('Deleted ' + (res.j.deleted || 0), 'ok'); load(); }
          else { delBtn.disabled = false; toast('Delete failed', 'error'); }
        }).catch(function () { delBtn.disabled = false; toast('Network error', 'error'); });
    });
  });

  function upload(file) {
    if (!file) return;
    var fd = new FormData();
    fd.append('file', file);
    toast('Uploading…', 'ok');
    fetch('/os/api/media/upload', {
      method: 'POST',
      headers: { 'X-CSRF-Token': cookie('vp_csrf') },
      body: fd
    })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        if (!res.ok) { toast(typeof res.j.error === 'string' ? res.j.error : (res.j.message || res.j.detail || 'Upload failed'), 'error'); return; }
        toast('Uploaded', 'ok');
        load();
      })
      .catch(function () { toast('Network error', 'error'); });
  }

  if (dropzone) {
    dropzone.addEventListener('click', function () { if (input) input.click(); });
    dropzone.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); if (input) input.click(); }
    });
    dropzone.addEventListener('dragover', function (e) { e.preventDefault(); dropzone.classList.add('media-dropzone--over'); });
    dropzone.addEventListener('dragleave', function () { dropzone.classList.remove('media-dropzone--over'); });
    dropzone.addEventListener('drop', function (e) {
      e.preventDefault();
      dropzone.classList.remove('media-dropzone--over');
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) upload(e.dataTransfer.files[0]);
    });
  }
  if (input) input.addEventListener('change', function () { if (input.files.length) upload(input.files[0]); });

  load();
})();

/* ── Notification centre ─────────────────────────────────────── */
/* The topbar bell opens an expandable panel of actionable notifications
 * (rendered server-side as plain links, so clicking a row navigates straight
 * to the page that clears it). This only toggles visibility — no fetch, no
 * innerHTML — keeping the strict CSP intact. */
(function initNotifications() {
  var wrap = $('[data-notif]');
  if (!wrap) return;
  var btn = $('[data-notif-toggle]', wrap);
  var panel = $('[data-notif-panel]', wrap);
  if (!btn || !panel) return;
  function open() {
    panel.hidden = false;
    wrap.classList.add('is-open');
    btn.setAttribute('aria-expanded', 'true');
  }
  function close() {
    panel.hidden = true;
    wrap.classList.remove('is-open');
    btn.setAttribute('aria-expanded', 'false');
  }
  on(btn, 'click', function (e) {
    e.preventDefault();
    e.stopPropagation();
    panel.hidden ? open() : close();
  });
  // Dismiss on outside click or Escape.
  on(document, 'click', function (e) { if (!wrap.contains(e.target)) close(); });
  on(document, 'keydown', function (e) { if (e.key === 'Escape') close(); });
})();

/* ── Login page shake on error ───────────────────────────────── */
(function initLogin() {
  var panel = $('.login-panel');
  if (!panel) return;
  // The error div is rendered server-side; its presence triggers a shake.
  if ($('.login-error', panel)) {
    panel.classList.add('shake');
    panel.addEventListener('animationend', function () { panel.classList.remove('shake'); }, { once: true });
  }
})();

/* ── Installable app (PWA) ───────────────────────────────────────
   Register the console's /os-scoped service worker (privacy-first: never caches
   authenticated pages) and turn the topbar install button into a one-tap "Install
   VayuOS". Handles Chrome/Edge/Android via beforeinstallprompt, and gives iOS —
   which never fires it — an "Add to Home Screen" hint. Hidden once installed. */
(function initPWA() {
  if ('serviceWorker' in navigator) {
    // When a new worker takes control (e.g. after a deploy), reload once so the
    // freshest VayuOS shows immediately — no stale build ever lingers on a device.
    var swReloaded = false;
    navigator.serviceWorker.addEventListener('controllerchange', function () {
      if (swReloaded) return;
      swReloaded = true;
      window.location.reload();
    });
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('/os/sw.js', { scope: '/os/' }).then(function (reg) {
        if (reg && reg.update) { try { reg.update(); } catch (e) { /* no-op */ } }
      }).catch(function () {});
    });
  }
  var btn = document.querySelector('[data-pwa-install]');
  if (!btn) return;
  var standalone = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) ||
    window.navigator.standalone === true;
  if (standalone) return; // already installed — nothing to offer

  var isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
  var deferred = null;

  window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault();
    deferred = e;
    btn.hidden = false;
  });
  window.addEventListener('appinstalled', function () {
    deferred = null;
    btn.hidden = true;
    if (window.vpToast) window.vpToast('VayuOS installed — find it on your home screen.', 'success');
  });
  on(btn, 'click', function () {
    if (deferred) {
      deferred.prompt();
      deferred.userChoice.then(function () { deferred = null; btn.hidden = true; });
      return;
    }
    if (window.vpToast) {
      window.vpToast(isIOS
        ? 'To install: tap the Share button, then “Add to Home Screen”.'
        : 'To install: open your browser menu and choose “Install app” / “Add to Home screen”.',
        'info');
    }
  });
  // iOS never fires beforeinstallprompt — reveal the button so iPhone/iPad users
  // still get the install hint.
  if (isIOS) { btn.hidden = false; }
})();

/* ── New-mail notifications ──────────────────────────────────────────────────
   Polls /os/vayumail/unseen on every console page and raises a desktop
   notification the moment any mailbox's unseen count rises — so a new mail in
   ANY mailbox reaches you even when you're on another VayuOS page. Clicking the
   notification opens that mailbox directly. The baseline lives only here (no
   server state); the first poll just records counts and never notifies (so
   already-unread mail is not announced on load). Desktop notifications need a
   secure context (HTTPS); on the http .onion (Tor) the API is unavailable, so it
   degrades to a clickable toast + a title badge. Endpoint auth already scopes
   what you see (admin = all mailboxes; staff = only their own), so this just
   renders whatever it is allowed to return. */
(function initMailNotify() {
  if (!document.querySelector('.vp-os')) return;        // console pages only
  if (document.querySelector('.auth-page')) return;     // not the sign-in shell
  var ENDPOINT = '/os/vayumail/unseen';
  var POLL_MS = 60000;
  var baseline = null;                 // address -> unseen; null until first poll
  var notifyReady = false;
  var baseTitle = document.title;
  var titleCount = 0;

  function secureCtx() { return window.isSecureContext !== false; }
  function ensurePerm() {
    if (!('Notification' in window) || !secureCtx()) return;
    if (Notification.permission === 'granted') { notifyReady = true; return; }
    if (Notification.permission === 'default') {
      try {
        Notification.requestPermission().then(function (p) { notifyReady = (p === 'granted'); });
      } catch (e) { /* Safari <16 uses a callback form; ignore */ }
    }
  }
  function deepLink(key) { return '/os/vayumail/inbox?user=' + encodeURIComponent(key); }
  function goTo(box) { try { window.focus(); } catch (e) { /* no-op */ } window.location.href = deepLink(box.key); }

  function announce(box, delta) {
    var msg = (delta > 1 ? delta + ' new messages' : 'New message') + ' in ' + box.address;
    if (notifyReady && ('Notification' in window)) {
      var opts = { body: msg, tag: 'vmail:' + box.address, renotify: true, data: { url: deepLink(box.key) } };
      // Prefer the service worker's showNotification: it is the ONLY path that
      // works in an installed PWA and on Android/mobile browsers (where the
      // `new Notification()` constructor is unsupported), and its click is
      // handled by the worker (see sw.js `notificationclick`) so the mailbox
      // opens even if this tab is gone. Fall back to the page Notification
      // constructor on desktop browsers without an active worker.
      if (navigator.serviceWorker && navigator.serviceWorker.ready) {
        navigator.serviceWorker.ready
          .then(function (reg) { return reg.showNotification('VayuMail — new mail', opts); })
          .catch(function () { pageNotify(box, opts); });
        return;
      }
      if (pageNotify(box, opts)) return;
    }
    if (typeof window.vpToast === 'function') {
      // Clickable toast: an operator on an .onion (no secure context) or with
      // notifications denied still gets the alert and a one-click way in.
      var t = window.vpToast(msg + ' — open', 'info');
      if (t && t.addEventListener) { t.style.cursor = 'pointer'; on(t, 'click', function () { goTo(box); }); }
    }
  }
  function pageNotify(box, opts) {
    try {
      var n = new Notification('VayuMail — new mail', opts);
      n.onclick = function () { goTo(box); n.close(); };
      return true;
    } catch (e) { return false; }
  }
  function bumpTitle(n) {
    titleCount += n;
    document.title = titleCount > 0 ? '(' + titleCount + ') ' + baseTitle : baseTitle;
  }
  function clearTitle() { titleCount = 0; document.title = baseTitle; }
  window.addEventListener('focus', clearTitle);
  // Live-bump the topbar notification bell so new mail shows there in real time
  // (the bell is otherwise only recomputed on a full page render). It reflects the
  // combined count of all notification types, so we add the new-mail delta.
  function bumpBell(delta) {
    var wrap = document.querySelector('[data-notif]');
    if (!wrap) return;
    var btn = wrap.querySelector('[data-notif-toggle]');
    if (!btn) return;
    var badge = wrap.querySelector('.topbar-notif__badge');
    var cur = badge ? (parseInt((badge.textContent || '').replace(/\D/g, ''), 10) || 0) : 0;
    var label = (cur + delta) > 99 ? '99+' : String(cur + delta);
    if (!badge) { badge = document.createElement('span'); badge.className = 'topbar-notif__badge'; btn.appendChild(badge); }
    badge.textContent = label;
    btn.classList.add('topbar-notif__btn--active');
    var head = wrap.querySelector('.topbar-notif__count');
    if (head) head.textContent = label + ' new';
  }

  function poll() {
    fetch(ENDPOINT, { headers: { 'Accept': 'application/json' } })
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(function (list) {
        if (!Array.isArray(list)) return;
        var seen = Object.create(null);
        list.forEach(function (b) { seen[b.address] = true; });
        if (baseline === null) {                 // first poll: record, never notify
          baseline = Object.create(null);
          list.forEach(function (b) { baseline[b.address] = b.unseen; });
          ensurePerm();
          return;
        }
        var totalNew = 0;
        list.forEach(function (b) {
          var prev = baseline[b.address] || 0;
          if (b.unseen > prev) { var delta = b.unseen - prev; totalNew += delta; announce(b, delta); }
          baseline[b.address] = b.unseen;
        });
        Object.keys(baseline).forEach(function (addr) { if (!seen[addr]) delete baseline[addr]; });
        if (totalNew > 0) { bumpTitle(totalNew); bumpBell(totalNew); }
      })
      .catch(function () { /* offline / transient — try again next tick */ });
  }
  // First poll a few seconds after load (so a fresh sign-in isn't spammed), then
  // on a steady interval. Background tabs are throttled by the browser, which is
  // fine — the notification is exactly what a backgrounded operator wants.
  setTimeout(poll, 4000);
  setInterval(poll, POLL_MS);
})();

})(); // end IIFE

/* ── Keyboard layer (Wave 3.7) ────────────────────────────────
   j/k move through the post rows, x toggles the highlighted row's bulk select,
   Enter opens the highlighted row, n starts a new post (or focuses quick
   compose on the dashboard). Only fires when a post list exists; never fires
   while typing, inside a form field, or with a modifier held. */
(function initKeyboardLayer() {
  var rows = function () { return $$('.post-row [data-post-row], [data-post-row]').filter(function (r) { return !r.hidden; }); };
  var idx = -1;
  function highlight(next) {
    var list = rows();
    if (!list.length) return;
    if (idx >= 0 && list[idx]) list[idx].classList.remove('post-row--kbd');
    idx = (next + list.length) % list.length;
    var row = list[idx];
    row.classList.add('post-row--kbd');
    var sum = row.querySelector('summary');
    if (sum) sum.scrollIntoView({ block: 'nearest' });
  }
  function isTyping(el) {
    if (!el) return false;
    var tag = (el.tagName || '').toLowerCase();
    return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable;
  }
  document.addEventListener('keydown', function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (isTyping(e.target)) return;
    var list = rows();
    var hasList = list.length > 0;
    var composer = $('#quick-compose-input');
    if (e.key === 'n') {
      // n = "new post": focus quick compose where it exists, otherwise open the editor.
      if (composer) { e.preventDefault(); composer.focus(); }
      else { window.location.href = '/os/editor'; }
      return;
    }
    if (!hasList) return;
    switch (e.key) {
      case 'j': e.preventDefault(); highlight(idx + 1); break;
      case 'k': e.preventDefault(); highlight(idx - 1); break;
      case 'x':
        if (idx < 0 || !list[idx]) return;
        e.preventDefault();
        var chk = list[idx].querySelector('[data-post-select]');
        if (chk) { chk.checked = !chk.checked; chk.dispatchEvent(new Event('change', { bubbles: true })); }
        break;
      case 'Enter':
        if (idx < 0 || !list[idx]) return;
        e.preventDefault();
        var sum = list[idx].querySelector('summary');
        if (sum) sum.click();
        break;
    }
  });
})();
})();
