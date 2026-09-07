/*
 * admin-os-editor.js — VayuPress VayuOS block editor (ADR-0068; v1.14.0 upgrade).
 *
 * Vanilla JS, strict CSP: no eval, no new Function, no innerHTML with untrusted
 * data. The DOM is built with createElement/textContent. The canonical document
 * is an array of typed blocks; it is serialised to JSON and POSTed to the server,
 * which renders + sanitises it (internal/blockrender) — the client never trusts
 * rendered HTML except the server's own sanitised preview, injected only through
 * the DOMPurify-guarded renderSanitized() sink below.
 *
 * v1.14.0 adds: table / toggle / task-list / math / audio blocks, drag-and-drop
 * + keyboard block reordering, an undo/redo stack, live word/character count and
 * reading time, a distraction-free focus mode, a split-screen live preview, a
 * global Cmd/Ctrl+K command menu, and a categorised, keyboard-navigable slash
 * palette. Element.style mutations from JS are CSP-safe (the policy governs HTML
 * style attributes / <style>, not scripted style writes).
 */
(function () {
  'use strict';

  var root = document.querySelector('[data-editor]');
  if (!root) return;

  var slug = root.getAttribute('data-slug') || '';
  var canvas = root.querySelector('[data-editor-canvas]');
  var titleEl = root.querySelector('[data-editor-title]');
  var statusEl = root.querySelector('[data-editor-status]');
  var topbarStatusEl = root.querySelector('[data-editor-topbar-status]');
  var saveBtn = root.querySelector('[data-editor-save]');
  var previewBtn = root.querySelector('[data-editor-preview-btn]');
  var previewModal = root.querySelector('[data-editor-preview]');
  var previewBody = root.querySelector('[data-editor-preview-body]');
  var previewClose = root.querySelector('[data-editor-preview-close]');
  var historyBtn = root.querySelector('[data-editor-history-btn]');
  var historyModal = root.querySelector('[data-editor-history]');
  var historyList = root.querySelector('[data-editor-history-list]');
  var historyDiff = root.querySelector('[data-editor-history-diff]');
  var historyClose = root.querySelector('[data-editor-history-close]');
  // v1.14.0 chrome (optional — guarded everywhere so older shells still work).
  var focusBtn = root.querySelector('[data-editor-focus-btn]');
  var splitBtn = root.querySelector('[data-editor-split-btn]');
  var htmlBtn = root.querySelector('[data-editor-html-btn]');
  var htmlPanel = root.querySelector('[data-editor-html-panel]');
  var htmlArea = root.querySelector('[data-editor-html-area]');
  var wordCountEl = root.querySelector('[data-editor-wordcount]');
  var liveEl = root.querySelector('[data-editor-live]');
  var liveBody = root.querySelector('[data-editor-live-body]');
  var statsWordsEl = root.querySelector('[data-editor-stats-words]');
  var statsCharsEl = root.querySelector('[data-editor-stats-chars]');
  var statsReadEl = root.querySelector('[data-editor-stats-read]');
  var undoBtn = root.querySelector('[data-editor-undo]');
  var redoBtn = root.querySelector('[data-editor-redo]');

  // Block type registry. `cat` groups blocks in the slash palette. Each defines
  // how to create its editing UI and how to serialise back to the document model.
  var BLOCK_TYPES = [
    { type: 'paragraph', label: 'Text', icon: '¶', hint: 'Plain paragraph', cat: 'Basic' },
    { type: 'heading', label: 'Heading', icon: 'H', hint: 'Section heading', cat: 'Basic' },
    { type: 'list', label: 'Bullet list', icon: '•', hint: 'Unordered list', cat: 'Basic' },
    { type: 'ordered', label: 'Numbered list', icon: '1.', hint: 'Ordered list', cat: 'Basic' },
    { type: 'tasklist', label: 'Task list', icon: '☑', hint: 'Checklist with done states', cat: 'Basic' },
    { type: 'quote', label: 'Quote', icon: '"', hint: 'Block quote', cat: 'Basic' },
    { type: 'divider', label: 'Divider', icon: '―', hint: 'Horizontal rule', cat: 'Basic' },
    { type: 'image', label: 'Image', icon: '🖼', hint: 'Upload, drag & drop, or paste any image link (Unsplash, Pixabay, …)', cat: 'Media' },
    { type: 'gallery', label: 'Gallery', icon: '▦', hint: 'Responsive image gallery (up to 9)', cat: 'Media' },
    { type: 'audio', label: 'Audio', icon: '♪', hint: 'Self-hosted audio player', cat: 'Media' },
    { type: 'embed', label: 'Embed / Link card', icon: '🔗', hint: 'Unfurl a URL (privacy-first)', cat: 'Embeds' },
    { type: 'diagram', label: 'Diagram', icon: '🔀', hint: 'Mermaid flowchart / sequence → SVG', cat: 'Embeds' },
    { type: 'markdown', label: 'Markdown', icon: 'M↓', hint: 'Write a block in Markdown', cat: 'Advanced' },
    { type: 'html', label: 'HTML', icon: '<>', hint: 'Custom HTML (sanitised on save)', cat: 'Advanced' },
    { type: 'code', label: 'Code', icon: '</>', hint: 'Code block with language hint', cat: 'Advanced' },
    { type: 'callout', label: 'Callout', icon: '!', hint: 'Highlighted note', cat: 'Advanced' },
    { type: 'table', label: 'Table', icon: '⊞', hint: 'Rows & columns', cat: 'Advanced' },
    { type: 'toggle', label: 'Toggle', icon: '▸', hint: 'Collapsible details', cat: 'Advanced' },
    { type: 'math', label: 'Math', icon: '∑', hint: 'LaTeX / math expression', cat: 'Advanced' }
  ];
  var CATEGORIES = ['Basic', 'Media', 'Embeds', 'Advanced'];

  // AI-assist commands shown at the bottom of the slash palette (when AI is available).
  var AI_CMDS = [
    { op: 'continue', label: 'AI: Continue writing', icon: '✦', hint: 'Continue the current paragraph' },
    { op: 'summarize', label: 'AI: Summarize', icon: '✦', hint: 'Condense the current block to a short summary' },
    { op: 'rewrite', label: 'AI: Rewrite', icon: '✦', hint: 'Rephrase the current block for clarity' }
  ];
  var aiEnabled = false; // updated from /os/api/editor/ai status check on load

  // ── Document model ─────────────────────────────────────────────────────────
  var blocks = [];
  var dragSrcIdx = -1;
  var grabbedIdx = -1; // block currently "lifted" in keyboard reorder mode

  // announce pushes a message to a polite ARIA live region so screen readers
  // narrate keyboard reordering ("Block lifted", "Moved to position 3 of 7").
  // The region is created once and reused; visually hidden.
  var _liveRegion = null;
  function announce(msg) {
    if (!_liveRegion) {
      _liveRegion = document.createElement('div');
      _liveRegion.setAttribute('aria-live', 'polite');
      _liveRegion.setAttribute('aria-atomic', 'true');
      _liveRegion.className = 'eblock__sr-live';
      document.body.appendChild(_liveRegion);
    }
    // Toggle the text so identical consecutive messages are still announced.
    _liveRegion.textContent = '';
    setTimeout(function () { _liveRegion.textContent = msg; }, 30);
  }

  // refocusGrabHandle re-focuses the drag handle of the block at idx after a
  // re-render and keeps it in keyboard grab-mode, so arrow keys move a block
  // continuously without re-grabbing between steps.
  function refocusGrabHandle(idx) {
    var host = document.querySelector('[data-block-idx="' + idx + '"] .eblock__drag');
    if (host) host.focus();
  }

  function hydrate() {
    var dataEl = document.getElementById('vp-editor-data');
    var raw = dataEl ? dataEl.textContent.trim() : '';
    if (raw) {
      try {
        var parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length) {
          blocks = parsed;
        }
      } catch (e) { /* start fresh */ }
    }
    if (!blocks.length) {
      blocks = [{ type: 'paragraph', text: '' }];
    }
  }

  // ── Status ──────────────────────────────────────────────────────────────────
  function setStatus(msg, kind) {
    if (statusEl) {
      statusEl.textContent = msg;
      statusEl.className = 'editor-status' + (kind ? ' editor-status--' + kind : '');
    }
    if (topbarStatusEl) {
      topbarStatusEl.textContent = msg;
      topbarStatusEl.className = 'editor-topbar-status' + (kind ? ' editor-topbar-status--' + kind : '');
    }
  }

  // ── Block-text extraction (stats, diff, AI source) ──────────────────────────
  function blockText(b) {
    if (!b) return '';
    switch (b.type) {
      case 'list':
      case 'ordered':
      case 'tasklist':
        return (b.items || []).join(' ');
      case 'table':
        return (b.header || []).join(' ') + ' ' +
          (b.rows || []).map(function (r) { return (r || []).join(' '); }).join(' ');
      case 'toggle':
        return (b.summary || '') + ' ' + (b.text || '');
      case 'gallery':
        return b.caption || '';
      default:
        return b.text || '';
    }
  }
  function collectAllText() {
    return blocks.map(blockText).join('\n');
  }

  // ── Live stats: word / character count + reading time ───────────────────────
  function countWords(s) {
    var t = (s || '').trim();
    if (!t) return 0;
    return t.split(/\s+/).length;
  }
  function updateStats() {
    var text = collectAllText();
    var words = countWords(text);
    var chars = text.replace(/\s+/g, ' ').trim().length;
    var mins = words ? Math.max(1, Math.round(words / 200)) : 0;
    if (wordCountEl) wordCountEl.textContent = words + (words === 1 ? ' word' : ' words');
    if (statsWordsEl) statsWordsEl.textContent = String(words);
    if (statsCharsEl) statsCharsEl.textContent = String(chars);
    if (statsReadEl) statsReadEl.textContent = mins ? (mins + ' min read') : '—';
    renderOutline();
  }

  // ── Live document outline ───────────────────────────────────────────────────
  // The sidebar outline mirrors the document's heading structure as you write:
  // every heading block becomes a click-to-jump entry, indented by level. It is
  // rebuilt from the block model (never from the DOM) behind a cheap string
  // signature, so the per-keystroke cost when nothing outline-relevant changed
  // is one small string build and compare — no DOM work.
  var outlineWrap = document.querySelector('[data-editor-outline-wrap]');
  var outlineList = document.querySelector('[data-editor-outline]');
  var outlineSig = null;
  function renderOutline() {
    if (!outlineWrap || !outlineList) return;
    var heads = [];
    for (var i = 0; i < blocks.length; i++) {
      var b = blocks[i];
      if (b && b.type === 'heading') {
        heads.push({ idx: i, level: Math.min(4, Math.max(2, parseInt(b.level, 10) || 2)), text: (b.text || '').trim() });
      }
    }
    var sig = heads.map(function (h) { return h.idx + ':' + h.level + ':' + h.text; }).join('');
    if (sig === outlineSig) return;
    outlineSig = sig;
    outlineList.textContent = '';
    if (!heads.length) { outlineWrap.hidden = true; return; }
    outlineWrap.hidden = false;
    heads.forEach(function (h) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'editor-outline__item editor-outline__item--l' + h.level;
      btn.textContent = h.text || 'Untitled heading';
      btn.setAttribute('data-outline-idx', String(h.idx));
      btn.title = 'Jump to “' + (h.text || 'Untitled heading') + '”';
      outlineList.appendChild(btn);
    });
    markOutlineActive(lastFocusedBlockIdx);
  }

  // Click-to-jump: focus the heading's field and bring it to the center of the
  // viewport (instant when the user prefers reduced motion).
  if (outlineList) {
    outlineList.addEventListener('click', function (e) {
      var btn = e.target && e.target.closest ? e.target.closest('[data-outline-idx]') : null;
      if (!btn) return;
      var idx = parseInt(btn.getAttribute('data-outline-idx'), 10);
      if (isNaN(idx) || idx < 0 || idx >= blocks.length) return;
      focusBlock(idx, false);
      var el = canvas.querySelector('[data-block-idx="' + idx + '"]');
      if (el) {
        var smooth = !(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
        el.scrollIntoView({ block: 'center', behavior: smooth ? 'smooth' : 'auto' });
      }
    });
  }

  // Active-section tracking: highlight the outline entry for the heading that
  // governs the block the caret is in (the nearest heading at or above it).
  var lastFocusedBlockIdx = -1;
  function markOutlineActive(blockIdx) {
    if (!outlineList) return;
    var items = outlineList.children;
    var activeIdx = -1;
    for (var i = 0; i < items.length; i++) {
      var hIdx = parseInt(items[i].getAttribute('data-outline-idx'), 10);
      if (hIdx <= blockIdx) activeIdx = i;
      items[i].classList.remove('is-active');
    }
    if (activeIdx >= 0) items[activeIdx].classList.add('is-active');
  }
  if (canvas) {
    canvas.addEventListener('focusin', function (e) {
      var host = e.target && e.target.closest ? e.target.closest('[data-block-idx]') : null;
      if (!host) return;
      var idx = parseInt(host.getAttribute('data-block-idx'), 10);
      if (isNaN(idx)) return;
      lastFocusedBlockIdx = idx;
      markOutlineActive(idx);
    });
  }

  // ── Undo / redo (block-level checkpoints) ───────────────────────────────────
  // History holds JSON snapshots of the block document. Structural mutations
  // checkpoint immediately; text edits checkpoint on a short debounce. Native
  // per-field text undo is preserved because Cmd/Ctrl+Z is only intercepted when
  // focus is NOT inside an editable field.
  var hist = [], histPos = -1, histTimer = null;
  function serialize() { return JSON.stringify(blocks); }
  function commitNow() {
    if (histTimer) { clearTimeout(histTimer); histTimer = null; }
    var s = serialize();
    if (histPos >= 0 && hist[histPos] === s) return;
    hist = hist.slice(0, histPos + 1);
    hist.push(s);
    if (hist.length > 120) hist.shift();
    histPos = hist.length - 1;
    refreshUndoButtons();
  }
  function scheduleCommit() {
    if (histTimer) clearTimeout(histTimer);
    histTimer = setTimeout(commitNow, 600);
  }
  function restore(state) {
    try { blocks = JSON.parse(state); } catch (e) { return; }
    if (!Array.isArray(blocks) || !blocks.length) blocks = [{ type: 'paragraph', text: '' }];
    renderCanvas();
    updateStats();
    scheduleLivePreview();
    scheduleAutosave();
  }
  function undo() {
    if (histTimer) commitNow();
    if (histPos > 0) { histPos--; restore(hist[histPos]); setStatus('Undo', 'ok'); refreshUndoButtons(); }
  }
  function redo() {
    if (histPos < hist.length - 1) { histPos++; restore(hist[histPos]); setStatus('Redo', 'ok'); refreshUndoButtons(); }
  }
  function refreshUndoButtons() {
    if (undoBtn) undoBtn.disabled = histPos <= 0;
    if (redoBtn) redoBtn.disabled = histPos >= hist.length - 1;
  }

  // touch() is called after any text-field edit; structural() after any block
  // add / remove / move / type change.
  function touch() { updateStats(); scheduleAutosave(); scheduleCommit(); scheduleLivePreview(); }
  function structural() { renderCanvas(); commitNow(); updateStats(); scheduleAutosave(); scheduleLivePreview(); }

  // ── Rendering the editing surface (all DOM built safely) ───────────────────
  function clearDropMarkers() {
    var els = canvas.querySelectorAll('.is-drop-before, .is-drop-after, .is-dragging');
    Array.prototype.forEach.call(els, function (el) {
      el.classList.remove('is-drop-before', 'is-drop-after', 'is-dragging');
    });
  }

  function makeBlockEl(block, idx) {
    var wrap = document.createElement('div');
    wrap.className = 'eblock eblock--' + (block.type || 'paragraph');
    wrap.setAttribute('data-block-idx', String(idx));

    // Control rail (drag handle, move up/down, insert, delete).
    var ctrl = document.createElement('div');
    ctrl.className = 'eblock__ctrl';

    var drag = document.createElement('button');
    drag.type = 'button';
    drag.className = 'eblock__btn eblock__drag';
    drag.textContent = '⋮⋮';
    drag.title = 'Drag to reorder';
    drag.setAttribute('draggable', 'true');
    drag.setAttribute('aria-label', 'Drag to reorder block');
    drag.addEventListener('dragstart', function (e) {
      dragSrcIdx = idx;
      if (e.dataTransfer) {
        e.dataTransfer.effectAllowed = 'move';
        try { e.dataTransfer.setData('text/plain', String(idx)); } catch (err) {}
        try { e.dataTransfer.setDragImage(wrap, 12, 12); } catch (err) {}
      }
      wrap.classList.add('is-dragging');
    });
    drag.addEventListener('dragend', function () { dragSrcIdx = -1; clearDropMarkers(); });
    // Keyboard grab-mode: the drag handle is also fully operable without a
    // mouse. Space/Enter "lifts" the block (aria-grabbed); ArrowUp/ArrowDown
    // then move it a step at a time with a live announcement; Space/Enter or
    // Escape drops it; blur cancels. This closes the accessibility gap where
    // reordering was mouse-only (the ↑/↓ buttons still work independently).
    drag.setAttribute('aria-roledescription', 'Draggable block handle');
    if (grabbedIdx === idx) { drag.setAttribute('aria-grabbed', 'true'); wrap.classList.add('is-grabbed'); }
    drag.addEventListener('keydown', function (e) {
      if (e.key === ' ' || e.key === 'Enter') {
        e.preventDefault();
        var lift = grabbedIdx !== idx;
        grabbedIdx = lift ? idx : -1;
        drag.setAttribute('aria-grabbed', lift ? 'true' : 'false');
        wrap.classList.toggle('is-grabbed', lift);
        announce(lift ? 'Block lifted. Arrow up or down to move, space to drop.' : 'Block dropped at position ' + (idx + 1) + '.');
        return;
      }
      if (grabbedIdx !== idx) return; // arrows only act while this block is lifted
      if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
        e.preventDefault();
        var dir = e.key === 'ArrowUp' ? -1 : 1;
        if (idx + dir < 0 || idx + dir >= blocks.length) return;
        grabbedIdx = idx + dir; // survives the re-render below
        nudge(idx, dir);        // structural() → renderCanvas() rebuilds the rail
        // The DOM was rebuilt; refocus the moved block's handle so the next
        // arrow press continues the move without re-grabbing.
        setTimeout(function () { refocusGrabHandle(grabbedIdx); }, 0);
        announce('Moved to position ' + (grabbedIdx + 1) + ' of ' + blocks.length + '.');
      } else if (e.key === 'Escape') {
        e.preventDefault();
        grabbedIdx = -1;
        wrap.classList.remove('is-grabbed');
        drag.setAttribute('aria-grabbed', 'false');
        announce('Move cancelled.');
      }
    });
    drag.addEventListener('blur', function () {
      if (grabbedIdx === idx) { grabbedIdx = -1; wrap.classList.remove('is-grabbed'); drag.setAttribute('aria-grabbed', 'false'); }
    });

    var up = mkCtrlBtn('↑', 'Move up', function () { nudge(idx, -1); });
    var down = mkCtrlBtn('↓', 'Move down', function () { nudge(idx, 1); });
    var addBtn = mkCtrlBtn('+', 'Insert block below', function () { openPalette(idx + 1, idx); });
    var dupBtn = mkCtrlBtn('⧉', 'Duplicate block', function () { duplicateBlock(idx); });
    var delBtn = mkCtrlBtn('×', 'Delete block', function () { removeBlock(idx); });

    ctrl.appendChild(drag);
    ctrl.appendChild(up);
    ctrl.appendChild(down);
    ctrl.appendChild(addBtn);
    ctrl.appendChild(dupBtn);
    ctrl.appendChild(delBtn);
    wrap.appendChild(ctrl);

    // Drop-target behaviour for reordering.
    wrap.addEventListener('dragover', function (e) {
      if (dragSrcIdx < 0) return;
      e.preventDefault();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
      var rect = wrap.getBoundingClientRect();
      var after = (e.clientY - rect.top) > rect.height / 2;
      wrap.classList.toggle('is-drop-after', after);
      wrap.classList.toggle('is-drop-before', !after);
    });
    wrap.addEventListener('dragleave', function () {
      wrap.classList.remove('is-drop-before', 'is-drop-after');
    });
    wrap.addEventListener('drop', function (e) {
      if (dragSrcIdx < 0) return;
      e.preventDefault();
      e.stopPropagation();
      var rect = wrap.getBoundingClientRect();
      var after = (e.clientY - rect.top) > rect.height / 2;
      moveBlock(dragSrcIdx, after ? idx + 1 : idx);
      clearDropMarkers();
    });

    wrap.appendChild(buildField(block, idx));
    return wrap;
  }

  function mkCtrlBtn(label, title, onClick) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'eblock__btn';
    b.textContent = label;
    b.title = title;
    b.addEventListener('click', onClick);
    return b;
  }

  // buildField returns the per-type editable control.
  function buildField(block, idx) {
    var field = document.createElement('div');
    field.className = 'eblock__field';

    switch (block.type) {
      case 'divider': {
        var hr = document.createElement('hr');
        hr.className = 'eblock__divider';
        field.appendChild(hr);
        break;
      }
      case 'image': {
        var url = mkInput('text', block.url || '', 'Paste any image link (Unsplash, Pixabay, /media/…) or upload');
        url.addEventListener('input', function () { block.url = url.value; touch(); fillAltFromLibrary(url.value, alt, block); });
        var uprow = document.createElement('div');
        uprow.className = 'eblock__row';
        var upBtn = mkSmallBtn('⬆ Upload', function () { upFile.click(); });
        var upFile = document.createElement('input');
        upFile.type = 'file';
        upFile.accept = 'image/*';
        upFile.style.display = 'none';
        upFile.addEventListener('change', function () {
          if (upFile.files && upFile.files[0]) {
            uploadInto(upFile.files[0], function (u) { block.url = u; url.value = u; touch(); fillAltFromLibrary(u, alt, block); });
          }
          upFile.value = '';
        });
        uprow.appendChild(url);
        uprow.appendChild(upBtn);
        uprow.appendChild(upFile);
        var alt = mkInput('text', block.alt || '', 'Alt text (described for accessibility)');
        alt.addEventListener('input', function () { block.alt = alt.value; touch(); });
        // If the block already points at a library image with no alt, default it.
        fillAltFromLibrary(block.url || '', alt, block);
        var cap = mkInput('text', block.caption || '', 'Caption (optional)');
        cap.addEventListener('input', function () { block.caption = cap.value; touch(); });
        var width = document.createElement('select');
        width.className = 'eblock__level';
        [['', 'Regular width'], ['wide', 'Wide'], ['full', 'Full width']].forEach(function (o) {
          var opt = document.createElement('option');
          opt.value = o[0];
          opt.textContent = o[1];
          if ((block.width || '') === o[0]) opt.selected = true;
          width.appendChild(opt);
        });
        width.addEventListener('change', function () { block.width = width.value; touch(); });
        field.appendChild(uprow);
        field.appendChild(alt);
        field.appendChild(cap);
        field.appendChild(width);
        break;
      }
      case 'gallery': {
        field.appendChild(buildGalleryField(block, idx));
        break;
      }
      case 'html': {
        var htmlSrc = mkTextarea(block.text || '', '<div>Custom HTML…</div>');
        htmlSrc.className += ' eblock__code';
        htmlSrc.addEventListener('input', function () { block.text = htmlSrc.value; autoGrow(htmlSrc); touch(); });
        field.appendChild(htmlSrc);
        field.appendChild(mkHint('Custom HTML is sanitised on save (scripts, forms, and inline handlers are removed). Use it for rich markup like styled blocks or buttons-as-links.'));
        setTimeout(function () { autoGrow(htmlSrc); }, 0);
        break;
      }
      case 'markdown': {
        var mdSrc = mkTextarea(block.text || '', '## Write in Markdown\\n\\n- lists, **bold**, [links](url), tables…');
        mdSrc.className += ' eblock__code';
        mdSrc.addEventListener('input', function () { block.text = mdSrc.value; autoGrow(mdSrc); touch(); });
        field.appendChild(mdSrc);
        setTimeout(function () { autoGrow(mdSrc); }, 0);
        break;
      }
      case 'audio': {
        var au = mkInput('text', block.url || '', 'Local audio URL, e.g. /media/episode.mp3');
        au.addEventListener('input', function () { block.url = au.value; touch(); });
        var cap = mkInput('text', block.alt || '', 'Caption (optional)');
        cap.addEventListener('input', function () { block.alt = cap.value; touch(); });
        field.appendChild(au);
        field.appendChild(cap);
        field.appendChild(mkHint('Audio must be a local /media file (upload via the Media library). External URLs are ignored for privacy.'));
        break;
      }
      case 'embed': {
        var embedUrl = mkInput('text', block.url || '', 'Paste a URL to unfurl…');
        var embedStatus = document.createElement('span');
        embedStatus.className = 'eblock__embed-status';
        if (block.title) embedStatus.textContent = block.title;
        embedUrl.addEventListener('change', function () {
          var val = embedUrl.value.trim();
          block.url = val;
          if (!val) return;
          embedStatus.textContent = 'Fetching…';
          fetch('/os/api/embed/unfurl', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ url: val })
          }).then(function (r) { return r.json(); }).then(function (data) {
            if (data.error) { embedStatus.textContent = 'Error: ' + data.error; return; }
            block.url = data.url || val;
            block.title = data.title || '';
            block.description = data.description || '';
            block.provider = data.provider || '';
            block.thumbURL = data.thumbURL || '';
            block.kind = data.kind || 'link';
            block.embedSrc = data.embedSrc || '';
            var verb = block.kind === 'video' ? '▶ Video: ' : '';
            embedStatus.textContent = verb + (block.title || block.url);
            touch();
          }).catch(function () { embedStatus.textContent = 'Could not fetch URL'; });
        });
        field.appendChild(embedUrl);
        field.appendChild(embedStatus);
        break;
      }
      case 'list':
      case 'ordered': {
        var ta = mkTextarea((block.items || []).join('\n'), 'One item per line');
        ta.addEventListener('input', function () {
          block.items = ta.value.split('\n').filter(function (s) { return s.trim() !== ''; });
          autoGrow(ta);
          touch();
        });
        field.appendChild(ta);
        setTimeout(function () { autoGrow(ta); }, 0);
        break;
      }
      case 'tasklist': {
        field.appendChild(buildTaskList(block, idx));
        break;
      }
      case 'table': {
        field.appendChild(buildTableField(block, idx));
        break;
      }
      case 'toggle': {
        var summary = mkInput('text', block.summary || '', 'Toggle title…');
        summary.className += ' eblock__heading';
        summary.addEventListener('input', function () { block.summary = summary.value; touch(); });
        var body = mkTextarea(block.text || '', 'Hidden content…');
        body.addEventListener('input', function () { block.text = body.value; autoGrow(body); touch(); });
        var openLine = document.createElement('label');
        openLine.className = 'eblock__checkline';
        var openCb = document.createElement('input');
        openCb.type = 'checkbox';
        openCb.checked = !!block.open;
        openCb.addEventListener('change', function () { block.open = openCb.checked; touch(); });
        var openTxt = document.createElement('span');
        openTxt.textContent = 'Expanded by default';
        openLine.appendChild(openCb);
        openLine.appendChild(openTxt);
        field.appendChild(summary);
        field.appendChild(body);
        field.appendChild(openLine);
        setTimeout(function () { autoGrow(body); }, 0);
        break;
      }
      case 'math': {
        var mt = mkTextarea(block.text || '', 'LaTeX or math expression, e.g. E = mc^2');
        mt.className += ' eblock__code';
        mt.addEventListener('input', function () { block.text = mt.value; autoGrow(mt); touch(); });
        field.appendChild(mt);
        field.appendChild(mkHint('Stored verbatim and rendered in a styled block (privacy-first, no external renderer).'));
        setTimeout(function () { autoGrow(mt); }, 0);
        break;
      }
      case 'code': {
        var lang = mkInput('text', block.lang || '', 'Language (e.g. go, js)');
        lang.className += ' eblock__lang';
        lang.addEventListener('input', function () { block.lang = lang.value; touch(); });
        var code = mkTextarea(block.text || '', 'Code…');
        code.className += ' eblock__code';
        code.addEventListener('input', function () { block.text = code.value; autoGrow(code); touch(); });
        field.appendChild(lang);
        field.appendChild(code);
        setTimeout(function () { autoGrow(code); }, 0);
        break;
      }
      case 'diagram': {
        var dsrc = mkTextarea(block.text || '', 'flowchart TD\n  A[Start] --> B[End]');
        dsrc.className += ' eblock__code';
        var dprev = document.createElement('div');
        dprev.className = 'eblock__diagram-preview';
        var dtimer;
        var renderDiag = function () {
          var v = dsrc.value.trim();
          if (!v) { while (dprev.firstChild) dprev.removeChild(dprev.firstChild); return; }
          fetch('/os/api/diagram/preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ source: v })
          }).then(function (r) { return r.json(); }).then(function (d) {
            if (d.svg) { renderSanitized(dprev, d.svg); dprev.classList.remove('is-error'); }
            else { dprev.textContent = d.error || 'Could not render diagram'; dprev.classList.add('is-error'); }
          }).catch(function () { dprev.textContent = 'Preview failed'; dprev.classList.add('is-error'); });
        };
        dsrc.addEventListener('input', function () {
          block.text = dsrc.value;
          autoGrow(dsrc);
          touch();
          clearTimeout(dtimer);
          dtimer = setTimeout(renderDiag, 400);
        });
        field.appendChild(dsrc);
        field.appendChild(dprev);
        setTimeout(function () { autoGrow(dsrc); }, 0);
        if (block.text) { setTimeout(renderDiag, 0); }
        break;
      }
      case 'heading': {
        var lvlSel = document.createElement('select');
        lvlSel.className = 'eblock__level';
        [2, 3, 4].forEach(function (n) {
          var opt = document.createElement('option');
          opt.value = String(n);
          opt.textContent = 'H' + n;
          if ((block.level || 2) === n) opt.selected = true;
          lvlSel.appendChild(opt);
        });
        lvlSel.addEventListener('change', function () { block.level = parseInt(lvlSel.value, 10); touch(); });
        var ht = mkInput('text', block.text || '', 'Heading…');
        ht.className += ' eblock__heading';
        ht.addEventListener('input', function () { block.text = ht.value; touch(); });
        ht.addEventListener('keydown', onTextKey(idx));
        field.appendChild(lvlSel);
        field.appendChild(ht);
        break;
      }
      default: {
        // paragraph, quote, callout — single text area.
        var t = mkTextarea(block.text || '', placeholderFor(block.type));
        t.addEventListener('input', function () {
          block.text = t.value;
          autoGrow(t);
          if (block.type === 'paragraph' && tryParagraphShortcut(idx, t)) return;
          touch();
        });
        t.addEventListener('keydown', onTextKey(idx));
        if (block.type === 'paragraph') {
          t.addEventListener('paste', function (e) {
            // Pasting a lone URL onto an empty paragraph turns it into a
            // bookmark / embed card and unfurls it (matches the "paste any URL"
            // flow). Anything else pastes normally.
            if (t.value.trim() !== '') return;
            var clip = (e.clipboardData && e.clipboardData.getData('text/plain')) || '';
            clip = clip.trim();
            if (isLoneURL(clip)) {
              e.preventDefault();
              convertBlock(idx, { type: 'embed', url: clip, title: '', description: '', provider: '', thumbURL: '' });
              setTimeout(function () { unfurlEmbedAt(idx, clip); }, 0);
              return;
            }
            // Rich paste (Wave 4.3): when the clipboard carries text/html — a
            // copy from a web page, a doc, another editor — structure survives.
            // The HTML is sanitised with DOMPurify to the block vocabulary
            // (p/headings/lists/quote/code + inline marks) BEFORE parsing, so
            // nothing untrusted ever enters the document tree, then converted
            // to the same blocks the Markdown path produces.
            var clipHTML = (e.clipboardData && e.clipboardData.getData('text/html')) || '';
            if (clipHTML) {
              var hparsed = parseHTMLBlocks(clipHTML);
              if (hparsed.length) {
                e.preventDefault();
                blocks = blocks.slice(0, idx).concat(hparsed, blocks.slice(idx + 1));
                structural();
                var hlast = idx + hparsed.length - 1;
                setTimeout(function () { focusBlock(hlast, true); }, 0);
                return;
              }
            }
            // Multi-line paste onto an empty paragraph: parse the Markdown into
            // real blocks (headings, lists, quotes, code, dividers, paragraphs)
            // instead of dumping everything into one textarea. Single-line
            // pastes and pastes into non-empty paragraphs behave exactly as
            // before — this only upgrades the "paste a whole draft in" flow.
            if (clip.indexOf('\n') !== -1) {
              var parsed = parseMarkdownBlocks(clip);
              if (parsed.length) {
                e.preventDefault();
                blocks = blocks.slice(0, idx).concat(parsed, blocks.slice(idx + 1));
                structural();
                var last = idx + parsed.length - 1;
                setTimeout(function () { focusBlock(last, true); }, 0);
              }
            }
          });
        }
        field.appendChild(t);
        if (block.type === 'callout') {
          var tone = mkInput('text', block.style || 'info', 'Tone (info, warn, success)');
          tone.className += ' eblock__tone';
          tone.addEventListener('input', function () { block.style = tone.value; touch(); });
          field.appendChild(tone);
        }
        setTimeout(function () { autoGrow(t); }, 0);
      }
    }
    return field;
  }

  // ── Task-list editor ────────────────────────────────────────────────────────
  function buildTaskList(block, idx) {
    block.items = block.items || [];
    block.checked = block.checked || [];
    if (!block.items.length) { block.items = ['']; block.checked = [false]; }
    var wrap = document.createElement('div');
    wrap.className = 'eblock__tasks';
    block.items.forEach(function (it, i) {
      var row = document.createElement('div');
      row.className = 'eblock__task' + (block.checked[i] ? ' is-done' : '');
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'eblock__task-check';
      cb.checked = !!block.checked[i];
      cb.addEventListener('change', function () {
        block.checked[i] = cb.checked;
        row.classList.toggle('is-done', cb.checked);
        touch();
      });
      var ti = mkInput('text', it, 'To-do…');
      ti.className += ' eblock__task-text';
      ti.addEventListener('input', function () { block.items[i] = ti.value; touch(); });
      ti.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          block.items.splice(i + 1, 0, '');
          block.checked.splice(i + 1, 0, false);
          structural();
          setTimeout(function () { focusTaskItem(idx, i + 1); }, 0);
        } else if (e.key === 'Backspace' && ti.value === '' && block.items.length > 1) {
          e.preventDefault();
          block.items.splice(i, 1);
          block.checked.splice(i, 1);
          structural();
          setTimeout(function () { focusTaskItem(idx, Math.max(0, i - 1)); }, 0);
        }
      });
      row.appendChild(cb);
      row.appendChild(ti);
      wrap.appendChild(row);
    });
    var add = document.createElement('button');
    add.type = 'button';
    add.className = 'eblock__addrow';
    add.textContent = '+ Add item';
    add.addEventListener('click', function () {
      block.items.push('');
      block.checked.push(false);
      structural();
      setTimeout(function () { focusTaskItem(idx, block.items.length - 1); }, 0);
    });
    wrap.appendChild(add);
    return wrap;
  }

  function focusTaskItem(idx, i) {
    var wrap = canvas.querySelector('[data-block-idx="' + idx + '"]');
    if (!wrap) return;
    var items = wrap.querySelectorAll('.eblock__task-text');
    if (items[i]) {
      items[i].focus();
      try { var n = items[i].value.length; items[i].setSelectionRange(n, n); } catch (e) {}
    }
  }

  // ── Table editor ──────────────────────────────────────────────────────────
  function buildTableField(block, idx) {
    block.header = block.header || [];
    block.rows = block.rows || [];
    if (!block.header.length && !block.rows.length) {
      block.header = ['Column 1', 'Column 2'];
      block.rows = [['', ''], ['', '']];
    }
    var wrap = document.createElement('div');
    wrap.className = 'eblock__table';
    var table = document.createElement('table');
    table.className = 'eblock__table-grid';

    if (block.header.length) {
      var thead = document.createElement('thead');
      var htr = document.createElement('tr');
      block.header.forEach(function (h, c) {
        var th = document.createElement('th');
        var inp = mkInput('text', h, 'Header');
        inp.addEventListener('input', function () { block.header[c] = inp.value; touch(); });
        th.appendChild(inp);
        htr.appendChild(th);
      });
      htr.appendChild(document.createElement('th')); // spacer for row controls
      thead.appendChild(htr);
      table.appendChild(thead);
    }

    var tbody = document.createElement('tbody');
    block.rows.forEach(function (row, r) {
      var tr = document.createElement('tr');
      row.forEach(function (cell, c) {
        var td = document.createElement('td');
        var inp = mkInput('text', cell, 'Cell');
        inp.addEventListener('input', function () { block.rows[r][c] = inp.value; touch(); });
        td.appendChild(inp);
        tr.appendChild(td);
      });
      var ctlTd = document.createElement('td');
      ctlTd.className = 'eblock__table-rowctl';
      var del = mkCtrlBtn('×', 'Delete row', function () { block.rows.splice(r, 1); structural(); });
      ctlTd.appendChild(del);
      tr.appendChild(ctlTd);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);

    var ctl = document.createElement('div');
    ctl.className = 'eblock__table-ctl';
    var addRow = mkSmallBtn('+ Row', function () {
      var cols = block.header.length || (block.rows[0] ? block.rows[0].length : 2);
      var nr = [];
      for (var i = 0; i < cols; i++) nr.push('');
      block.rows.push(nr);
      structural();
    });
    var addCol = mkSmallBtn('+ Column', function () {
      if (!block.header.length) {
        var cols = block.rows[0] ? block.rows[0].length : 0;
        for (var i = 0; i < cols; i++) block.header.push('Column ' + (i + 1));
      }
      block.header.push('Column ' + (block.header.length + 1));
      block.rows.forEach(function (rw) { rw.push(''); });
      structural();
    });
    ctl.appendChild(addRow);
    ctl.appendChild(addCol);
    wrap.appendChild(ctl);
    return wrap;
  }

  function mkSmallBtn(label, onClick) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn--ghost btn--xs';
    b.textContent = label;
    b.addEventListener('click', onClick);
    return b;
  }

  // uploadInto uploads a file to the media library and calls cb(url) on success.
  // Shared by the image card's Upload button and the gallery editor.
  function uploadInto(file, cb) {
    var fd = new FormData();
    fd.append('file', file);
    setStatus('Uploading image…');
    fetch('/os/api/media/upload', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken() }, body: fd })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) {
        if (d && d.url) { cb(d.url); setStatus('Image uploaded', 'ok'); }
        else setStatus('Upload failed', 'danger');
      }).catch(function () { setStatus('Image upload failed', 'danger'); });
  }

  // ── Media alt-text defaults ─────────────────────────────────────────────────
  // The Media library stores alt text per asset. When an image block points at a
  // /media/<name> file and its alt is still blank, default it to the library's
  // saved alt. The library listing is fetched once and cached.
  var mediaAltMap = null;
  function withMediaAlts(cb) {
    if (mediaAltMap) { cb(mediaAltMap); return; }
    fetch('/os/api/media', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : { items: [] }; })
      .then(function (d) {
        mediaAltMap = {};
        ((d && d.items) || []).forEach(function (it) { if (it.alt) mediaAltMap[it.name] = it.alt; });
        cb(mediaAltMap);
      })
      .catch(function () { mediaAltMap = {}; cb(mediaAltMap); });
  }
  function mediaNameFromURL(u) {
    var m = /\/media\/([a-f0-9]{32}\.(?:png|jpg|gif|webp|pdf))(?:[?#]|$)/.exec(u || '');
    return m ? m[1] : '';
  }
  // fillAltFromLibrary defaults a blank alt input from the saved library alt for
  // the block's media URL. No-op if the alt already has a value.
  function fillAltFromLibrary(urlStr, altInput, block) {
    if (!altInput || altInput.value.trim()) return;
    var name = mediaNameFromURL(urlStr);
    if (!name) return;
    withMediaAlts(function (map) {
      if (altInput.value.trim()) return; // user may have typed meanwhile
      var alt = map[name];
      if (alt) { altInput.value = alt; block.alt = alt; touch(); }
    });
  }

  // isLoneURL reports whether s is a single bare http(s) URL (no surrounding text).
  function isLoneURL(s) {
    return /^https?:\/\/\S+$/.test(s) && !/\s/.test(s);
  }

  // unfurlEmbedAt resolves a URL's metadata server-side and fills the embed block
  // at idx (used by the slash "Embed" card and by auto-embed on URL paste).
  function unfurlEmbedAt(idx, url) {
    var b = blocks[idx];
    if (!b || b.type !== 'embed') return;
    setStatus('Fetching…');
    fetch('/os/api/embed/unfurl', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      body: JSON.stringify({ url: url })
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (data.error) { setStatus('Embed: ' + data.error, 'warn'); return; }
      b.url = data.url || url;
      b.title = data.title || '';
      b.description = data.description || '';
      b.provider = data.provider || '';
      b.thumbURL = data.thumbURL || '';
      b.kind = data.kind || 'link';
      b.embedSrc = data.embedSrc || '';
      structural();
      setStatus('Embed added', 'ok');
    }).catch(function () { setStatus('Could not fetch URL', 'danger'); });
  }

  // ── Gallery editor (up to 9 images) ─────────────────────────────────────────
  // safeMediaURL is a strict allowlist for any URL that will be assigned to an
  // <img> src or stored in the document: it permits http(s), protocol-relative
  // (//host), site-relative (/path), and scheme-less relative paths, and rejects
  // everything else — notably javascript:, data:, and vbscript: URLs — by
  // returning ''. Control characters (which can smuggle a scheme past the check,
  // e.g. "java\tscript:") are rejected outright. This is the client-side barrier;
  // the server (blockrender) independently escapes/sanitises on render.
  function safeMediaURL(u) {
    u = (u == null ? '' : String(u)).trim();
    if (!u) return '';
    if (/[\u0000-\u001F\u007F]/.test(u)) return '';      // control chars
    if (u.charAt(0) === '/') return u;                   // /path or //host
    if (/^\.{1,2}\//.test(u)) return u;                  // ./x or ../x
    if (/^[^:]+$/.test(u)) return u;                     // relative, no scheme
    return /^https?:\/\//i.test(u) ? u : '';             // explicit http(s) only
  }

  // safeImgSrc is the barrier used at every point a value is assigned to an
  // <img> src. It resolves the (possibly relative) value against the current
  // origin with the URL parser and returns the parsed .href ONLY when the
  // resulting scheme is http(s); javascript:/data:/vbscript: and malformed
  // inputs yield ''. Returning the parser's normalised href — rather than the
  // raw string — behind an explicit protocol check makes this an effective
  // sanitiser for the "DOM text reinterpreted as HTML" data flow, including
  // values rehydrated from the saved document.
  function safeImgSrc(u) {
    u = (u == null ? '' : String(u)).trim();
    if (!u) return '';
    try {
      var parsed = new URL(u, window.location.origin);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return parsed.href;
      }
    } catch (e) { /* malformed URL → unsafe */ }
    return '';
  }

  function buildGalleryField(block, idx) {
    block.images = block.images || [];
    var wrap = document.createElement('div');
    wrap.className = 'eblock__gallery';

    var grid = document.createElement('div');
    grid.className = 'eblock__gallery-grid';
    block.images.forEach(function (src, i) {
      var cell = document.createElement('div');
      cell.className = 'eblock__gallery-cell';
      var img = document.createElement('img');
      img.src = safeImgSrc(src);
      img.alt = '';
      var del = document.createElement('button');
      del.type = 'button';
      del.className = 'eblock__gallery-del';
      del.textContent = '×';
      del.title = 'Remove image';
      del.addEventListener('click', function () { block.images.splice(i, 1); structural(); });
      cell.appendChild(img);
      cell.appendChild(del);
      grid.appendChild(cell);
    });
    wrap.appendChild(grid);

    var ctl = document.createElement('div');
    ctl.className = 'eblock__row';
    var addUrl = mkInput('text', '', 'Image URL, then press Add');
    var addBtn = mkSmallBtn('+ Add URL', function () {
      var v = safeMediaURL(addUrl.value);
      if (!v) { setStatus('Enter a valid image URL (http(s) or a /media path)', 'warn'); return; }
      if (block.images.length >= 9) { setStatus('A gallery holds up to 9 images', 'warn'); return; }
      block.images.push(v);
      addUrl.value = '';
      structural();
    });
    var upBtn = mkSmallBtn('⬆ Upload', function () { gFile.click(); });
    var gFile = document.createElement('input');
    gFile.type = 'file';
    gFile.accept = 'image/*';
    gFile.multiple = true;
    gFile.style.display = 'none';
    gFile.addEventListener('change', function () {
      var files = gFile.files ? Array.prototype.slice.call(gFile.files) : [];
      files.forEach(function (f) {
        if (block.images.length >= 9) return;
        uploadInto(f, function (u) { var s = safeMediaURL(u); if (s && block.images.length < 9) { block.images.push(s); structural(); } });
      });
      gFile.value = '';
    });
    ctl.appendChild(addUrl);
    ctl.appendChild(addBtn);
    ctl.appendChild(upBtn);
    ctl.appendChild(gFile);
    wrap.appendChild(ctl);

    var cap = mkInput('text', block.caption || '', 'Gallery caption (optional)');
    cap.addEventListener('input', function () { block.caption = cap.value; touch(); });
    wrap.appendChild(cap);
    wrap.appendChild(mkHint('Up to 9 images, shown as a responsive grid. Drag images into the editor or use Upload.'));
    return wrap;
  }

  function placeholderFor(type) {
    if (type === 'quote') return 'Quote…';
    if (type === 'callout') return 'Callout text…';
    return "Write something, or press '/' for blocks…";
  }

  function mkInput(type, val, ph) {
    var i = document.createElement('input');
    i.type = type;
    i.className = 'eblock__input';
    i.value = val;
    i.placeholder = ph;
    return i;
  }

  function mkTextarea(val, ph) {
    var t = document.createElement('textarea');
    t.className = 'eblock__text';
    t.value = val;
    t.placeholder = ph;
    t.rows = 1;
    return t;
  }

  function mkHint(text) {
    var h = document.createElement('div');
    h.className = 'eblock__hint text-xs muted';
    h.textContent = text;
    return h;
  }

  function autoGrow(t) {
    t.style.height = 'auto';
    t.style.height = (t.scrollHeight) + 'px';
  }

  function focusBlock(idx, atEnd) {
    var wrap = canvas.querySelector('[data-block-idx="' + idx + '"]');
    if (!wrap) return;
    var f = wrap.querySelector('.eblock__heading, .eblock__text, .eblock__input');
    if (!f) return;
    f.focus();
    if (atEnd && typeof f.setSelectionRange === 'function') {
      try { var n = f.value.length; f.setSelectionRange(n, n); } catch (e) {}
    }
  }

  function convertBlock(idx, newBlock) {
    blocks[idx] = newBlock;
    structural();
    setTimeout(function () { focusBlock(idx, true); }, 0);
  }

  // tryParagraphShortcut turns leading Markdown markers in a paragraph into the
  // matching block as soon as the trigger space is typed.
  function tryParagraphShortcut(idx, el) {
    var v = el.value;
    var m;
    if ((m = /^[-*]\s\[( |x|X)\]\s(.*)$/.exec(v))) {
      convertBlock(idx, { type: 'tasklist', items: [m[2] || ''], checked: [/x/i.test(m[1])] });
      return true;
    }
    if ((m = /^(#{1,4})\s(.*)$/.exec(v))) {
      var lvl = Math.min(4, Math.max(2, m[1].length));
      convertBlock(idx, { type: 'heading', level: lvl, text: m[2] });
      return true;
    }
    if ((m = /^[-*]\s(.*)$/.exec(v))) {
      convertBlock(idx, { type: 'list', style: 'unordered', items: m[1] ? [m[1]] : [] });
      return true;
    }
    if ((m = /^1\.\s(.*)$/.exec(v))) {
      convertBlock(idx, { type: 'list', style: 'ordered', items: m[1] ? [m[1]] : [] });
      return true;
    }
    if ((m = /^>\s(.*)$/.exec(v))) {
      convertBlock(idx, { type: 'quote', text: m[1] });
      return true;
    }
    if ((m = /^```(\w*)$/.exec(v))) {
      convertBlock(idx, { type: 'code', lang: m[1] || '', text: '' });
      return true;
    }
    if (/^---\s?$/.test(v)) {
      blocks[idx] = { type: 'divider' };
      blocks.splice(idx + 1, 0, { type: 'paragraph', text: '' });
      structural();
      setTimeout(function () { focusBlock(idx + 1, true); }, 0);
      return true;
    }
    return false;
  }

  // parseMarkdownBlocks turns pasted multi-line Markdown into an array of typed
  // blocks, mirroring the leading-marker shortcuts: headings, task lists,
  // bullet/numbered lists (consecutive items grouped into one block), quotes
  // (consecutive lines joined), fenced code (language kept), dividers; blank
  // lines split paragraphs and consecutive prose lines join into one paragraph.
  // Pure function — capped at 500 lines so a giant paste can never jank the UI.
  // ── Rich paste (Wave 4.3) ──────────────────────────────────────────────────
  // htmlInlineToMd converts an element's INLINE content to the Markdown the
  // textareas already speak (strong/b → **, em/i → *, code → `, a → [t](href),
  // br → newline). Unknown elements degrade to their text — structure is never
  // invented from markup the editor cannot represent.
  function htmlInlineToMd(node) {
    var out = '';
    Array.prototype.forEach.call(node.childNodes, function (ch) {
      if (ch.nodeType === 3) { out += ch.nodeValue; return; }
      if (ch.nodeType !== 1) return;
      var tag = ch.tagName.toLowerCase();
      var inner = htmlInlineToMd(ch);
      if (tag === 'strong' || tag === 'b') { out += inner ? '**' + inner + '**' : ''; }
      else if (tag === 'em' || tag === 'i') { out += inner ? '*' + inner + '*' : ''; }
      else if (tag === 'code') { out += inner ? '`' + inner + '`' : ''; }
      else if (tag === 'a') {
        var href = ch.getAttribute('href') || '';
        out += inner ? '[' + inner + '](' + href + ')' : '';
      }
      else if (tag === 'br') { out += '\n'; }
      else { out += inner; }
    });
    return out;
  }

  // parseHTMLBlocks turns pasted text/html into editor blocks. DOMPurify runs
  // FIRST with an allowlist of exactly the block vocabulary this editor has —
  // anything outside it (style, img, script, tables, class attributes) is
  // stripped before the tree is ever touched. Falls back to [] when DOMPurify
  // is unavailable, in which case the paste falls through to plain-text
  // handling: never parse unsanitised HTML just to preserve formatting.
  function parseHTMLBlocks(html) {
    if (!window.DOMPurify || !window.DOMPurify.sanitize) return [];
    var clean = window.DOMPurify.sanitize(String(html || ''), {
      ALLOWED_TAGS: ['p', 'h1', 'h2', 'h3', 'ul', 'ol', 'li', 'blockquote', 'pre', 'code', 'strong', 'b', 'em', 'i', 'a', 'br'],
      ALLOWED_ATTR: ['href'],
      KEEP_CONTENT: true
    });
    var doc;
    try { doc = new DOMParser().parseFromString(clean, 'text/html'); } catch (err) { return []; }
    var out = [];
    Array.prototype.forEach.call(doc.body.childNodes, function (n) {
      if (n.nodeType === 3) {
        var txt = (n.nodeValue || '').trim();
        if (txt) out.push({ type: 'paragraph', text: txt });
        return;
      }
      if (n.nodeType !== 1) return;
      var tag = n.tagName.toLowerCase();
      if (tag === 'p') {
        var t = htmlInlineToMd(n).trim();
        if (t) out.push({ type: 'paragraph', text: t });
      } else if (tag === 'h1' || tag === 'h2' || tag === 'h3') {
        var ht = htmlInlineToMd(n).trim();
        if (ht) out.push({ type: 'heading', level: tag === 'h3' ? 3 : 2, text: ht });
      } else if (tag === 'ul' || tag === 'ol') {
        var items = [];
        Array.prototype.forEach.call(n.children, function (li) {
          if (li.tagName.toLowerCase() !== 'li') return;
          var it = htmlInlineToMd(li).replace(/\s+/g, ' ').trim();
          if (it) items.push(it);
        });
        if (items.length) out.push({ type: 'list', style: tag === 'ol' ? 'ordered' : 'unordered', items: items });
      } else if (tag === 'blockquote') {
        var q = htmlInlineToMd(n).trim();
        if (q) out.push({ type: 'quote', text: q });
      } else if (tag === 'pre') {
        var code = (n.textContent || '').replace(/\n+$/, '');
        if (code) out.push({ type: 'code', lang: '', text: code });
      }
    });
    return out;
  }

  function parseMarkdownBlocks(text) {
    var lines = String(text).replace(/\r\n?/g, '\n').split('\n').slice(0, 500);
    var out = [], i = 0, m;
    function flushPara(buf) {
      var s = buf.join('\n').replace(/\s+$/, '');
      if (s) out.push({ type: 'paragraph', text: s });
    }
    while (i < lines.length) {
      var ln = lines[i];
      if (/^\s*$/.test(ln)) { i++; continue; }
      if ((m = /^```(\w*)\s*$/.exec(ln))) { // fenced code until closing fence
        var code = []; i++;
        while (i < lines.length && !/^```\s*$/.test(lines[i])) { code.push(lines[i]); i++; }
        i++; // skip closing fence (or run off the end)
        out.push({ type: 'code', lang: m[1] || '', text: code.join('\n') });
        continue;
      }
      if (/^---+\s*$/.test(ln)) { out.push({ type: 'divider' }); i++; continue; }
      if ((m = /^(#{1,6})\s+(.*)$/.exec(ln))) {
        out.push({ type: 'heading', level: Math.min(4, Math.max(2, m[1].length)), text: m[2] });
        i++; continue;
      }
      if (/^[-*]\s\[( |x|X)\]\s/.test(ln)) { // task list (grouped)
        var titems = [], tchecked = [];
        while (i < lines.length && (m = /^[-*]\s\[( |x|X)\]\s(.*)$/.exec(lines[i]))) {
          titems.push(m[2]); tchecked.push(/x/i.test(m[1])); i++;
        }
        out.push({ type: 'tasklist', items: titems, checked: tchecked });
        continue;
      }
      if (/^[-*]\s+/.test(ln)) { // unordered list (grouped)
        var uitems = [];
        while (i < lines.length && (m = /^[-*]\s+(.*)$/.exec(lines[i]))) { uitems.push(m[1]); i++; }
        out.push({ type: 'list', style: 'unordered', items: uitems });
        continue;
      }
      if (/^\d+\.\s+/.test(ln)) { // ordered list (grouped)
        var oitems = [];
        while (i < lines.length && (m = /^\d+\.\s+(.*)$/.exec(lines[i]))) { oitems.push(m[1]); i++; }
        out.push({ type: 'list', style: 'ordered', items: oitems });
        continue;
      }
      if (/^>\s?/.test(ln)) { // quote (consecutive lines joined)
        var q = [];
        while (i < lines.length && (m = /^>\s?(.*)$/.exec(lines[i]))) { q.push(m[1]); i++; }
        out.push({ type: 'quote', text: q.join('\n') });
        continue;
      }
      var buf = []; // prose: join consecutive non-blank plain lines
      while (i < lines.length && !/^\s*$/.test(lines[i]) &&
             !/^(#{1,6}\s|[-*]\s|\d+\.\s|>\s?|```|---+\s*$)/.test(lines[i])) {
        buf.push(lines[i]); i++;
      }
      if (!buf.length) { buf.push(lines[i]); i++; } // safety: always consume
      flushPara(buf);
    }
    return out;
  }

  // wrapSelection surrounds the textarea's current selection with Markdown marks
  // (or drops an empty pair at the caret when nothing is selected), then fires an
  // input event so block.text, the live stats and autosave all update through the
  // existing listener. For links it leaves the "url" placeholder selected so the
  // writer types the destination immediately — the ⌘K flow people expect.
  function wrapSelection(el, before, after, isLink) {
    var s = el.selectionStart, e2 = el.selectionEnd, v = el.value;
    var sel = v.slice(s, e2);
    el.value = v.slice(0, s) + before + sel + after + v.slice(e2);
    if (isLink) {
      var us = s + before.length + sel.length + 2; // just past "]("
      el.selectionStart = us; el.selectionEnd = us + 3; // the word "url"
    } else if (sel) {
      el.selectionStart = s + before.length;
      el.selectionEnd = e2 + before.length; // keep the original text selected
    } else {
      el.selectionStart = el.selectionEnd = s + before.length; // caret between marks
    }
    el.focus();
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }

  // onTextKey gives text blocks a continuous, document-like writing flow.
  function onTextKey(idx) {
    return function (e) {
      var el = e.target;
      // Inline formatting shortcuts (⌘/Ctrl + B/I/E/K) — wrap the selection with
      // the Markdown marks, like a real prose editor. Alt is excluded so it never
      // clashes with OS accents.
      if ((e.metaKey || e.ctrlKey) && !e.altKey) {
        var mk = null, kk = (e.key || '').toLowerCase();
        if (kk === 'b') mk = ['**', '**', false];
        else if (kk === 'i') mk = ['*', '*', false];
        else if (kk === 'e') mk = ['`', '`', false];
        else if (kk === 'k') mk = ['[', '](url)', true];
        if (mk) { e.preventDefault(); wrapSelection(el, mk[0], mk[1], mk[2]); return; }
        if (kk === 'd') { e.preventDefault(); duplicateBlock(idx); return; } // ⌘/Ctrl+D duplicates the block
      }
      if (e.key === '/' && el.value === '') {
        e.preventDefault();
        openPalette(idx + 1, idx);
        return;
      }
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        insertBlock(idx + 1, { type: 'paragraph', text: '' });
        setTimeout(function () { focusBlock(idx + 1, true); }, 0);
        return;
      }
      if (e.key === 'Backspace' && el.selectionStart === 0 && el.selectionEnd === 0 &&
          el.value === '' && blocks.length > 1) {
        e.preventDefault();
        var prev = idx - 1;
        removeBlock(idx);
        if (prev >= 0) setTimeout(function () { focusBlock(prev, true); }, 0);
        return;
      }
    };
  }

  function renderCanvas() {
    while (canvas.firstChild) canvas.removeChild(canvas.firstChild);
    blocks.forEach(function (b, i) {
      canvas.appendChild(makeBlockEl(b, i));
    });
  }

  // ── Mutations ──────────────────────────────────────────────────────────────
  function insertBlock(at, block) {
    if (at < 0) at = 0;
    if (at > blocks.length) at = blocks.length;
    blocks.splice(at, 0, block);
    structural();
  }

  function removeBlock(idx) {
    blocks.splice(idx, 1);
    if (!blocks.length) blocks = [{ type: 'paragraph', text: '' }];
    structural();
  }

  // moveBlock relocates the block at `from` to insertion index `to` (in the
  // pre-move array). Used by drag-and-drop.
  function moveBlock(from, to) {
    if (from < 0 || from >= blocks.length) return;
    var b = blocks.splice(from, 1)[0];
    if (from < to) to--;
    if (to < 0) to = 0;
    if (to > blocks.length) to = blocks.length;
    blocks.splice(to, 0, b);
    structural();
  }

  // duplicateBlock deep-clones the block at idx and inserts the copy directly
  // below it, then focuses the copy. Blocks are plain JSON-serialisable data
  // (text, items, level, style, url…), so a structural clone via JSON is exact
  // and can't share array/object references with the original.
  function duplicateBlock(idx) {
    if (idx < 0 || idx >= blocks.length) return;
    var copy;
    try { copy = JSON.parse(JSON.stringify(blocks[idx])); }
    catch (e) { return; } // never corrupt the doc on an unexpected shape
    blocks.splice(idx + 1, 0, copy);
    structural();
    setTimeout(function () { focusBlock(idx + 1, true); }, 0);
  }

  // nudge swaps a block with its neighbour (keyboard / button reorder).
  function nudge(idx, dir) {
    var j = idx + dir;
    if (j < 0 || j >= blocks.length) return;
    var tmp = blocks[idx];
    blocks[idx] = blocks[j];
    blocks[j] = tmp;
    structural();
    setTimeout(function () { focusBlock(j, true); }, 0);
  }

  function newBlockOf(type) {
    if (type === 'ordered') return { type: 'list', style: 'ordered', items: [] };
    if (type === 'list') return { type: 'list', style: 'unordered', items: [] };
    if (type === 'tasklist') return { type: 'tasklist', items: [''], checked: [false] };
    if (type === 'heading') return { type: 'heading', level: 2, text: '' };
    if (type === 'divider') return { type: 'divider' };
    if (type === 'image') return { type: 'image', url: '', alt: '', caption: '', width: '' };
    if (type === 'gallery') return { type: 'gallery', images: [], caption: '' };
    if (type === 'audio') return { type: 'audio', url: '', alt: '' };
    if (type === 'embed') return { type: 'embed', url: '', title: '', description: '', provider: '', thumbURL: '' };
    if (type === 'code') return { type: 'code', lang: '', text: '' };
    if (type === 'html') return { type: 'html', text: '' };
    if (type === 'markdown') return { type: 'markdown', text: '' };
    if (type === 'diagram') return { type: 'diagram', text: '' };
    if (type === 'callout') return { type: 'callout', style: 'info', text: '' };
    if (type === 'table') return { type: 'table', header: ['Column 1', 'Column 2'], rows: [['', ''], ['', '']] };
    if (type === 'toggle') return { type: 'toggle', summary: '', text: '', open: false };
    if (type === 'math') return { type: 'math', text: '' };
    return { type: 'paragraph', text: '' };
  }

  // ── Slash / command palette (categorised, keyboard-navigable) ───────────────
  var paletteEl = null;

  function makePaletteItem(icon, label, hint, onClick) {
    var item = document.createElement('button');
    item.type = 'button';
    item.className = 'block-palette__item';
    var ic = document.createElement('span');
    ic.className = 'block-palette__icon';
    ic.textContent = icon;
    var lab = document.createElement('span');
    lab.className = 'block-palette__label';
    lab.textContent = label;
    var hintEl = document.createElement('span');
    hintEl.className = 'block-palette__hint';
    hintEl.textContent = hint;
    item.appendChild(ic);
    item.appendChild(lab);
    item.appendChild(hintEl);
    item.addEventListener('click', function () { onClick(); closePalette(); });
    return item;
  }

  function openPalette(insertAt, sourceBlockIdx) {
    closePalette();
    paletteEl = document.createElement('div');
    paletteEl.className = 'block-palette';

    var search = document.createElement('input');
    search.type = 'text';
    search.className = 'block-palette__search';
    search.placeholder = 'Search blocks…  (↑↓ navigate · Enter insert · Esc close)';
    paletteEl.appendChild(search);

    var list = document.createElement('div');
    list.className = 'block-palette__list';

    CATEGORIES.forEach(function (cat) {
      var inCat = BLOCK_TYPES.filter(function (b) { return b.cat === cat; });
      if (!inCat.length) return;
      var sep = document.createElement('div');
      sep.className = 'block-palette__sep';
      sep.textContent = cat;
      list.appendChild(sep);
      inCat.forEach(function (bt) {
        var item = makePaletteItem(bt.icon, bt.label, bt.hint, function () {
          insertBlock(insertAt, newBlockOf(bt.type));
          setTimeout(function () { focusBlock(insertAt, true); }, 0);
        });
        item.setAttribute('data-search', (bt.label + ' ' + bt.hint + ' ' + bt.type).toLowerCase());
        list.appendChild(item);
      });
    });

    if (aiEnabled && sourceBlockIdx != null && sourceBlockIdx >= 0 && sourceBlockIdx < blocks.length) {
      var aisep = document.createElement('div');
      aisep.className = 'block-palette__sep';
      aisep.textContent = 'AI assist';
      list.appendChild(aisep);
      var srcText = blockText(blocks[sourceBlockIdx]);
      AI_CMDS.forEach(function (cmd) {
        var item = makePaletteItem(cmd.icon, cmd.label, cmd.hint, function () {
          runAI(cmd.op, srcText, insertAt);
        });
        item.setAttribute('data-search', (cmd.label + ' ' + cmd.hint).toLowerCase());
        list.appendChild(item);
      });
    }

    paletteEl.appendChild(list);

    var selIdx = -1;
    function visibleItems() {
      return Array.prototype.filter.call(
        list.querySelectorAll('.block-palette__item'),
        function (it) { return it.style.display !== 'none'; });
    }
    function highlight() {
      var items = visibleItems();
      items.forEach(function (it, i) { it.classList.toggle('is-active', i === selIdx); });
      if (selIdx >= 0 && items[selIdx] && items[selIdx].scrollIntoView) {
        items[selIdx].scrollIntoView({ block: 'nearest' });
      }
    }
    function applyFilter() {
      var q = search.value.trim().toLowerCase();
      list.querySelectorAll('.block-palette__item').forEach(function (it) {
        var hay = it.getAttribute('data-search') || '';
        it.style.display = (!q || hay.indexOf(q) !== -1) ? '' : 'none';
      });
      // Hide category headers that have no visible items beneath them.
      list.querySelectorAll('.block-palette__sep').forEach(function (sep) {
        var anyVisible = false, n = sep.nextSibling;
        while (n) {
          if (n.classList && n.classList.contains('block-palette__sep')) break;
          if (n.classList && n.classList.contains('block-palette__item') && n.style.display !== 'none') { anyVisible = true; break; }
          n = n.nextSibling;
        }
        sep.style.display = anyVisible ? '' : 'none';
      });
      selIdx = visibleItems().length ? 0 : -1;
      highlight();
    }
    search.addEventListener('input', applyFilter);
    search.addEventListener('keydown', function (e) {
      var items = visibleItems();
      if (e.key === 'ArrowDown') { e.preventDefault(); if (items.length) { selIdx = (selIdx + 1) % items.length; highlight(); } }
      else if (e.key === 'ArrowUp') { e.preventDefault(); if (items.length) { selIdx = (selIdx - 1 + items.length) % items.length; highlight(); } }
      else if (e.key === 'Enter') { e.preventDefault(); var t = items[selIdx >= 0 ? selIdx : 0]; if (t) t.click(); }
      else if (e.key === 'Escape') { closePalette(); }
    });

    document.body.appendChild(paletteEl);
    applyFilter();
    setTimeout(function () { search.focus(); }, 0);
    document.addEventListener('keydown', escClose);
    setTimeout(function () { document.addEventListener('click', outsideClose); }, 0);
  }

  function escClose(e) { if (e.key === 'Escape') closePalette(); }
  function outsideClose(e) { if (paletteEl && !paletteEl.contains(e.target)) closePalette(); }
  function closePalette() {
    if (paletteEl && paletteEl.parentNode) paletteEl.parentNode.removeChild(paletteEl);
    paletteEl = null;
    document.removeEventListener('keydown', escClose);
    document.removeEventListener('click', outsideClose);
  }

  // ── AI assist ─────────────────────────────────────────────────────────────
  function runAI(op, text, insertAt) {
    if (!text.trim()) {
      setStatus('Select a block with text first', 'warn');
      return;
    }
    setStatus('AI thinking…');
    fetch('/os/api/editor/ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      body: JSON.stringify({ op: op, text: text })
    }).then(function (r) {
      if (r.status === 503) { aiEnabled = false; }
      if (!r.ok) throw new Error('ai-' + r.status);
      return r.json();
    }).then(function (d) {
      var result = (d && d.result) ? String(d.result) : '';
      if (!result) { setStatus('AI returned empty result', 'warn'); return; }
      showAISuggestion(result, insertAt);
      setStatus('AI suggestion ready', 'ok');
    }).catch(function (err) {
      setStatus('AI assist: ' + String(err.message || err), 'danger');
    });
  }

  function showAISuggestion(text, insertAt) {
    var existing = document.getElementById('ai-suggest-overlay');
    if (existing && existing.parentNode) existing.parentNode.removeChild(existing);

    var overlay = document.createElement('div');
    overlay.id = 'ai-suggest-overlay';
    overlay.className = 'ai-suggest';
    var pre = document.createElement('div');
    pre.className = 'ai-suggest__text';
    pre.textContent = text;
    var actions = document.createElement('div');
    actions.className = 'ai-suggest__actions';

    var accept = document.createElement('button');
    accept.type = 'button';
    accept.className = 'btn btn--primary btn--xs';
    accept.textContent = 'Accept';
    accept.addEventListener('click', function () {
      insertBlock(insertAt, { type: 'paragraph', text: text });
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
    });

    var discard = document.createElement('button');
    discard.type = 'button';
    discard.className = 'btn btn--ghost btn--xs';
    discard.textContent = 'Discard';
    discard.addEventListener('click', function () {
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
      setStatus('Ready');
    });

    actions.appendChild(accept);
    actions.appendChild(discard);
    overlay.appendChild(pre);
    overlay.appendChild(actions);
    canvas.parentNode.insertBefore(overlay, canvas.nextSibling);
  }

  // ── Version history ────────────────────────────────────────────────────────
  function openHistory() {
    if (!slug) { setStatus('Save the post first', 'warn'); return; }
    if (!historyModal) return;
    historyModal.hidden = false;
    loadVersionList();
  }

  function loadVersionList() {
    if (!historyList) return;
    while (historyList.firstChild) historyList.removeChild(historyList.firstChild);
    var loading = document.createElement('div');
    loading.className = 'text-sm muted';
    loading.textContent = 'Loading…';
    historyList.appendChild(loading);

    fetch('/os/api/editor/versions/' + encodeURIComponent(slug), {
      headers: { Accept: 'application/json' }
    }).then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) {
        while (historyList.firstChild) historyList.removeChild(historyList.firstChild);
        var list = (d && d.versions) || [];
        if (!list.length) {
          var empty = document.createElement('div');
          empty.className = 'text-sm muted';
          empty.textContent = 'No versions yet.';
          historyList.appendChild(empty);
          return;
        }
        list.forEach(function (v) {
          var btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'history-ver';
          var ts = document.createElement('span');
          ts.className = 'history-ver__ts';
          ts.textContent = new Date(v.created_at || v.CreatedAt || '').toLocaleString();
          var label = document.createElement('span');
          label.className = 'history-ver__label';
          label.textContent = v.label || ('#' + v.id);
          btn.appendChild(ts);
          btn.appendChild(label);
          btn.addEventListener('click', function () { loadVersionDiff(v.id); });
          historyList.appendChild(btn);
        });
      }).catch(function () {
        while (historyList.firstChild) historyList.removeChild(historyList.firstChild);
        var err = document.createElement('div');
        err.className = 'text-sm muted';
        err.textContent = 'Could not load versions.';
        historyList.appendChild(err);
      });
  }

  function loadVersionDiff(id) {
    if (!historyDiff) return;
    while (historyDiff.firstChild) historyDiff.removeChild(historyDiff.firstChild);
    var loading = document.createElement('div');
    loading.className = 'text-sm muted';
    loading.textContent = 'Loading diff…';
    historyDiff.appendChild(loading);

    fetch('/os/api/editor/versions/' + encodeURIComponent(slug) + '/' + encodeURIComponent(String(id)), {
      headers: { Accept: 'application/json' }
    }).then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (v) {
        while (historyDiff.firstChild) historyDiff.removeChild(historyDiff.firstChild);
        var currentText = collectAllText();
        var oldText = v.content || v.Content || '';
        renderWordDiff(currentText, oldText);
      }).catch(function () {
        while (historyDiff.firstChild) historyDiff.removeChild(historyDiff.firstChild);
        var err = document.createElement('div');
        err.className = 'text-sm muted';
        err.textContent = 'Could not load version.';
        historyDiff.appendChild(err);
      });
  }

  function renderWordDiff(current, old) {
    var pre = document.createElement('div');
    pre.className = 'history-diff__view';
    var oldWords = old.split(/\s+/).filter(Boolean);
    var newWords = current.split(/\s+/).filter(Boolean);
    var ops = lcsWordDiff(oldWords, newWords);
    ops.forEach(function (op) {
      var span = document.createElement('span');
      span.className = op.kind === 'del' ? 'diff-del' : op.kind === 'ins' ? 'diff-ins' : 'diff-eq';
      span.textContent = op.word + ' ';
      pre.appendChild(span);
    });
    var heading = document.createElement('div');
    heading.className = 'history-diff__title text-xs muted';
    heading.textContent = 'Current ↔ selected version (word-level diff)';
    historyDiff.appendChild(heading);
    historyDiff.appendChild(pre);
  }

  function lcsWordDiff(oldW, newW) {
    var m = oldW.length, n = newW.length;
    var maxW = 300;
    if (m > maxW || n > maxW) {
      var ops = [];
      oldW.slice(0, maxW).forEach(function (w) { ops.push({ kind: 'del', word: w }); });
      newW.slice(0, maxW).forEach(function (w) { ops.push({ kind: 'ins', word: w }); });
      return ops;
    }
    var dp = [];
    for (var i = 0; i <= m; i++) dp[i] = new Array(n + 1).fill(0);
    for (var ii = 1; ii <= m; ii++) {
      for (var jj = 1; jj <= n; jj++) {
        dp[ii][jj] = oldW[ii - 1] === newW[jj - 1] ? dp[ii - 1][jj - 1] + 1 : Math.max(dp[ii - 1][jj], dp[ii][jj - 1]);
      }
    }
    var result = [];
    var a = m, b = n;
    while (a > 0 || b > 0) {
      if (a > 0 && b > 0 && oldW[a - 1] === newW[b - 1]) { result.unshift({ kind: 'eq', word: oldW[a - 1] }); a--; b--; }
      else if (b > 0 && (a === 0 || dp[a][b - 1] >= dp[a - 1][b])) { result.unshift({ kind: 'ins', word: newW[b - 1] }); b--; }
      else { result.unshift({ kind: 'del', word: oldW[a - 1] }); a--; }
    }
    return result;
  }

  // ── Persistence ────────────────────────────────────────────────────────────
  function csrfToken() {
    var m = document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : '';
  }

  function payload() {
    var p = { slug: slug, title: titleEl ? titleEl.value : '', blocks: blocks };
    // Only send publishing-options fields once the panel has hydrated, so an
    // older/incomplete shell can never accidentally clear tags or metadata.
    if (metaHydrated) {
      p.tags = pmTags.slice();
      p.publishDate = pm['publish-date'] ? pm['publish-date'].value : '';
      p.meta = collectMeta();
    }
    return JSON.stringify(p);
  }

  function save() {
    if (!slug && (!titleEl || !titleEl.value.trim())) {
      setStatus('Add a title before saving', 'warn');
      if (titleEl) titleEl.focus();
      return;
    }
    // In HTML mode the source is authoritative — parse it into blocks first so
    // the save reflects the operator's raw edits.
    if (htmlMode) { applyHTMLSource().then(performSave).catch(function () { setStatus('Could not parse HTML', 'danger'); }); return; }
    // In Markdown mode the source is likewise authoritative.
    if (mdMode) { applyMDSource(); }
    performSave();
  }

  function performSave() {
    setStatus('Saving…');
    fetch('/os/api/editor/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      body: payload()
    }).then(function (r) {
      if (!r.ok) throw new Error('save failed (' + r.status + ')');
      return r.json();
    }).then(function (data) {
      if (!slug && data && data.slug) {
        slug = data.slug;
        if (root) root.setAttribute('data-slug', slug);
        try { history.replaceState({}, '', '/os/editor/' + encodeURIComponent(slug)); } catch (e) {}
        if (typeof pmSet === 'function') { pmSet(pm['slug'], slug); syncSlugUI(); }
      }
      // A successful create answers with the row's lifecycle state so the
      // topbar pill appears immediately (new posts are born drafts).
      if (data && data.postStatus) applyPostStatus(String(data.postStatus), false);
      renderPubUI();
      // Saved ⇒ nothing unsaved remains: drop the crash-recovery copy.
      markClean();
      setStatus('Saved · ' + new Date().toLocaleTimeString(), 'ok');
      if (window.vpToast) window.vpToast('Post saved', 'ok');
    }).catch(function (err) {
      setStatus(String(err.message || err), 'danger');
    });
  }

  var autosaveTimer = null;
  function scheduleAutosave() {
    // Every edit path funnels through here, so this is the single choke point
    // for the dirty flag + crash-recovery backup (Wave 1).
    dirty = true;
    backupNow();
    if (!slug) return;
    setStatus('Editing…');
    if (autosaveTimer) clearTimeout(autosaveTimer);
    autosaveTimer = setTimeout(save, 2500);
  }

  // ── Lifecycle: publish state, dirty flag, crash backup (Wave 1) ─────────────
  // Saving must never publish: a brand-new post is born a draft server-side and
  // the topbar control below is the ONLY way this surface flips the switch.
  var postStatus = ''; // '' = unknown / never saved; otherwise 'draft' | 'published'
  var pubStateEl = root.querySelector('[data-editor-pubstate]');
  var pubBtn = root.querySelector('[data-editor-publish-btn]');

  function applyPostStatus(next, announce) {
    postStatus = (next === 'draft' || next === 'published') ? next : '';
    renderPubUI();
    if (announce && window.vpToast) {
      window.vpToast(next === 'published' ? 'Post published' : 'Post unpublished — back to draft', next === 'published' ? 'ok' : 'warn');
    }
  }

  function renderPubUI() {
    if (!pubStateEl || !pubBtn) return;
    if (!slug || !postStatus) { pubStateEl.hidden = true; pubBtn.hidden = true; return; }
    pubStateEl.hidden = false;
    pubBtn.hidden = false;
    if (postStatus === 'published') {
      pubStateEl.textContent = 'Published';
      pubStateEl.classList.remove('is-draft');
      pubStateEl.classList.add('is-published');
      pubBtn.textContent = 'Unpublish';
      pubBtn.setAttribute('title', 'Revert to draft — readers will no longer see this post');
    } else {
      pubStateEl.textContent = 'Draft';
      pubStateEl.classList.remove('is-published');
      pubStateEl.classList.add('is-draft');
      pubBtn.textContent = 'Publish';
      pubBtn.setAttribute('title', 'Publish to the live site');
    }
  }

  function togglePublish() {
    if (!slug || !postStatus || pubBtn.disabled) return;
    var target = postStatus === 'published' ? 'draft' : 'published';
    var prev = postStatus;
    pubBtn.disabled = true;
    setStatus(target === 'published' ? 'Publishing…' : 'Unpublishing…');
    fetch('/os/api/posts/status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      body: JSON.stringify({ slug: slug, status: target })
    }).then(function (r) {
      if (!r.ok) throw new Error('status change failed (' + r.status + ')');
      return r.json();
    }).then(function () {
      applyPostStatus(target, true);
      setStatus(target === 'published' ? 'Published' : 'Draft', 'ok');
    }).catch(function (err) {
      applyPostStatus(prev, false);
      setStatus(String(err.message || err), 'danger');
      if (window.vpToast) window.vpToast('Could not change publish state', 'danger');
    }).then(function () {
      pubBtn.disabled = false;
      renderPubUI();
    });
  }
  if (pubBtn) pubBtn.addEventListener('click', togglePublish);

  // Dirty flag + crash-recovery backup. Autosave deliberately waits until a slug
  // exists, so everything typed into a brand-new post previously lived only in
  // RAM — browser close, crash or accidental Back meant total loss (P0).
  var dirty = false;
  var BACKUP_KEY = 'vp-editor-autobackup';

  function backupNow() {
    try {
      localStorage.setItem(BACKUP_KEY, JSON.stringify({
        slug: slug || '',
        title: titleEl ? titleEl.value : '',
        blocks: blocks,
        t: Date.now()
      }));
    } catch (e) { /* storage unavailable — the beforeunload guard still applies */ }
  }

  function markClean() {
    dirty = false;
    try { localStorage.removeItem(BACKUP_KEY); } catch (e) {}
  }

  window.addEventListener('beforeunload', function (e) {
    if (!dirty) return;
    e.preventDefault();
    e.returnValue = '';
  });

  // Offer recovered work when the last backup belongs to THIS document (same
  // slug, or both brand-new). DOM built with createElement/textContent only.
  (function offerRecovery() {
    var rawBak = null;
    try { rawBak = localStorage.getItem(BACKUP_KEY); } catch (e) {}
    if (!rawBak) return;
    var bak = null;
    try { bak = JSON.parse(rawBak); } catch (e2) { localStorage.removeItem(BACKUP_KEY); return; }
    if (!bak || !Array.isArray(bak.blocks) || !bak.blocks.length) {
      localStorage.removeItem(BACKUP_KEY);
      return;
    }
    if ((bak.slug || '') !== (slug || '')) return; // another document's leftover
    try {
      if (JSON.stringify(bak.blocks) === JSON.stringify(blocks)) { markClean(); return; }
    } catch (e3) {}
    dirty = true;
    var bar = document.createElement('div');
    bar.className = 'editor-recover';
    var msg = document.createElement('span');
    msg.className = 'editor-recover__msg';
    msg.textContent = 'Unsaved changes from an earlier session were found.';
    var restoreBtn = document.createElement('button');
    restoreBtn.type = 'button';
    restoreBtn.className = 'btn btn--sm btn--primary';
    restoreBtn.textContent = 'Restore';
    var discardBtn = document.createElement('button');
    discardBtn.type = 'button';
    discardBtn.className = 'btn btn--sm btn--ghost';
    discardBtn.textContent = 'Discard';
    restoreBtn.addEventListener('click', function () {
      blocks = bak.blocks;
      if (bak.title && titleEl && !titleEl.value.trim()) titleEl.value = bak.title;
      renderCanvas();
      commitNow();
      updateStats();
      bar.parentNode.removeChild(bar);
      setStatus('Recovered unsaved changes — remember to save', 'warn');
    });
    discardBtn.addEventListener('click', function () {
      markClean();
      if (bar.parentNode) bar.parentNode.removeChild(bar);
    });
    bar.appendChild(msg);
    bar.appendChild(restoreBtn);
    bar.appendChild(discardBtn);
    var mainEl = root.querySelector('.editor-main') || root;
    mainEl.insertBefore(bar, mainEl.firstChild);
  })();

  // ── Preview (modal + split live pane) ───────────────────────────────────────
  // The server returns UGC-sanitised HTML (blockrender). To display rendered
  // markup we must reinterpret a string as HTML — every sink is funnelled through
  // DOMPurify.sanitize; if DOMPurify is unavailable we degrade to inert text.
  function renderSanitized(target, rawHTML) {
    if (window.DOMPurify && typeof window.DOMPurify.sanitize === 'function') {
      target.innerHTML = window.DOMPurify.sanitize(rawHTML);
    } else {
      target.textContent = rawHTML;
    }
  }

  function fetchPreview() {
    return fetch('/os/api/editor/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      body: JSON.stringify({ blocks: blocks })
    }).then(function (r) { return r.json(); });
  }

  function preview() {
    if (htmlMode) { applyHTMLSource().then(doPreview).catch(function () { setStatus('Preview failed', 'danger'); }); return; }
    if (mdMode) { applyMDSource(); }
    doPreview();
  }
  function doPreview() {
    setStatus('Rendering preview…');
    fetchPreview().then(function (data) {
      renderSanitized(previewBody, data.html || '');
      previewModal.hidden = false;
      setStatus('Ready');
    }).catch(function () { setStatus('Preview failed', 'danger'); });
  }

  var splitOn = false, livePreviewTimer = null;
  function toggleSplit() {
    if (htmlMode) { exitHTMLMode(); }
    if (mdMode) { exitMDMode(); }
    splitOn = !splitOn;
    root.classList.toggle('is-split', splitOn);
    if (liveEl) liveEl.hidden = !splitOn;
    if (splitBtn) splitBtn.classList.toggle('is-active', splitOn);
    if (splitOn) renderLivePreview();
  }
  function scheduleLivePreview() {
    if (!splitOn) return;
    if (livePreviewTimer) clearTimeout(livePreviewTimer);
    livePreviewTimer = setTimeout(renderLivePreview, 500);
  }
  function renderLivePreview() {
    if (!liveBody) return;
    fetchPreview().then(function (data) {
      renderSanitized(liveBody, data.html || '');
    }).catch(function () {});
  }

  // ── Focus (distraction-free) mode ───────────────────────────────────────────
  var focusOn = false;
  function toggleFocus() {
    focusOn = !focusOn;
    root.classList.toggle('is-focus', focusOn);
    if (focusBtn) focusBtn.classList.toggle('is-active', focusOn);
    if (focusOn) scheduleTypewriter(); // recentre the caret line on entering
    else markActiveBlock(null);        // clear the spotlight on exit
  }

  // ── Typewriter scrolling ────────────────────────────────────────────────────
  // Engaged automatically in focus mode — the hallmark "zen writing" feel: the
  // line you're typing floats at the vertical middle of the canvas instead of
  // drifting to the bottom edge, so your eyes never move. Pure scroll math,
  // coalesced into one animation frame so rapid typing never thrashes layout.
  // Only acts on a COLLAPSED caret, so dragging a text selection is never
  // fought; only acts inside the canvas, so the command menu / modals are free.
  var typewriterRAF = 0, activeBlockEl = null;
  // markActiveBlock spotlights the block holding the caret and dims the rest —
  // the "current line glows, everything else recedes" companion to typewriter
  // scrolling. The `is-spotlight` root class gates the dimming so NOTHING is
  // dimmed until the caret is actually in a block (e.g. while editing the
  // title), avoiding a fully-greyed canvas.
  function markActiveBlock(el) {
    if (activeBlockEl === el) return;
    if (activeBlockEl) activeBlockEl.classList.remove('is-caret');
    activeBlockEl = el;
    if (el) el.classList.add('is-caret');
    root.classList.toggle('is-spotlight', !!el);
  }
  function typewriterCentre() {
    if (!focusOn || !canvas) return;
    var sel = document.getSelection();
    if (!sel || !sel.rangeCount || !sel.isCollapsed) return;
    var node = sel.anchorNode;
    if (!node || !canvas.contains(node)) return;
    var el = node.nodeType === 1 ? node : node.parentNode;
    while (el && el.parentNode !== canvas) el = el.parentNode; // nearest block child
    if (!el || el.parentNode !== canvas) return;
    markActiveBlock(el); // spotlight this line, dim the others
    // Only centre when the canvas is its own scroll container. On mobile the
    // page scrolls instead (canvas overflow-y: visible), so there is nothing to
    // move — the browser already keeps the caret above the keyboard.
    if (canvas.scrollHeight <= canvas.clientHeight) return;
    var cr = el.getBoundingClientRect(), vr = canvas.getBoundingClientRect();
    var delta = (cr.top + cr.height / 2) - (vr.top + vr.height / 2);
    if (Math.abs(delta) > 4) canvas.scrollTop += delta;
  }
  function scheduleTypewriter() {
    if (typewriterRAF) return;
    typewriterRAF = requestAnimationFrame(function () {
      typewriterRAF = 0;
      typewriterCentre();
    });
  }
  document.addEventListener('selectionchange', scheduleTypewriter);

  // ── HTML source mode (one-click round-trip) ────────────────────────────────
  // The HTML editor lets an operator edit the rendered HTML directly. Entering
  // it asks the server to render the current blocks to sanitised HTML; leaving
  // it parses that HTML back into blocks (server-side importer, which preserves
  // inline formatting as Markdown). A visual → HTML → visual round-trip is
  // therefore lossless for common formatting. Saving while in HTML mode applies
  // the source first so no edit is lost.
  var htmlMode = false, htmlBusy = false;
  function enterHTMLMode() {
    if (!htmlPanel || !htmlArea || htmlBusy) return;
    htmlBusy = true;
    setStatus('Loading HTML…');
    // HTML mode, Markdown mode and split preview are mutually exclusive.
    if (mdMode) exitMDMode();
    if (splitOn) toggleSplit();
    fetchPreview().then(function (data) {
      htmlArea.value = data.html || '';
      htmlMode = true;
      root.classList.add('is-html');
      htmlPanel.hidden = false;
      if (htmlBtn) { htmlBtn.classList.add('is-active'); htmlBtn.setAttribute('aria-pressed', 'true'); }
      setStatus('Editing HTML', 'ok');
      setTimeout(function () { htmlArea.focus(); }, 0);
      htmlBusy = false;
    }).catch(function () {
      setStatus('Could not load HTML', 'danger');
      htmlBusy = false;
    });
  }
  // applyHTMLSource parses the textarea HTML into blocks and returns a Promise
  // that resolves once `blocks` has been replaced. Used on exit and before save.
  function applyHTMLSource() {
    if (!htmlArea) return Promise.resolve();
    return fetch('/os/api/editor/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      body: JSON.stringify({ html: htmlArea.value })
    }).then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) {
        var next = (d && d.blocks) || [];
        blocks = (Array.isArray(next) && next.length) ? next : [{ type: 'paragraph', text: '' }];
      });
  }
  function exitHTMLMode() {
    if (!htmlMode || htmlBusy) { return Promise.resolve(); }
    htmlBusy = true;
    setStatus('Applying HTML…');
    return applyHTMLSource().then(function () {
      htmlMode = false;
      root.classList.remove('is-html');
      if (htmlPanel) htmlPanel.hidden = true;
      if (htmlBtn) { htmlBtn.classList.remove('is-active'); htmlBtn.setAttribute('aria-pressed', 'false'); }
      renderCanvas();
      commitNow();
      updateStats();
      scheduleAutosave();
      scheduleLivePreview();
      setStatus('Applied', 'ok');
      htmlBusy = false;
    }).catch(function () {
      setStatus('Could not parse HTML', 'danger');
      htmlBusy = false;
    });
  }
  function toggleHTML() {
    if (htmlMode) { exitHTMLMode(); } else { enterHTMLMode(); }
  }

  // ── Markdown source mode (whole-document round-trip) ───────────────────────
  // Like HTML mode, but the source of truth is Markdown. Entering serialises the
  // block document to Markdown; leaving parses it back into blocks. Standard
  // blocks (text, headings, lists, quotes, code, images, dividers) round-trip as
  // clean Markdown; rich blocks (galleries, embeds, tables, …) are carried in an
  // inert sentinel comment so NOTHING is ever lost in the round-trip.
  var mdBtn = root.querySelector('[data-editor-md-btn]');
  var mdPanel = root.querySelector('[data-editor-md-panel]');
  var mdArea = root.querySelector('[data-editor-md-area]');
  var mdMode = false;

  // Fixed heading-prefix table indexed by the clamped level 1..6 (index 0 unused)
  // — used instead of building the '#' run dynamically, so no input can size an
  // allocation.
  var HEADING_HASHES = ['', '#', '##', '###', '####', '#####', '######'];

  function mdSentinel(block) {
    return '<!--vp:' + encodeURIComponent(JSON.stringify(block)) + '-->';
  }
  function mdFromBlocks(list) {
    var out = [];
    (list || []).forEach(function (b) {
      switch (b.type) {
        case 'paragraph': out.push(b.text || ''); break;
        case 'heading': {
          var lvl = Math.min(Math.max(parseInt(b.level, 10) || 2, 1), 6);
          // Fixed lookup instead of new Array(n)/repeat(n): there is no dynamic
          // allocation sized by input at all, so a hostile block.level can never
          // drive a large allocation (resource exhaustion) — the value is one of
          // exactly six constant strings.
          out.push(HEADING_HASHES[lvl] + ' ' + (b.text || ''));
          break;
        }
        // Lists carry their kind in b.style ('ordered' | 'unordered'); the
        // legacy 'ordered' TYPE is an older shape kept for drafts saved before
        // the model was unified. Both must serialise a numbered list as "1." —
        // otherwise a numbered list the writer built round-trips out as bullets.
        case 'list':
          if (b.style === 'ordered') {
            out.push((b.items || []).map(function (it, i) { return (i + 1) + '. ' + it; }).join('\n'));
          } else {
            out.push((b.items || []).map(function (it) { return '- ' + it; }).join('\n'));
          }
          break;
        case 'ordered': out.push((b.items || []).map(function (it, i) { return (i + 1) + '. ' + it; }).join('\n')); break;
        case 'tasklist': out.push((b.items || []).map(function (it, i) {
          return '- [' + ((b.checked || [])[i] ? 'x' : ' ') + '] ' + it;
        }).join('\n')); break;
        case 'quote': out.push((b.text || '').split('\n').map(function (l) { return '> ' + l; }).join('\n')); break;
        case 'divider': out.push('---'); break;
        case 'code': out.push('```' + (b.lang || '') + '\n' + (b.text || '') + '\n```'); break;
        case 'markdown': out.push(b.text || ''); break;
        case 'html': out.push(b.text || ''); break;
        case 'image': {
          // Plain images become pure Markdown; captioned/sized ones keep their
          // extras via the sentinel so the round-trip stays lossless.
          if ((b.caption || '') === '' && (b.width || '') === '') {
            out.push('![' + (b.alt || '') + '](' + (b.url || '') + ')');
          } else {
            out.push(mdSentinel(b));
          }
          break;
        }
        default: out.push(mdSentinel(b));
      }
    });
    return out.join('\n\n') + '\n';
  }

  function blocksFromMD(src) {
    var lines = String(src || '').replace(/\r\n?/g, '\n').split('\n');
    var out = [];
    var para = [];
    function flushPara() {
      if (!para.length) return;
      var text = para.join('\n').trim();
      para = [];
      if (!text) return;
      var sm = text.match(/^<!--vp:([^>]*)-->$/);
      if (sm) {
        try { out.push(JSON.parse(decodeURIComponent(sm[1]))); return; } catch (e) { /* fall through as text */ }
      }
      if (text.charAt(0) === '<') { out.push({ type: 'html', text: text }); return; }
      out.push({ type: 'paragraph', text: text });
    }
    var i = 0;
    while (i < lines.length) {
      var line = lines[i];
      var m;
      if (/^\s*$/.test(line)) { flushPara(); i++; continue; }
      // Fenced code
      if ((m = line.match(/^```(\S*)\s*$/)) && !para.length) {
        var lang = m[1] || '';
        var buf = [];
        i++;
        while (i < lines.length && !/^```\s*$/.test(lines[i])) { buf.push(lines[i]); i++; }
        i++; // closing fence
        out.push({ type: 'code', lang: lang, text: buf.join('\n') });
        continue;
      }
      // Heading
      if ((m = line.match(/^(#{1,6})\s+(.*)$/)) && !para.length) {
        flushPara();
        out.push({ type: 'heading', level: m[1].length, text: m[2] });
        i++; continue;
      }
      // Divider
      if (/^(-{3,}|\*{3,}|_{3,})\s*$/.test(line) && !para.length) {
        flushPara(); out.push({ type: 'divider' }); i++; continue;
      }
      // Image on its own line
      if ((m = line.match(/^!\[([^\]]*)\]\(([^)\s]+)\)\s*$/)) && !para.length) {
        flushPara(); out.push({ type: 'image', url: m[2], alt: m[1] }); i++; continue;
      }
      // Task list
      if (/^[-*+]\s+\[( |x|X)\]\s+/.test(line) && !para.length) {
        var titems = [], tchecked = [];
        while (i < lines.length && (m = lines[i].match(/^[-*+]\s+\[( |x|X)\]\s+(.*)$/))) {
          titems.push(m[2]); tchecked.push(/x/i.test(m[1])); i++;
        }
        out.push({ type: 'tasklist', items: titems, checked: tchecked });
        continue;
      }
      // Bullet list
      if (/^[-*+]\s+/.test(line) && !para.length) {
        var bitems = [];
        while (i < lines.length && (m = lines[i].match(/^[-*+]\s+(.*)$/))) { bitems.push(m[1]); i++; }
        out.push({ type: 'list', items: bitems });
        continue;
      }
      // Ordered list — use the canonical { type:'list', style:'ordered' } shape
      // that the palette, autoformat and paste all produce, so there is exactly
      // one representation of a numbered list across load / create / serialise.
      if (/^\d+[.)]\s+/.test(line) && !para.length) {
        var oitems = [];
        while (i < lines.length && (m = lines[i].match(/^\d+[.)]\s+(.*)$/))) { oitems.push(m[1]); i++; }
        out.push({ type: 'list', style: 'ordered', items: oitems });
        continue;
      }
      // Quote
      if (/^>\s?/.test(line) && !para.length) {
        var qlines = [];
        while (i < lines.length && /^>\s?/.test(lines[i])) { qlines.push(lines[i].replace(/^>\s?/, '')); i++; }
        out.push({ type: 'quote', text: qlines.join('\n') });
        continue;
      }
      para.push(line);
      i++;
    }
    flushPara();
    return out.length ? out : [{ type: 'paragraph', text: '' }];
  }

  function enterMDMode() {
    if (!mdPanel || !mdArea || mdMode) return;
    // Leaving HTML mode parses the source asynchronously — wait for the blocks
    // to be up to date before serialising them to Markdown.
    if (htmlMode) { exitHTMLMode().then(enterMDMode); return; }
    if (splitOn) toggleSplit();
    mdArea.value = mdFromBlocks(blocks);
    mdMode = true;
    root.classList.add('is-html');
    mdPanel.hidden = false;
    if (mdBtn) { mdBtn.classList.add('is-active'); mdBtn.setAttribute('aria-pressed', 'true'); }
    setStatus('Editing Markdown', 'ok');
    setTimeout(function () { mdArea.focus(); }, 0);
  }
  function applyMDSource() {
    if (!mdArea) return;
    blocks = blocksFromMD(mdArea.value);
  }
  function exitMDMode() {
    if (!mdMode) return;
    applyMDSource();
    mdMode = false;
    root.classList.remove('is-html');
    if (mdPanel) mdPanel.hidden = true;
    if (mdBtn) { mdBtn.classList.remove('is-active'); mdBtn.setAttribute('aria-pressed', 'false'); }
    renderCanvas();
    commitNow();
    updateStats();
    scheduleAutosave();
    scheduleLivePreview();
    setStatus('Applied', 'ok');
  }
  function toggleMD() {
    if (mdMode) { exitMDMode(); } else { enterMDMode(); }
  }

  // ── Post settings panel (publishing options) ────────────────────────────────
  // A slide-out drawer for everything that is not the post body: feature image,
  // URL slug, publish date, excerpt, tags, SEO meta, social cards, and the
  // featured / page flags. Values hydrate from the <script id="vp-editor-meta">
  // document and are sent back inside the save payload (tags + publishDate +
  // meta). The slug is renamed out-of-band via /os/api/editor/slug so it never
  // races the queued content write.
  var settingsBtn = root.querySelector('[data-editor-settings-btn]');
  var settingsPanel = root.querySelector('[data-editor-settings]');
  var settingsBackdrop = root.querySelector('[data-editor-settings-backdrop]');
  var settingsClose = root.querySelector('[data-editor-settings-close]');
  var pm = {};
  ['feature-image', 'feature-preview', 'feature-empty', 'feature-upload', 'feature-remove', 'feature-file',
    'slug', 'slug-apply', 'slug-prefix', 'slug-status', 'publish-date', 'excerpt', 'excerpt-count',
    'tags-input', 'tags-list', 'featured', 'is-page', 'author',
    'meta-title', 'meta-title-count', 'meta-description', 'meta-description-count', 'canonical',
    'og-title', 'og-description', 'og-image', 'twitter-title', 'twitter-description', 'twitter-image'
  ].forEach(function (k) { pm[k] = root.querySelector('[data-pm-' + k + ']'); });
  var pmTags = [];
  var metaHydrated = false;

  function pmVal(el) { return el ? (el.value || '') : ''; }
  function pmSet(el, v) { if (el) el.value = v == null ? '' : String(v); }

  function hydrateSettings() {
    var el = document.getElementById('vp-editor-meta');
    if (!el) return;
    var data = {};
    try { data = JSON.parse(el.textContent.trim() || '{}'); } catch (e) { data = {}; }
    metaHydrated = true;
    pmTags = Array.isArray(data.tags) ? data.tags.slice() : [];
    pmSet(pm['excerpt'], data.excerpt);
    pmSet(pm['feature-image'], data.featureImage);
    pmSet(pm['meta-title'], data.metaTitle);
    pmSet(pm['meta-description'], data.metaDescription);
    pmSet(pm['canonical'], data.canonicalURL);
    pmSet(pm['og-title'], data.ogTitle);
    pmSet(pm['og-description'], data.ogDescription);
    pmSet(pm['og-image'], data.ogImage);
    pmSet(pm['twitter-title'], data.twitterTitle);
    pmSet(pm['twitter-description'], data.twitterDescription);
    pmSet(pm['twitter-image'], data.twitterImage);
    pmSet(pm['publish-date'], data.publishDate);
    pmSet(pm['slug'], data.slug || slug);
    if (pm['featured']) pm['featured'].checked = !!data.featured;
    if (pm['is-page']) pm['is-page'].checked = !!data.isPage;
    if (pm['author'] && data.authorId) pmSet(pm['author'], data.authorId);
    // The meta document carries the row's lifecycle state — surface it in the
    // topbar (Wave 1: the editor previously hid status entirely).
    applyPostStatus(typeof data.status === 'string' ? data.status : '', false);
    syncSlugUI();
    updateFeaturePreview();
    renderTags();
    updateCounters();
  }

  // collectMeta mirrors the server PostMeta JSON tags.
  function collectMeta() {
    return {
      excerpt: pmVal(pm['excerpt']),
      featureImage: pmVal(pm['feature-image']),
      metaTitle: pmVal(pm['meta-title']),
      metaDescription: pmVal(pm['meta-description']),
      canonicalURL: pmVal(pm['canonical']),
      ogTitle: pmVal(pm['og-title']),
      ogDescription: pmVal(pm['og-description']),
      ogImage: pmVal(pm['og-image']),
      twitterTitle: pmVal(pm['twitter-title']),
      twitterDescription: pmVal(pm['twitter-description']),
      twitterImage: pmVal(pm['twitter-image']),
      featured: !!(pm['featured'] && pm['featured'].checked),
      isPage: !!(pm['is-page'] && pm['is-page'].checked),
      authorId: pmVal(pm['author'])
    };
  }

  function updateCounters() {
    if (pm['excerpt'] && pm['excerpt-count']) pm['excerpt-count'].textContent = String(pmVal(pm['excerpt']).length);
    if (pm['meta-title'] && pm['meta-title-count']) pm['meta-title-count'].textContent = String(pmVal(pm['meta-title']).length);
    if (pm['meta-description'] && pm['meta-description-count']) pm['meta-description-count'].textContent = String(pmVal(pm['meta-description']).length);
    updateSeoSnippet();
  }

  // Live Google-result preview. Mirrors the renderer's fallback chain: SEO title
  // → post title; SEO description → excerpt. URL uses the current slug.
  var seoSnip = {
    box: root.querySelector('[data-seo-snippet]'),
    url: root.querySelector('[data-seo-snippet-url]'),
    title: root.querySelector('[data-seo-snippet-title]'),
    desc: root.querySelector('[data-seo-snippet-desc]'),
  };
  function clip(s, n) { s = (s || '').trim(); return s.length > n ? s.slice(0, n - 1).trim() + '…' : s; }
  function updateSeoSnippet() {
    if (!seoSnip.box) return;
    var title = pmVal(pm['meta-title']).trim() || (titleEl ? titleEl.value.trim() : '') || 'Untitled post';
    var desc = pmVal(pm['meta-description']).trim() || pmVal(pm['excerpt']).trim() || 'Add an SEO description or excerpt to control this text.';
    var s = pmVal(pm['slug']).trim() || (slug || '');
    var base = window.location.origin.replace(/^https?:\/\//, '');
    seoSnip.url.textContent = base + ' › ' + (s || '…');
    seoSnip.title.textContent = clip(title, 60);
    seoSnip.desc.textContent = clip(desc, 160);
  }

  function updateFeaturePreview() {
    var url = pmVal(pm['feature-image']).trim();
    if (pm['feature-preview']) {
      var safe = safeImgSrc(url);
      if (safe) { pm['feature-preview'].src = safe; pm['feature-preview'].hidden = false; }
      else { pm['feature-preview'].hidden = true; pm['feature-preview'].removeAttribute('src'); }
    }
    if (pm['feature-empty']) pm['feature-empty'].hidden = !!url;
  }

  function uploadFeatureImage(file) {
    var fd = new FormData();
    fd.append('file', file);
    setStatus('Uploading image…');
    fetch('/os/api/media/upload', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken() }, body: fd })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) {
        if (d && d.url) { pmSet(pm['feature-image'], d.url); updateFeaturePreview(); setStatus('Feature image set', 'ok'); scheduleAutosave(); }
        else setStatus('Upload failed', 'danger');
      }).catch(function () { setStatus('Feature image upload failed', 'danger'); });
  }

  // Tags chip editor.
  function renderTags() {
    if (!pm['tags-list']) return;
    while (pm['tags-list'].firstChild) pm['tags-list'].removeChild(pm['tags-list'].firstChild);
    pmTags.forEach(function (t, i) {
      var chip = document.createElement('span');
      chip.className = 'pm-tag';
      var label = document.createElement('span');
      label.textContent = t;
      var x = document.createElement('button');
      x.type = 'button';
      x.className = 'pm-tag-x';
      x.textContent = '×';
      x.setAttribute('aria-label', 'Remove tag ' + t);
      x.addEventListener('click', function () { pmTags.splice(i, 1); renderTags(); scheduleAutosave(); });
      chip.appendChild(label);
      chip.appendChild(x);
      pm['tags-list'].appendChild(chip);
    });
  }
  function addTagsFromInput() {
    if (!pm['tags-input']) return;
    var raw = pm['tags-input'].value || '';
    raw.split(',').forEach(function (part) {
      part = part.trim();
      if (part && pmTags.indexOf(part) < 0) pmTags.push(part);
    });
    pm['tags-input'].value = '';
    renderTags();
    scheduleAutosave();
  }

  // Slug rename (out-of-band; only for saved posts).
  function syncSlugUI() {
    var saved = !!slug;
    if (pm['slug-apply']) pm['slug-apply'].disabled = !saved;
    if (pm['slug-status']) {
      pm['slug-status'].textContent = saved
        ? 'Changing the URL updates every link to this post.'
        : 'The slug is set automatically from the title on first save.';
    }
  }
  function applySlug() {
    if (!slug) { setStatus('Save the post before changing its URL', 'warn'); return; }
    var next = (pmVal(pm['slug']) || '').trim();
    if (!next || next === slug) return;
    setStatus('Updating URL…');
    fetch('/os/api/editor/slug', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      body: JSON.stringify({ slug: slug, newSlug: next })
    }).then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) {
        if (d && d.slug) {
          slug = d.slug;
          if (root) root.setAttribute('data-slug', slug);
          pmSet(pm['slug'], slug);
          try { history.replaceState({}, '', '/os/editor/' + encodeURIComponent(slug)); } catch (e) {}
          setStatus('URL updated · /' + slug, 'ok');
        }
      }).catch(function () { setStatus('Could not update URL', 'danger'); });
  }

  function openSettings() {
    if (!settingsPanel) return;
    settingsPanel.hidden = false;
    if (settingsBackdrop) settingsBackdrop.hidden = false;
    root.classList.add('is-settings');
    if (settingsBtn) { settingsBtn.classList.add('is-active'); settingsBtn.setAttribute('aria-pressed', 'true'); }
  }
  function closeSettings() {
    if (!settingsPanel) return;
    settingsPanel.hidden = true;
    if (settingsBackdrop) settingsBackdrop.hidden = true;
    root.classList.remove('is-settings');
    if (settingsBtn) { settingsBtn.classList.remove('is-active'); settingsBtn.setAttribute('aria-pressed', 'false'); }
  }
  function toggleSettings() {
    if (settingsPanel && settingsPanel.hidden) openSettings(); else closeSettings();
  }

  // ── Inline formatting toolbar (floating on text selection) ──────────────────
  var fmtBar = null;
  function fmtTarget() {
    var el = document.activeElement;
    if (!el || !canvas.contains(el)) return null;
    if (el.tagName === 'TEXTAREA' && el.classList.contains('eblock__text') && !el.classList.contains('eblock__code')) return el;
    if (el.tagName === 'INPUT' && el.classList.contains('eblock__heading')) return el;
    return null;
  }
  // wrapSelection here was a SECOND declaration that hoisted over the canonical
  // one at the top of the file, silently dropping its isLink support — which is
  // how the documented ⌘K link flow broke (Wave 1 finding E8). Deleted; the
  // floating toolbar's calls work unchanged against the canonical signature.

  function applyLink(el) {
    var s = el.selectionStart, e = el.selectionEnd, val = el.value;
    var sel = val.slice(s, e) || 'link text';
    var insert = '[' + sel + '](url)';
    el.value = val.slice(0, s) + insert + val.slice(e);
    var urlStart = s + ('[' + sel + '](').length;
    el.setSelectionRange(urlStart, urlStart + 3);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.focus();
  }
  function buildFmtBar() {
    var bar = document.createElement('div');
    bar.className = 'fmt-bar';
    var defs = [
      { label: 'B', title: 'Bold', cls: 'fmt-bar__btn--b', fn: function (el) { wrapSelection(el, '**', '**'); } },
      { label: 'i', title: 'Italic', cls: 'fmt-bar__btn--i', fn: function (el) { wrapSelection(el, '*', '*'); } },
      { label: '</>', title: 'Inline code', cls: '', fn: function (el) { wrapSelection(el, '`', '`'); } },
      { label: 'S', title: 'Strikethrough', cls: 'fmt-bar__btn--s', fn: function (el) { wrapSelection(el, '~~', '~~'); } },
      { label: '🔗', title: 'Link', cls: '', fn: function (el) { applyLink(el); } }
    ];
    defs.forEach(function (d) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'fmt-bar__btn ' + d.cls;
      b.title = d.title;
      b.textContent = d.label;
      b.addEventListener('mousedown', function (e) { e.preventDefault(); });
      b.addEventListener('click', function (e) {
        e.preventDefault();
        var el = fmtTarget() || lastFmtEl;
        if (el) d.fn(el);
        positionFmtBar(el);
      });
      bar.appendChild(b);
    });
    return bar;
  }
  var lastFmtEl = null;
  function positionFmtBar(el) {
    if (!fmtBar || !el) return;
    var r = el.getBoundingClientRect();
    fmtBar.style.top = (window.scrollY + r.top - fmtBar.offsetHeight - 8) + 'px';
    fmtBar.style.left = (window.scrollX + r.left + 8) + 'px';
  }
  function maybeShowFmtBar() {
    var el = fmtTarget();
    var hasSel = el && el.selectionStart !== el.selectionEnd;
    if (!hasSel) { hideFmtBar(); return; }
    lastFmtEl = el;
    if (!fmtBar) { fmtBar = buildFmtBar(); document.body.appendChild(fmtBar); }
    fmtBar.style.display = 'flex';
    positionFmtBar(el);
  }
  function hideFmtBar() { if (fmtBar) fmtBar.style.display = 'none'; }
  document.addEventListener('mouseup', function () { setTimeout(maybeShowFmtBar, 0); });
  document.addEventListener('keyup', function (e) {
    if (e.shiftKey || e.key === 'ArrowLeft' || e.key === 'ArrowRight' || e.key === 'ArrowUp' || e.key === 'ArrowDown') {
      setTimeout(maybeShowFmtBar, 0);
    }
  });
  document.addEventListener('scroll', hideFmtBar, true);

  // ── Image paste / drop upload ──────────────────────────────────────────────
  function focusedBlockIdx() {
    var el = document.activeElement;
    if (!el || !canvas.contains(el)) return blocks.length;
    var wrap = el.closest ? el.closest('[data-block-idx]') : null;
    if (!wrap) return blocks.length;
    var i = parseInt(wrap.getAttribute('data-block-idx'), 10);
    return isNaN(i) ? blocks.length : i + 1;
  }
  function uploadImageFile(file, insertAt) {
    var fd = new FormData();
    fd.append('file', file);
    setStatus('Uploading image…');
    fetch('/os/api/media/upload', {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken() },
      body: fd
    }).then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) {
        if (d && d.url) {
          insertBlock(insertAt, { type: 'image', url: d.url, alt: '' });
          setStatus('Image inserted', 'ok');
        } else { setStatus('Upload failed', 'danger'); }
      }).catch(function () { setStatus('Image upload failed', 'danger'); });
  }
  canvas.addEventListener('paste', function (e) {
    var items = (e.clipboardData && e.clipboardData.items) || [];
    for (var i = 0; i < items.length; i++) {
      if (items[i].type && items[i].type.indexOf('image/') === 0) {
        var f = items[i].getAsFile();
        if (f) { e.preventDefault(); uploadImageFile(f, focusedBlockIdx()); }
      }
    }
  });
  canvas.addEventListener('dragover', function (e) {
    if (e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types || [], 'Files') >= 0) {
      e.preventDefault();
      canvas.classList.add('is-dragover');
    }
  });
  canvas.addEventListener('dragleave', function () { canvas.classList.remove('is-dragover'); });
  canvas.addEventListener('drop', function (e) {
    canvas.classList.remove('is-dragover');
    var files = (e.dataTransfer && e.dataTransfer.files) || [];
    var imgs = [];
    for (var i = 0; i < files.length; i++) {
      if (files[i].type && files[i].type.indexOf('image/') === 0) imgs.push(files[i]);
    }
    if (imgs.length) {
      e.preventDefault();
      var at = blocks.length;
      imgs.forEach(function (f) { uploadImageFile(f, at++); });
    }
  });

  // ── Wire up ────────────────────────────────────────────────────────────────
  hydrate();
  renderCanvas();
  commitNow();
  updateStats();

  if (saveBtn) saveBtn.addEventListener('click', save);
  if (previewBtn) previewBtn.addEventListener('click', preview);

  // ── Share draft (Wave 4.4) ────────────────────────────────────────────────
  // Mints a signed 48-hour preview link through the console endpoint and puts
  // it on the clipboard. The post stays a draft: the link is the product, so
  // the URL itself is shown in the toast when the clipboard is unavailable.
  var shareBtn = root.querySelector('[data-editor-share-btn]');
  if (shareBtn) {
    shareBtn.addEventListener('click', function () {
      shareBtn.disabled = true;
      fetch('/os/api/posts/' + encodeURIComponent(slug) + '/share', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrfToken() },
        body: '{}',
      })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (res) {
          shareBtn.disabled = false;
          if (!res.ok) {
            var why = (res.d && (res.d.detail || res.d.title)) || 'Could not create a share link';
            if (window.vpToast) window.vpToast(why, 'error');
            return;
          }
          var url = res.d.url || '';
          var done = function () {
            if (window.vpToast) window.vpToast('Preview link copied — valid 48 hours, the post stays a draft.', 'ok');
          };
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(url).then(done, function () {
              if (window.vpToast) window.vpToast('Share link: ' + url, 'ok');
            });
          } else {
            if (window.vpToast) window.vpToast('Share link: ' + url, 'ok');
          }
        })
        .catch(function () { shareBtn.disabled = false; if (window.vpToast) window.vpToast('Network error', 'error'); });
    });
  }

  // ── Device toggles (Wave 4.4) ─────────────────────────────────────────────
  // The live preview can pretend to be a phone or a tablet, so an operator
  // sees the responsive truth before publishing instead of after.
  var livePane = root.querySelector('[data-editor-live]');
  var liveHead = livePane ? livePane.querySelector('.editor-live-head') : null;
  if (livePane && liveHead && !liveHead.querySelector('[data-device]')) {
    var devWrap = document.createElement('span');
    devWrap.className = 'editor-devices';
    var setDevice = function (d) {
      livePane.setAttribute('data-device', d);
      Array.prototype.forEach.call(devWrap.children, function (b) {
        b.setAttribute('aria-pressed', b.getAttribute('data-device') === d ? 'true' : 'false');
      });
    };
    [['desktop', '🖥', 'Desktop'], ['tablet', '▭', 'Tablet'], ['mobile', '▯', 'Phone']].forEach(function (d) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'editor-devices__btn';
      b.setAttribute('data-device', d[0]);
      b.setAttribute('aria-pressed', d[0] === 'desktop' ? 'true' : 'false');
      b.title = 'Preview at ' + d[2].toLowerCase() + ' width';
      b.textContent = d[1];
      b.addEventListener('click', function () { setDevice(d[0]); });
      devWrap.appendChild(b);
    });
    liveHead.appendChild(devWrap);
    setDevice('desktop');
  }

  // ── Direct image upload (toolbar) ──────────────────────────────────────────
  // A first-class "Image" button: pick a file, upload it to /media, and insert
  // the image block at the caret — no visit to the media library required.
  var imageBtn = root.querySelector('[data-editor-image-btn]');
  var imageFileInput = document.createElement('input');
  imageFileInput.type = 'file';
  imageFileInput.accept = 'image/png,image/jpeg,image/gif,image/webp';
  imageFileInput.hidden = true;
  document.body.appendChild(imageFileInput);
  imageFileInput.addEventListener('change', function () {
    var f = imageFileInput.files && imageFileInput.files[0];
    // focusedBlockIdx() already returns the slot directly below the caret block,
    // so insert there (matching the paste path) — no extra offset.
    if (f) uploadImageFile(f, focusedBlockIdx());
    imageFileInput.value = '';
  });
  if (imageBtn) imageBtn.addEventListener('click', function () { imageFileInput.click(); });

  // ── AI: write a draft from a prompt ────────────────────────────────────────
  var aiBtn = root.querySelector('[data-editor-ai-btn]');
  var aiModal = root.querySelector('[data-editor-ai-modal]');
  var aiProvidersLoaded = false;
  function aiQ(sel) { return aiModal ? aiModal.querySelector(sel) : null; }
  function openAIModal() {
    if (!aiModal) return;
    aiModal.hidden = false;
    var p = aiQ('[data-ai-prompt]');
    if (p) p.focus();
    if (!aiProvidersLoaded) loadAIProviders();
  }
  function closeAIModal() { if (aiModal) aiModal.hidden = true; }
  function loadAIProviders() {
    var sel = aiQ('[data-ai-provider]'), msg = aiQ('[data-ai-msg]');
    var modelEl = aiQ('[data-ai-model]'), runBtn = aiQ('[data-ai-run]');
    if (!sel) return;
    fetch('/os/api/editor/ai-providers', { headers: { 'X-CSRF-Token': csrfToken() } })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        aiProvidersLoaded = true;
        while (sel.firstChild) sel.removeChild(sel.firstChild);
        var provs = (d && d.providers) || [];
        if (!provs.length) {
          var o = document.createElement('option');
          o.value = ''; o.textContent = 'No provider configured';
          sel.appendChild(o); sel.disabled = true;
          if (runBtn) runBtn.disabled = true;
          aiEngineChip(false, 'not configured');
          aiSay(msg, 'Add a local Ollama endpoint, or an OpenAI / OpenRouter API key, in VayuOS \u2192 API Keys to enable AI writing.', 'err');
          return;
        }
        sel.disabled = false;
        if (runBtn) runBtn.disabled = false;
        provs.forEach(function (p) {
          var o = document.createElement('option');
          o.value = p.id; o.textContent = p.label;
          o.setAttribute('data-default-model', p.defaultModel || '');
          sel.appendChild(o);
        });
        sel.addEventListener('change', function () { loadAIModels(sel.value); aiEngineSummary(); });
        loadAIModels(sel.value);
        aiEngineSummary();
      })
      .catch(function () {
        aiEngineChip(false, 'unavailable');
        aiSay(msg, 'Could not load AI providers.', 'err');
      });
  }
  // aiEngineChip / aiEngineSummary keep the collapsed "Model & provider" row
  // truthful: which provider is selected, or that none is usable. Without this the
  // summary claims nothing and the author has to open it to find out.
  function aiEngineChip(ok, label) {
    var chip = aiQ('[data-ai-engine-chip]');
    if (!chip) return;
    chip.className = 'mon-chip ' + (ok ? 'mon-chip--on' : 'mon-chip--off');
    chip.textContent = (ok ? '\u25CF ' : '\u25CB ') + label;
  }
  function aiEngineSummary() {
    var sel = aiQ('[data-ai-provider]'), sub = aiQ('[data-ai-engine-sub]');
    if (!sel) return;
    var label = sel.options[sel.selectedIndex] ? sel.options[sel.selectedIndex].textContent : '';
    aiEngineChip(!!sel.value, label || 'none');
    var modelEl = aiQ('[data-ai-model]');
    var m = modelEl && modelEl.value.trim();
    if (sub) sub.textContent = m ? (label + ' \u00B7 ' + m) : (label || 'Which model writes it');
  }

  // loadAIModels fills the model dropdown with the chosen provider's catalogue
  // (fetched live, curated fallback) and keeps the custom text box in sync.
  function loadAIModels(provider) {
    var modelSel = aiQ('[data-ai-model-select]'), modelEl = aiQ('[data-ai-model]');
    if (!modelSel) return;
    while (modelSel.firstChild) modelSel.removeChild(modelSel.firstChild);
    var loading = document.createElement('option');
    loading.value = ''; loading.textContent = 'Loading models…';
    modelSel.appendChild(loading);
    fetch('/os/api/editor/ai-models?provider=' + encodeURIComponent(provider || ''), { headers: { 'X-CSRF-Token': csrfToken() } })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        while (modelSel.firstChild) modelSel.removeChild(modelSel.firstChild);
        var def = (d && d.default) || '';
        var first = document.createElement('option');
        first.value = ''; first.textContent = def ? ('Provider default (' + def + ')') : 'Type a model below…';
        modelSel.appendChild(first);
        var models = (d && d.models) || [];
        models.forEach(function (m) {
          var o = document.createElement('option');
          o.value = m; o.textContent = m;
          modelSel.appendChild(o);
        });
        if (modelEl) modelEl.placeholder = def || 'Model name required';
        // A warning here means the catalogue loaded but the provider already told
        // us generation will fail — a rejected key, or no credit. Surfacing it now
        // beats waiting for the author to write a prompt and lose it.
        if (d && d.warning) {
          aiSay(aiQ('[data-ai-msg]'), d.warning, 'err');
          aiEngineChip(false, 'key rejected');
        }
      })
      .catch(function () {
        while (modelSel.firstChild) modelSel.removeChild(modelSel.firstChild);
        var o = document.createElement('option');
        o.value = ''; o.textContent = 'Type a model below…';
        modelSel.appendChild(o);
      });
  }
  function insertGeneratedBlocks(newBlocks) {
    // Use the first heading as the post title when the title is still empty.
    if (titleEl && !titleEl.value.trim() && newBlocks[0] && newBlocks[0].type === 'heading' && newBlocks[0].text) {
      titleEl.value = String(newBlocks[0].text);
      updateStats();
      newBlocks = newBlocks.slice(1);
    }
    // Replace a lone empty starter paragraph rather than leaving it above the draft.
    var at = blocks.length;
    if (blocks.length === 1 && blocks[0].type === 'paragraph' && !((blocks[0].text || '').trim())) {
      blocks = []; at = 0;
    }
    // Insert the whole draft in ONE splice + structural() so the canvas rebuilds
    // once and the draft is a single "undo" step (not one per block).
    var valid = newBlocks.filter(function (b) { return b && b.type; });
    if (!valid.length) return;
    if (at < 0) at = 0;
    if (at > blocks.length) at = blocks.length;
    blocks.splice.apply(blocks, [at, 0].concat(valid));
    structural();
  }
  // aiShapeOptions reads the shaping controls. Anything left at its default
  // contributes nothing, so an author who ignores this panel gets exactly the
  // provider's own behaviour rather than our opinion of it.
  function aiShapeOptions() {
    var o = {};
    var shape = aiQ('[data-ai-shape]'), tone = aiQ('[data-ai-tone]');
    var len = aiQ('[data-ai-length]'), words = aiQ('[data-ai-words]');
    var aud = aiQ('[data-ai-audience]'), lang = aiQ('[data-ai-language]');
    var kw = aiQ('[data-ai-keyword]');
    var temp = aiQ('[data-ai-temp]');
    if (shape && shape.value) o.shape = shape.value;
    if (tone && tone.value) o.tone = tone.value;
    if (len && len.value === 'exact') {
      var n = parseInt(words && words.value, 10);
      if (n > 0) o.max_words = n;
    } else if (len && len.value) {
      o.length = len.value;
    }
    if (aud && aud.value.trim()) o.audience = aud.value.trim();
    if (lang && lang.value.trim()) o.language = lang.value.trim();
    if (kw && kw.value.trim()) o.keyword = kw.value.trim();
    // The slider is 0..20; 0 means "send nothing".
    if (temp) {
      var t = parseInt(temp.value, 10);
      if (t > 0) o.temperature = t / 10;
    }
    return o;
  }
  // aiCountShapeChanges drives the summary chip so the author can see at a glance
  // that this draft is being shaped, without opening the section.
  function aiRefreshShapeChip() {
    var chip = aiQ('[data-ai-shape-chip]');
    if (!chip) return;
    var o = aiShapeOptions();
    var n = 0, k;
    for (k in o) { if (Object.prototype.hasOwnProperty.call(o, k)) { if (k !== 'shape' || o[k] !== 'post') n++; } }
    if (n > 0) {
      chip.className = 'mon-chip mon-chip--on';
      chip.textContent = '\u25CF ' + n + (n === 1 ? ' setting' : ' settings');
    } else {
      chip.className = 'mon-chip mon-chip--off';
      chip.textContent = '\u25CB defaults';
    }
  }
  function runAIGenerate() {
    var promptEl = aiQ('[data-ai-prompt]'), sel = aiQ('[data-ai-provider]');
    var modelEl = aiQ('[data-ai-model]'), msg = aiQ('[data-ai-msg]'), runBtn = aiQ('[data-ai-run]');
    var prompt = promptEl ? promptEl.value.trim() : '';
    if (!prompt) {
      aiSay(msg, 'Enter a prompt first.', 'err');
      if (promptEl) promptEl.focus();
      return;
    }
    var provider = sel ? sel.value : '';
    var model = modelEl ? modelEl.value.trim() : '';
    var payload = aiShapeOptions();
    payload.prompt = prompt;
    payload.provider = provider;
    payload.model = model;
    if (runBtn) { runBtn.disabled = true; runBtn.textContent = 'Writing…'; }
    aiSay(msg, 'Starting… large models can take several minutes.', 'busy');
    // Start the job. The reply is immediate; the draft arrives by polling, so no
    // proxy in front of VayuPress ever has a long request to time out.
    fetch('/os/api/editor/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      body: JSON.stringify(payload)
    }).then(readJSON).then(function (res) {
      if (!res.ok || !res.d || !res.d.job) {
        aiDone(runBtn);
        aiSay(msg, apiErrText(res.d, res.status), 'err');
        return;
      }
      aiPollJob(res.d.job, msg, runBtn, promptEl, Date.now());
    }).catch(function () {
      aiDone(runBtn);
      aiSay(msg, 'Could not reach the server. Check your connection and try again.', 'err');
    });
  }
  // readJSON parses a response without assuming it is JSON. A proxy error page is
  // HTML, and treating that as JSON is what produced "[object Object]" and bare
  // status codes on the old synchronous path.
  function readJSON(r) {
    return r.text().then(function (t) {
      var d = null;
      try { d = t ? JSON.parse(t) : null; } catch (e) { d = null; }
      return { ok: r.ok, status: r.status, d: d, raw: t };
    });
  }
  function aiDone(runBtn) {
    if (runBtn) { runBtn.disabled = false; runBtn.textContent = 'Generate draft'; }
  }
  // aiPollJob waits for a generation to finish, reporting elapsed time so a long
  // wait looks like progress rather than a hang.
  function aiPollJob(job, msg, runBtn, promptEl, startedAt) {
    // A minute beyond the server's own 10-minute job budget, so the server's
    // specific message wins the race rather than this generic give-up.
    var deadline = startedAt + 11 * 60 * 1000;
    function tick() {
      if (Date.now() > deadline) {
        aiDone(runBtn);
        aiSay(msg, 'Gave up waiting for this draft. The model may still be queued — try a smaller model, or a shorter length.', 'err');
        return;
      }
      fetch('/os/api/editor/generate/status?job=' + encodeURIComponent(job), {
        headers: { 'X-CSRF-Token': csrfToken() }
      }).then(readJSON).then(function (res) {
        if (!res.ok) {
          aiDone(runBtn);
          aiSay(msg, apiErrText(res.d, res.status), 'err');
          return;
        }
        var d = res.d || {};
        if (d.status === 'pending') {
          var secs = d.elapsed_seconds || Math.round((Date.now() - startedAt) / 1000);
          // "Queued" is this install being busy; "writing" is the provider working.
          // Saying which is which stops a queue looking like a hang.
          var what = d.queued ? 'Queued behind other drafts' : 'Writing your draft';
          aiSay(msg, what + '… ' + secs + 's elapsed. Large models can take several minutes — you can leave this open.', 'busy');
          setTimeout(tick, 2000);
          return;
        }
        aiDone(runBtn);
        if (d.status === 'error') {
          aiSay(msg, d.message || 'Generation failed.', 'err');
          return;
        }
        var newBlocks = d.blocks || [];
        if (!newBlocks.length) {
          aiSay(msg, 'The model returned nothing usable — try again, or pick another model.', 'err');
          return;
        }
        insertGeneratedBlocks(newBlocks);
        var notes = d.notes || [];
        closeAIModal();
        if (promptEl) promptEl.value = '';
        aiSay(msg, 'The draft is inserted as editable blocks — always review before you publish.', '');
        setStatus(notes.length ? ('AI draft inserted — ' + notes.join('; ')) : 'AI draft inserted — review before publishing', notes.length ? '' : 'ok');
      }).catch(function () {
        // A transient network blip should not abandon a draft that is still being
        // written, so keep polling until the deadline.
        setTimeout(tick, 3000);
      });
    }
    setTimeout(tick, 1500);
  }
  // apiErrText pulls the human message out of an API error payload. The envelope
  // is {"error":{"code":..,"message":..}}, so reading d.error directly yields an
  // OBJECT and renders as "[object Object]" — which is what this surface did,
  // hiding every reason a generation failed behind a nonsense string.
  function apiErrText(d, status) {
    if (d) {
      if (typeof d.error === 'object' && d.error && d.error.message) return d.error.message;
      if (typeof d.message === 'string' && d.message) return d.message;
      if (typeof d.error === 'string' && d.error) return d.error;
    }
    return 'Generation failed (HTTP ' + status + ').';
  }

  // aiSay writes a status line with a visible state, so a failure does not read
  // like the neutral hint it replaces.
  function aiSay(el, text, kind) {
    if (!el) return;
    el.textContent = text;
    el.className = 'ai-status' + (kind ? ' ai-status--' + kind : '');
  }
  if (aiBtn) aiBtn.addEventListener('click', openAIModal);
  if (aiModal) {
    var aiCloseBtn = aiQ('[data-ai-close]'); if (aiCloseBtn) aiCloseBtn.addEventListener('click', closeAIModal);
    var aiCancelBtn = aiQ('[data-ai-cancel]'); if (aiCancelBtn) aiCancelBtn.addEventListener('click', closeAIModal);
    var aiRunBtn = aiQ('[data-ai-run]'); if (aiRunBtn) aiRunBtn.addEventListener('click', runAIGenerate);
    var aiModelSel = aiQ('[data-ai-model-select]');
    if (aiModelSel) aiModelSel.addEventListener('change', function () {
      var modelEl = aiQ('[data-ai-model]');
      if (modelEl && aiModelSel.value) modelEl.value = aiModelSel.value;
      aiEngineSummary();
    });
    var aiModelInput = aiQ('[data-ai-model]');
    if (aiModelInput) aiModelInput.addEventListener('input', aiEngineSummary);
    // "Exact word count" reveals the number field; every shaping control keeps
    // the summary chip honest.
    var aiLen = aiQ('[data-ai-length]');
    if (aiLen) aiLen.addEventListener('change', function () {
      var f = aiQ('[data-ai-words-field]');
      if (f) f.hidden = aiLen.value !== 'exact';
      aiRefreshShapeChip();
    });
    var aiTemp = aiQ('[data-ai-temp]');
    if (aiTemp) aiTemp.addEventListener('input', function () {
      var out = aiQ('[data-ai-temp-out]');
      var t = parseInt(aiTemp.value, 10);
      if (out) out.textContent = t > 0 ? (t / 10).toFixed(1) : 'model default';
      aiRefreshShapeChip();
    });
    ['[data-ai-shape]', '[data-ai-tone]', '[data-ai-words]', '[data-ai-audience]', '[data-ai-language]', '[data-ai-keyword]'].forEach(function (q) {
      var el = aiQ(q);
      if (el) el.addEventListener('change', aiRefreshShapeChip);
      if (el) el.addEventListener('input', aiRefreshShapeChip);
    });
    aiRefreshShapeChip();
    aiModal.addEventListener('click', function (e) { if (e.target === aiModal) closeAIModal(); });
  }
  if (previewClose) previewClose.addEventListener('click', function () { previewModal.hidden = true; });
  if (historyBtn) historyBtn.addEventListener('click', openHistory);
  if (historyClose) historyClose.addEventListener('click', function () { historyModal.hidden = true; });
  if (titleEl) titleEl.addEventListener('input', function () { updateStats(); updateSeoSnippet(); scheduleAutosave(); });
  if (focusBtn) focusBtn.addEventListener('click', toggleFocus);
  if (splitBtn) splitBtn.addEventListener('click', toggleSplit);
  if (htmlBtn) htmlBtn.addEventListener('click', toggleHTML);
  if (mdBtn) mdBtn.addEventListener('click', toggleMD);
  if (htmlArea) htmlArea.addEventListener('input', function () {
    setStatus('Editing HTML…');
    if (slug) scheduleAutosave();
  });

  // Post settings panel wiring.
  hydrateSettings();
  if (settingsBtn) settingsBtn.addEventListener('click', toggleSettings);

  // "＋ Page" — create a fresh standalone page and jump straight into it. Uses
  // the same quick-create endpoint the Pages manager uses (server flags is_page).
  var newPageBtn = root.querySelector('[data-editor-newpage]');
  if (newPageBtn) {
    newPageBtn.addEventListener('click', function () {
      var title = (window.prompt('New page title', 'Untitled page') || '').trim();
      if (!title) return;
      newPageBtn.disabled = true;
      fetch('/os/api/pages/quick-create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
        body: JSON.stringify({ title: title }),
      })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (res) {
          if (res.ok && res.d.slug) { window.location.href = '/os/editor/' + res.d.slug; }
          else { newPageBtn.disabled = false; window.alert((res.d && (res.d.detail || res.d.title)) || 'Could not create page'); }
        })
        .catch(function () { newPageBtn.disabled = false; window.alert('Network error'); });
    });
  }

  if (settingsClose) settingsClose.addEventListener('click', closeSettings);
  if (settingsBackdrop) settingsBackdrop.addEventListener('click', closeSettings);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && settingsPanel && !settingsPanel.hidden) closeSettings();
  });
  if (pm['feature-upload'] && pm['feature-file']) {
    pm['feature-upload'].addEventListener('click', function () { pm['feature-file'].click(); });
    pm['feature-file'].addEventListener('change', function () {
      if (pm['feature-file'].files && pm['feature-file'].files[0]) uploadFeatureImage(pm['feature-file'].files[0]);
      pm['feature-file'].value = '';
    });
  }
  if (pm['feature-image']) pm['feature-image'].addEventListener('input', function () { updateFeaturePreview(); scheduleAutosave(); });
  if (pm['feature-remove']) pm['feature-remove'].addEventListener('click', function () { pmSet(pm['feature-image'], ''); updateFeaturePreview(); scheduleAutosave(); });
  if (pm['slug-apply']) pm['slug-apply'].addEventListener('click', applySlug);
  if (pm['slug']) pm['slug'].addEventListener('input', updateSeoSnippet);
  if (pm['tags-input']) {
    pm['tags-input'].addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); addTagsFromInput(); }
      else if (e.key === 'Backspace' && pm['tags-input'].value === '' && pmTags.length) { pmTags.pop(); renderTags(); scheduleAutosave(); }
    });
    pm['tags-input'].addEventListener('blur', addTagsFromInput);
  }
  // Counters + autosave for any text/checkbox edit inside the panel.
  if (settingsPanel) {
    settingsPanel.addEventListener('input', function (e) {
      if (e.target === pm['slug'] || e.target === pm['tags-input']) return; // handled separately
      updateCounters();
      scheduleAutosave();
    });
    settingsPanel.addEventListener('change', function (e) {
      if (e.target === pm['featured'] || e.target === pm['is-page']) scheduleAutosave();
    });
  }
  if (undoBtn) undoBtn.addEventListener('click', undo);
  if (redoBtn) redoBtn.addEventListener('click', redo);

  // Global keyboard shortcuts.
  document.addEventListener('keydown', function (e) {
    var meta = e.metaKey || e.ctrlKey;
    if (!meta) return;
    var k = e.key.toLowerCase();
    if (k === 's') { e.preventDefault(); save(); return; }
    if (k === 'h' && e.shiftKey) { e.preventDefault(); toggleHTML(); return; }
    if (k === 'm' && e.shiftKey) { e.preventDefault(); toggleMD(); return; }
    if (k === 'p' && e.shiftKey) { e.preventDefault(); toggleSettings(); return; }
    if (k === 'k') { e.preventDefault(); if (htmlMode || mdMode) return; openPalette(focusedBlockIdx(), focusedBlockIdx() - 1); return; }
    if (e.key === '.') { e.preventDefault(); toggleFocus(); return; }
    if (k === 'z') {
      var ae = document.activeElement;
      var typing = ae && (ae.tagName === 'TEXTAREA' || ae.tagName === 'INPUT');
      if (!typing) { e.preventDefault(); if (e.shiftKey) redo(); else undo(); }
      return;
    }
    if (k === 'y') {
      var ae2 = document.activeElement;
      var typing2 = ae2 && (ae2.tagName === 'TEXTAREA' || ae2.tagName === 'INPUT');
      if (!typing2) { e.preventDefault(); redo(); }
    }
  });

  // Probe AI availability (fire-and-forget, affects palette only).
  fetch('/os/api/editor/ai', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
    body: JSON.stringify({ op: 'ping', text: '' })
  }).then(function (r) {
    if (r.status !== 503) aiEnabled = true;
  }).catch(function () {});
})();
