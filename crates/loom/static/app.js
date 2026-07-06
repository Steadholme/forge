/* Loom — progressive-enhancement layer (Odyssey v2).
 *
 * Every feature here is ADDITIVE: with JavaScript disabled the original <form> POST routes and
 * server-rendered markup work unchanged. Remote strings are only ever written with textContent,
 * never innerHTML. Motion is short (120–160ms) and disabled under prefers-reduced-motion. */
(function () {
  "use strict";

  var REDUCE = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // --- Toast feedback ------------------------------------------------------
  function toastRoot() {
    var r = document.getElementById("toast-root");
    if (!r) {
      r = document.createElement("div");
      r.id = "toast-root";
      r.className = "toast-root";
      r.setAttribute("aria-live", "polite");
      r.setAttribute("aria-atomic", "true");
      document.body.appendChild(r);
    }
    return r;
  }
  function toast(message, kind) {
    var el = document.createElement("div");
    el.className = "toast toast--" + (kind === "err" ? "err" : "ok");
    el.setAttribute("role", "status");
    el.textContent = message; // remote-safe
    toastRoot().appendChild(el);
    requestAnimationFrame(function () { el.classList.add("is-in"); });
    var ttl = REDUCE ? 2400 : 3200;
    setTimeout(function () {
      el.classList.remove("is-in");
      setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, REDUCE ? 0 : 180);
    }, ttl);
  }
  window.LoomUI = { toast: toast };

  // --- CSRF + POST helpers -------------------------------------------------
  function csrfToken() {
    var input = document.querySelector('input[name="csrf_token"]');
    if (input && input.value) return input.value;
    var m = document.cookie.match(/(?:^|;\s*)__Host-csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : "";
  }
  function postForm(url, data) {
    var body = new URLSearchParams();
    Object.keys(data).forEach(function (k) { body.append(k, data[k]); });
    return fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
      },
      credentials: "same-origin",
      body: body.toString()
    });
  }

  // --- Copy-to-clipboard buttons ------------------------------------------
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "absolute";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        resolve();
      } catch (err) { reject(err); }
    });
  }
  function initCopy() {
    document.addEventListener("click", function (e) {
      var btn = e.target.closest ? e.target.closest("[data-copy]") : null;
      if (!btn) return;
      e.preventDefault();
      var text = btn.getAttribute("data-copy");
      if (!text) {
        var strip = btn.closest(".cmd-strip, .copy-wrap");
        var code = strip && strip.querySelector("code");
        text = code ? code.textContent : "";
      }
      copyText(text).then(function () {
        toast("Copied to clipboard", "ok");
      }, function () {
        toast("Could not copy", "err");
      });
    });
  }

  // --- Blob line anchors + permalink copy ------------------------------------
  function parseLineHash(hash) {
    var m = String(hash || "").match(/^#L([1-9][0-9]*)(?:-L([1-9][0-9]*))?$/);
    if (!m) return null;
    var start = parseInt(m[1], 10);
    var end = m[2] ? parseInt(m[2], 10) : start;
    if (end < start) {
      var tmp = start;
      start = end;
      end = tmp;
    }
    return { start: start, end: end };
  }

  function initBlobLineAnchors() {
    var table = document.querySelector(".blob-code");
    if (!table) return;
    var maxLine = table.querySelectorAll(".blob-line").length;
    var anchorLine = null;

    function clearHighlights() {
      table.querySelectorAll(".blob-line--highlight").forEach(function (row) {
        row.classList.remove("blob-line--highlight");
      });
    }

    function applyHashHighlight() {
      var range = parseLineHash(window.location.hash);
      clearHighlights();
      if (!range) return;
      var start = Math.max(1, range.start);
      var end = Math.min(maxLine, range.end);
      if (start > maxLine) return;
      for (var n = start; n <= end; n += 1) {
        var row = document.getElementById("L" + n);
        if (row && row.classList) row.classList.add("blob-line--highlight");
      }
      anchorLine = range.start;
    }

    table.addEventListener("click", function (e) {
      var link = e.target.closest ? e.target.closest(".blob-line__num a") : null;
      if (!link || !table.contains(link)) return;
      var range = parseLineHash(link.getAttribute("href"));
      if (!range) return;
      e.preventDefault();
      var line = range.start;
      var from = e.shiftKey && anchorLine ? anchorLine : line;
      var start = Math.min(from, line);
      var end = Math.max(from, line);
      var hash = "#L" + start + (end === start ? "" : "-L" + end);
      if (window.location.hash === hash) {
        applyHashHighlight();
      } else {
        window.location.hash = hash;
      }
      anchorLine = line;
    });

    window.addEventListener("hashchange", applyHashHighlight);
    applyHashHighlight();
  }

  function initBlobPermalinks() {
    document.addEventListener("click", function (e) {
      var link = e.target.closest ? e.target.closest(".btn-permalink[data-permalink]") : null;
      if (!link) return;
      if (e.metaKey || e.ctrlKey || e.altKey || e.shiftKey) return;
      var href = link.getAttribute("data-permalink") || link.getAttribute("href");
      if (!href) return;
      e.preventDefault();
      var url;
      try {
        url = new URL(href, window.location.href);
      } catch (err) {
        window.location.href = href;
        return;
      }
      if (parseLineHash(window.location.hash)) url.hash = window.location.hash;
      copyText(url.toString()).then(function () {
        toast("Permalink copied", "ok");
      }, function () {
        window.location.href = url.toString();
      });
    });
  }

  // --- Sortable data tables ------------------------------------------------
  function cellValue(row, idx, type) {
    var cell = row.cells[idx];
    if (!cell) return type === "num" ? -Infinity : "";
    var raw = cell.getAttribute("data-sort-value");
    if (raw === null) raw = cell.textContent.trim();
    if (type === "num") {
      var n = parseFloat(String(raw).replace(/[^0-9.\-]/g, ""));
      return isNaN(n) ? -Infinity : n;
    }
    return String(raw).toLowerCase();
  }
  function initSort() {
    document.querySelectorAll("table.data[data-sortable]").forEach(function (table) {
      if (!table.tHead || !table.tHead.rows.length) return;
      var head = table.tHead.rows[0];
      Array.prototype.forEach.call(head.cells, function (th, idx) {
        if (th.hasAttribute("data-nosort")) return;
        th.classList.add("th-sort");
        th.tabIndex = 0;
        th.setAttribute("role", "button");
        function run() { sortTable(table, idx, th, head); }
        th.addEventListener("click", run);
        th.addEventListener("keydown", function (e) {
          if (e.key === "Enter" || e.key === " " || e.key === "Spacebar") { e.preventDefault(); run(); }
        });
      });
    });
  }
  function sortTable(table, idx, th, head) {
    var body = table.tBodies[0];
    if (!body) return;
    var rows = Array.prototype.slice.call(body.rows).filter(function (r) {
      return !r.classList.contains("empty-row");
    });
    if (rows.length < 2) return;
    var type = th.getAttribute("data-sort") || "text";
    var dir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
    var mul = dir === "ascending" ? 1 : -1;
    rows.sort(function (a, b) {
      var x = cellValue(a, idx, type), y = cellValue(b, idx, type);
      return x < y ? -mul : x > y ? mul : 0;
    });
    Array.prototype.forEach.call(head.cells, function (c) { c.removeAttribute("aria-sort"); });
    th.setAttribute("aria-sort", dir);
    rows.forEach(function (r) { body.appendChild(r); });
  }

  // --- Collapsible diff files: expand / collapse all -----------------------
  function initDiffToggleAll() {
    document.querySelectorAll("[data-diff-toolbar]").forEach(function (bar) {
      var scope = bar.closest(".card") || document;
      var files = scope.querySelectorAll("details.diff-file");
      if (!files.length) { bar.remove(); return; }
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-ghost btn-sm";
      function label() {
        var anyOpen = scope.querySelector("details.diff-file[open]");
        btn.textContent = anyOpen ? "Collapse all" : "Expand all";
      }
      label();
      btn.addEventListener("click", function () {
        var anyOpen = scope.querySelector("details.diff-file[open]");
        scope.querySelectorAll("details.diff-file").forEach(function (d) { d.open = !anyOpen; });
        label();
      });
      bar.appendChild(btn);
    });
  }

  // --- Inline diff comments (PR detail only) -------------------------------
  function initInlineComments() {
    var cfg = document.getElementById("pr-inline");
    if (!cfg) return;
    var endpoint = cfg.getAttribute("data-endpoint");
    var thread = document.getElementById("pr-inline-thread");

    document.querySelectorAll("details.diff-file table.diff tr.diff-row").forEach(function (row) {
      var line = row.getAttribute("data-line");
      if (!line) return; // only real code lines carry a line number
      var code = row.querySelector(".diff-code");
      if (!code) return;
      var add = document.createElement("button");
      add.type = "button";
      add.className = "diff-commentbtn";
      add.setAttribute("aria-label", "Comment on line " + line);
      add.title = "Comment on this line";
      add.textContent = "+";
      add.addEventListener("click", function (e) { e.stopPropagation(); openEditor(row); });
      code.insertBefore(add, code.firstChild);
    });

    function openEditor(row) {
      var next = row.nextSibling;
      if (next && next.classList && next.classList.contains("diff-editor-row")) {
        var open = next.querySelector("textarea");
        if (open) open.focus();
        return;
      }
      var file = row.closest("details.diff-file");
      var path = file ? (file.getAttribute("data-path") || "") : "";
      var line = row.getAttribute("data-line");

      var tr = document.createElement("tr");
      tr.className = "diff-editor-row";
      var td = document.createElement("td");
      td.colSpan = 2;

      var wrap = document.createElement("div");
      wrap.className = "diff-editor";
      var head = document.createElement("div");
      head.className = "diff-editor__head";
      head.textContent = "Comment on " + path + ":" + line;
      var ta = document.createElement("textarea");
      ta.className = "issue-input";
      ta.rows = 3;
      ta.setAttribute("aria-label", "Inline comment on " + path + " line " + line);
      var actions = document.createElement("div");
      actions.className = "actions";
      var save = document.createElement("button");
      save.type = "button";
      save.className = "btn btn-primary btn-sm";
      save.textContent = "Comment";
      var cancel = document.createElement("button");
      cancel.type = "button";
      cancel.className = "btn btn-ghost btn-sm";
      cancel.textContent = "Cancel";

      cancel.addEventListener("click", function () { tr.parentNode.removeChild(tr); });
      save.addEventListener("click", function () {
        var body = ta.value.trim();
        if (!body) { ta.focus(); return; }
        save.disabled = true;
        save.textContent = "Saving…";
        postForm(endpoint, { csrf_token: csrfToken(), path: path, line: line, body: body })
          .then(function (res) {
            if (!res.ok) throw new Error("http " + res.status);
            return res.json();
          })
          .then(function (j) {
            appendComment(j);
            if (tr.parentNode) tr.parentNode.removeChild(tr);
            toast("Comment added", "ok");
          })
          .catch(function () {
            save.disabled = false;
            save.textContent = "Comment";
            toast("Could not add comment", "err");
          });
      });

      actions.appendChild(save);
      actions.appendChild(cancel);
      wrap.appendChild(head);
      wrap.appendChild(ta);
      wrap.appendChild(actions);
      td.appendChild(wrap);
      tr.appendChild(td);
      row.parentNode.insertBefore(tr, row.nextSibling);
      ta.focus();
    }

    function appendComment(j) {
      if (!thread) return;
      var empty = thread.querySelector(".issue-item--empty");
      if (empty) thread.removeChild(empty);
      var li = document.createElement("li");
      li.className = "issue-item";
      var meta = document.createElement("div");
      meta.className = "issue-item__meta";
      var loc = document.createElement("span");
      loc.textContent = (j.path || "") + ":" + (j.line != null ? j.line : "");
      meta.appendChild(loc);
      meta.appendChild(document.createTextNode(" · " + (j.author || "") + " commented just now"));
      var bodyEl = document.createElement("div");
      bodyEl.className = "issue-item__body";
      bodyEl.textContent = j.body || "";
      li.appendChild(meta);
      li.appendChild(bodyEl);
      thread.appendChild(li);
    }
  }

  // --- Optimistic toggle forms (no full-page reload) -----------------------
  function initToggleForms() {
    document.querySelectorAll("form[data-json]").forEach(function (f) {
      f.addEventListener("submit", function (e) {
        e.preventDefault();
        var btn = f.querySelector('button[type="submit"]') || f.querySelector("button");
        var original = btn ? btn.textContent : "";
        if (btn) { btn.disabled = true; btn.textContent = "Working…"; }
        var data = {};
        f.querySelectorAll("input[name]").forEach(function (i) { data[i.name] = i.value; });
        postForm(f.getAttribute("action") + ".json", data)
          .then(function (res) {
            if (!res.ok) throw new Error("http " + res.status);
            return res.json();
          })
          .then(function (j) {
            var badge = document.getElementById("state-badge-main");
            if (badge && j.badge_class && j.badge_label) {
              badge.className = "state-badge " + j.badge_class;
              badge.textContent = j.badge_label;
            }
            if (btn) {
              btn.disabled = false;
              btn.textContent = j.button_label || original;
            }
            toast(j.message || "Updated", "ok");
          })
          .catch(function () {
            // Fall back to the real form POST so the action still succeeds without JS.
            toast("Could not update — reloading…", "err");
            HTMLFormElement.prototype.submit.call(f);
          });
      });
    });
  }

  // --- Char counters + in-flight buttons -----------------------------------
  function initCharCounters() {
    document.querySelectorAll("input[maxlength], textarea[maxlength]").forEach(function (el) {
      if (!el.classList.contains("count-input")) return;
      var max = parseInt(el.getAttribute("maxlength"), 10);
      var out = document.createElement("span");
      out.className = "char-counter";
      function upd() { out.textContent = el.value.length + " / " + max; }
      upd();
      el.addEventListener("input", upd);
      if (el.parentNode) el.parentNode.appendChild(out);
    });
  }

  // --- Destructive confirmation gates -------------------------------------
  function initDeleteConfirm() {
    document.querySelectorAll("form[data-delete-confirm]").forEach(function (form) {
      var expected = form.getAttribute("data-delete-confirm") || "";
      var input = form.querySelector("[data-delete-confirm-input]");
      var button = form.querySelector("[data-delete-confirm-button]");
      if (!input || !button) return;
      function update() {
        button.disabled = input.value !== expected;
      }
      update();
      input.addEventListener("input", update);
    });
  }

  // --- Deploy custom-domains list (fetch-on-load; add/remove via normal POST) ----
  function initDeployDomains() {
    function esc(s) {
      return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
      });
    }
    document.querySelectorAll("[data-domains-poll]").forEach(function (list) {
      var url = list.getAttribute("data-domains-poll");
      var action = list.getAttribute("data-domains-action") || "";
      var csrf = list.getAttribute("data-domains-csrf") || "";
      function render(domains) {
        if (!domains || !domains.length) {
          list.innerHTML = '<li class="deploy-domain-empty muted">No custom domains yet.</li>';
          return;
        }
        list.innerHTML = domains
          .map(function (d) {
            var badge = d.verified
              ? '<span class="pill pill-ok">verified</span>'
              : '<span class="pill pill-warn">pending</span>';
            return (
              '<li class="deploy-domain-item"><span class="deploy-domain-host">' +
              esc(d.hostname) +
              "</span> " +
              badge +
              '<form class="deploy-domain-remove" method="post" action="' +
              esc(action) +
              '"><input type="hidden" name="csrf_token" value="' +
              esc(csrf) +
              '"><input type="hidden" name="hostname" value="' +
              esc(d.hostname) +
              '"><button class="btn btn-ghost btn-sm" type="submit">Remove</button></form></li>'
            );
          })
          .join("");
      }
      fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : { domains: [] }; })
        .then(function (data) { render((data && data.domains) || []); })
        .catch(function () {
          list.innerHTML = '<li class="deploy-domain-empty muted">Could not load domains.</li>';
        });
    });
  }

  // --- Deploy status + public preview URL live-poll -------------------------
  function initDeployPreview() {
    var status = document.querySelector(".deploy-status[data-poll]");
    if (!status) return;
    var url = status.getAttribute("data-poll");
    var link = document.querySelector("[data-preview-link]");
    var tries = 0;
    function tick() {
      tries++;
      fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
          if (!d) return;
          if (d.status) {
            status.textContent = d.status;
            status.className = "deploy-status deploy-status--" + d.status;
          }
          // Persist-and-return: status_json swaps the placeholder for the real per-deploy public URL.
          if (link && d.previewUrl && /^https?:\/\//.test(d.previewUrl)) {
            link.href = d.previewUrl;
            link.textContent = d.previewUrl;
            var copy = document.querySelector("[data-preview-copy]");
            if (copy) copy.setAttribute("data-copy", d.previewUrl);
          }
          var terminal = d.status === "ready" || d.status === "failed" || d.status === "error";
          if (!terminal && tries < 8) setTimeout(tick, 4000);
        })
        .catch(function () {});
    }
    tick();
  }

  function init() {
    initCopy();
    initSort();
    initBlobLineAnchors();
    initBlobPermalinks();
    initDiffToggleAll();
    initInlineComments();
    initToggleForms();
    initCharCounters();
    initDeleteConfirm();
    initDeployDomains();
    initDeployPreview();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
