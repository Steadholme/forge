/* Cellar — progressive-enhancement layer (Odyssey v2).
 *
 * Every feature is ADDITIVE: with JavaScript disabled the original <form> POST routes and
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
    el.textContent = message;
    toastRoot().appendChild(el);
    requestAnimationFrame(function () { el.classList.add("is-in"); });
    var ttl = REDUCE ? 2400 : 3200;
    setTimeout(function () {
      el.classList.remove("is-in");
      setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, REDUCE ? 0 : 180);
    }, ttl);
  }
  window.CellarUI = { toast: toast };

  // --- CSRF + POST helpers -------------------------------------------------
  function csrfToken(form) {
    if (form) {
      var f = form.querySelector('input[name="csrf_token"]');
      if (f && f.value) return f.value;
    }
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
        toast("Copied pull command", "ok");
      }, function () {
        toast("Could not copy", "err");
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
        if (th.hasAttribute("data-nosort") || !th.textContent.trim()) return;
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

  // --- Optimistic tag delete (no full-page reload) -------------------------
  function initDeleteRows() {
    document.querySelectorAll("form[data-delete-row]").forEach(function (f) {
      f.addEventListener("submit", function (e) {
        if (e.defaultPrevented) return; // native confirm() was cancelled
        e.preventDefault();
        var row = f.closest("tr");
        var btn = f.querySelector('button[type="submit"]') || f.querySelector("button");
        var data = {};
        f.querySelectorAll("input[name]").forEach(function (i) { data[i.name] = i.value; });
        if (btn) { btn.disabled = true; btn.textContent = "Deleting…"; }
        postForm(f.getAttribute("action") + ".json", data)
          .then(function (res) {
            if (!res.ok) throw new Error("http " + res.status);
            return res.json();
          })
          .then(function () {
            removeRow(row);
            toast("Tag deleted", "ok");
          })
          .catch(function () {
            if (btn) { btn.disabled = false; btn.textContent = "Delete"; }
            toast("Could not delete — reloading…", "err");
            HTMLFormElement.prototype.submit.call(f);
          });
      });
    });
  }
  function removeRow(row) {
    if (!row) return;
    var body = row.parentNode;
    var table = body && body.closest ? body.closest("table") : null;
    if (REDUCE) {
      row.parentNode.removeChild(row);
    } else {
      row.style.transition = "opacity 140ms ease";
      row.style.opacity = "0";
      setTimeout(function () { if (row.parentNode) row.parentNode.removeChild(row); }, 150);
    }
    // Restore an empty-state row if the table just went empty.
    setTimeout(function () {
      if (!table) return;
      var live = Array.prototype.slice.call(table.tBodies[0].rows).filter(function (r) {
        return !r.classList.contains("empty-row");
      });
      if (!live.length && !table.querySelector(".empty-row")) {
        var tr = document.createElement("tr");
        tr.className = "empty-row";
        var td = document.createElement("td");
        td.colSpan = table.tHead ? table.tHead.rows[0].cells.length : 6;
        td.textContent = "This repository has no tags.";
        tr.appendChild(td);
        table.tBodies[0].appendChild(tr);
      }
    }, REDUCE ? 0 : 160);
  }

  // --- Retention dry-run preview (inline, no reload) -----------------------
  function initRetentionPreview() {
    var form = document.querySelector("form[data-preview]");
    if (!form) return;
    var target = document.getElementById("retention-preview");
    if (!target) return;
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = form.querySelector("button");
      var original = btn ? btn.textContent : "";
      if (btn) { btn.disabled = true; btn.textContent = "Computing…"; }
      postForm(form.getAttribute("action") + ".json", { csrf_token: csrfToken(form) })
        .then(function (res) {
          if (!res.ok) throw new Error("http " + res.status);
          return res.json();
        })
        .then(function (j) {
          renderPreview(target, j.deletions || []);
          if (btn) { btn.disabled = false; btn.textContent = original; }
          toast("Dry run complete", "ok");
          target.scrollIntoView({ behavior: REDUCE ? "auto" : "smooth", block: "nearest" });
        })
        .catch(function () {
          if (btn) { btn.disabled = false; btn.textContent = original; }
          toast("Preview failed — reloading…", "err");
          HTMLFormElement.prototype.submit.call(form);
        });
    });
  }
  function renderPreview(target, deletions) {
    while (target.firstChild) target.removeChild(target.firstChild);

    var head = document.createElement("div");
    head.className = "section-head";
    var h2 = document.createElement("h2");
    h2.textContent = "Dry run — tags that would be deleted";
    var count = document.createElement("span");
    count.className = "count-badge";
    count.textContent = deletions.length === 1 ? "1 tag" : deletions.length + " tags";
    head.appendChild(h2);
    head.appendChild(count);
    target.appendChild(head);

    var wrap = document.createElement("div");
    wrap.className = "table-wrap";
    var table = document.createElement("table");
    table.className = "data";
    var thead = document.createElement("thead");
    var htr = document.createElement("tr");
    ["Repository", "Tag"].forEach(function (t) {
      var th = document.createElement("th");
      th.textContent = t;
      htr.appendChild(th);
    });
    thead.appendChild(htr);
    table.appendChild(thead);
    var tbody = document.createElement("tbody");

    if (!deletions.length) {
      var er = document.createElement("tr");
      er.className = "empty-row";
      var etd = document.createElement("td");
      etd.colSpan = 2;
      etd.textContent = "Nothing would be deleted — every tag is kept by a rule (or is latest).";
      er.appendChild(etd);
      tbody.appendChild(er);
    } else {
      deletions.forEach(function (d) {
        var tr = document.createElement("tr");
        var rtd = document.createElement("td");
        rtd.className = "repo-cell";
        var rspan = document.createElement("span");
        rspan.className = "repo-name";
        rspan.textContent = d.repo || "";
        rtd.appendChild(rspan);
        var ttd = document.createElement("td");
        var tspan = document.createElement("span");
        tspan.className = "tag-pill";
        tspan.textContent = d.tag || "";
        ttd.appendChild(tspan);
        tr.appendChild(rtd);
        tr.appendChild(ttd);
        tbody.appendChild(tr);
      });
    }
    table.appendChild(tbody);
    wrap.appendChild(table);
    target.appendChild(wrap);
  }

  function init() {
    initCopy();
    initSort();
    initDeleteRows();
    initRetentionPreview();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
