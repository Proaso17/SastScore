/* sastcore web · interfaz. El contenido del usuario se inserta con textContent
   (nunca innerHTML), así que el código subido no puede inyectar HTML. */
(() => {
  "use strict";
  const $ = (sel, root = document) => root.querySelector(sel);
  const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

  // ── Iconos (SVG estático, de confianza) ─────────────────────────────────
  const I = {
    sun: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    moon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>',
    file: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>',
    x: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M18 6 6 18M6 6l12 12"/></svg>',
    warn: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>',
    back: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>',
    search: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>',
    pin: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 6-9 12-9 12s-9-6-9-12a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="2.5"/></svg>',
    check: '<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
    wrench: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.2L3 18v3h3l6.5-6.3a4 4 0 0 0 5.2-5.4l-2.6 2.6-2-2 2.6-2.6z"/></svg>',
    ext: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6M10 14 21 3"/></svg>',
  };
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };

  // ── Tema ────────────────────────────────────────────────────────────────
  const root = document.documentElement;
  const toggle = $("#theme-toggle");
  const prefersDark = () => window.matchMedia("(prefers-color-scheme: dark)").matches;
  const activeTheme = () => root.getAttribute("data-theme") || (prefersDark() ? "dark" : "light");
  const paintToggle = () => { toggle.innerHTML = activeTheme() === "dark" ? I.sun : I.moon; };
  const stored = localStorage.getItem("sastcore-theme");
  if (stored) root.setAttribute("data-theme", stored);
  paintToggle();
  toggle.addEventListener("click", () => {
    const next = activeTheme() === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    localStorage.setItem("sastcore-theme", next);
    paintToggle();
  });

  // ── Estado ──────────────────────────────────────────────────────────────
  let files = [];
  let findings = [];
  let filesScanned = 0;
  const filter = { sev: "ALL", q: "" };

  const dropzone = $("#dropzone");
  const input = $("#file-input");
  const listEl = $("#filelist");
  const analyzeBtn = $("#analyze-btn");
  const form = $("#upload-form");
  const alertEl = $("#alert");
  const uploadView = $("#upload-view");
  const loadingView = $("#loading-view");
  const resultsView = $("#results-view");

  // ── Selección de ficheros ───────────────────────────────────────────────
  const fmtSize = (n) =>
    n < 1024 ? `${n} B` : n < 1048576 ? `${Math.round(n / 1024)} KB` : `${(n / 1048576).toFixed(1)} MB`;

  function renderFiles() {
    listEl.innerHTML = "";
    files.forEach((f, i) => {
      const li = el("li");
      const ico = el("span", "fi-ico"); ico.innerHTML = I.file;
      const name = el("span", "fi-name", f.name);
      const size = el("span", "fi-size", fmtSize(f.size));
      const rm = el("button", "fi-x"); rm.type = "button"; rm.innerHTML = I.x;
      rm.setAttribute("aria-label", `Quitar ${f.name}`);
      rm.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); files.splice(i, 1); renderFiles(); });
      li.append(ico, name, size, rm);
      listEl.appendChild(li);
    });
    analyzeBtn.disabled = files.length === 0;
  }
  const addFiles = (fileList) => { for (const f of fileList) files.push(f); renderFiles(); };

  input.addEventListener("change", () => { addFiles(input.files); input.value = ""; });
  ["dragenter", "dragover"].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove("drag"); }));
  dropzone.addEventListener("drop", (e) => { if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files); });

  // ── Escaneo ─────────────────────────────────────────────────────────────
  function showAlert(msg) {
    alertEl.innerHTML = I.warn;
    alertEl.append(document.createTextNode(" " + msg));
    alertEl.classList.remove("hidden");
  }
  function show(view) {
    [uploadView, loadingView, resultsView].forEach((v) => v.classList.add("hidden"));
    view.classList.remove("hidden");
  }

  async function performScan(url, opts) {
    alertEl.classList.add("hidden");
    show(loadingView);
    try {
      const res = await fetch(url, opts);
      const data = await res.json();
      if (!res.ok) { show(uploadView); showAlert(data.error || "No se pudo analizar."); return; }
      findings = data.findings || [];
      filesScanned = data.files_scanned || 0;
      filter.sev = "ALL"; filter.q = "";
      renderResults();
      show(resultsView);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (_err) {
      show(uploadView);
      showAlert("No se pudo contactar con el servidor. Asegúrate de que está arrancado (ejecuta 'sastcore serve') y reintenta.");
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    if (!files.length) return;
    const fd = new FormData();
    for (const f of files) fd.append("files", f, f.name);
    performScan("/api/scan", { method: "POST", body: fd });
  });

  // ── Analizar un repo público de GitHub ──────────────────────────────────
  const repoBtn = $("#repo-btn");
  const repoUrl = $("#repo-url");
  function scanRepo() {
    const url = (repoUrl.value || "").trim();
    if (!url) return;
    performScan("/api/scan-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  }
  if (repoBtn && repoUrl) {
    repoBtn.addEventListener("click", scanRepo);
    repoUrl.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); scanRepo(); }
    });
  }

  // ── Ejemplo de demostración ─────────────────────────────────────────────
  const sampleBtn = $("#sample-btn");
  const SAMPLE = [
    "import hashlib, os",
    "",
    "def login(request, cursor):",
    "    user = request.args.get('user')",
    "    cursor.execute(\"SELECT * FROM users WHERE name = '\" + user + \"'\")",
    "    os.system('echo ' + user)",
    "    return hashlib.md5(user.encode()).hexdigest()",
    "",
    "API_KEY = 'AKIAIOSFODNN7EXAMPLE'",
    "",
  ].join("\n");
  if (sampleBtn) {
    sampleBtn.addEventListener("click", () => {
      files = [new File([SAMPLE], "ejemplo.py", { type: "text/x-python" })];
      renderFiles();
      form.requestSubmit();
    });
  }

  // ── Render de resultados ────────────────────────────────────────────────
  function severityCounts() {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach((f) => { c[f.severity] = (c[f.severity] || 0) + 1; });
    return c;
  }

  function renderResults() {
    resultsView.innerHTML = "";
    const head = el("div", "results-head");
    const back = el("button", "btn btn-ghost");
    back.innerHTML = I.back; back.append(document.createTextNode(" Nuevo análisis"));
    back.addEventListener("click", reset);
    head.append(back, el("h2", null, findings.length ? "Vulnerabilidades detectadas" : "Análisis completado"),
      el("span", "meta", `${findings.length} hallazgo(s) · ${filesScanned} fichero(s)`));
    resultsView.appendChild(head);

    if (!findings.length) { resultsView.appendChild(emptyState()); return; }

    const c = severityCounts();
    const stats = el("div", "stats");
    stats.appendChild(statCard("total", findings.length, "Total", false));
    SEV.forEach((s) => stats.appendChild(statCard(s, c[s], s, c[s] === 0)));
    resultsView.appendChild(stats);
    resultsView.appendChild(downloadBar());
    resultsView.appendChild(toolbar(c));
    const list = el("div"); list.id = "findings-list";
    resultsView.appendChild(list);
    renderList();
  }

  function statCard(cls, n, label, dim) {
    const d = el("div", `stat ${cls}${dim ? " dim" : ""}`);
    d.append(el("div", "n", String(n)), el("div", "l", label));
    return d;
  }

  // ── Descarga de informes ────────────────────────────────────────────────
  const DL_FORMATS = [["sarif", "SARIF"], ["json", "JSON"], ["markdown", "Markdown"], ["html", "HTML"]];
  const DL_EXT = { sarif: "sarif", json: "json", markdown: "md", html: "html" };

  function downloadBar() {
    const bar = el("div", "downloads");
    bar.appendChild(el("span", "dl-label", "Descargar informe:"));
    const status = el("span", "dl-status");
    DL_FORMATS.forEach(([fmt, label]) => {
      const b = el("button", "dl-btn", label);
      b.type = "button";
      b.addEventListener("click", () => downloadReport(fmt, b, status));
      bar.appendChild(b);
    });
    bar.appendChild(status);
    return bar;
  }

  async function downloadReport(fmt, btn, status) {
    status.textContent = "";
    btn.disabled = true;
    try {
      const res = await fetch("/report/" + fmt, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ files_scanned: filesScanned, findings }),
      });
      if (!res.ok) { status.textContent = "No se pudo generar el informe."; return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = el("a");
      a.href = url;
      a.download = "sastcore-report." + (DL_EXT[fmt] || "txt");
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (_e) {
      status.textContent = "No se pudo generar el informe.";
    } finally {
      btn.disabled = false;
    }
  }

  function toolbar(counts) {
    const tb = el("div", "toolbar");
    const search = el("div", "search"); search.innerHTML = I.search;
    const inp = el("input"); inp.type = "search"; inp.placeholder = "Buscar por regla, fichero o mensaje…";
    inp.setAttribute("aria-label", "Buscar hallazgos");
    inp.addEventListener("input", () => { filter.q = inp.value.toLowerCase().trim(); renderList(); });
    search.appendChild(inp);
    const chips = el("div", "chips");
    const chip = (val, label) => {
      const b = el("button", "chip" + (filter.sev === val ? " active" : ""), label);
      b.dataset.sev = val;
      b.addEventListener("click", () => {
        filter.sev = val;
        chips.querySelectorAll(".chip").forEach((x) => x.classList.toggle("active", x.dataset.sev === val));
        renderList();
      });
      return b;
    };
    chips.appendChild(chip("ALL", "Todas"));
    SEV.forEach((s) => { if (counts[s]) chips.appendChild(chip(s, `${s} ${counts[s]}`)); });
    tb.append(search, chips);
    return tb;
  }

  const matchesFilter = (f) => {
    if (filter.sev !== "ALL" && f.severity !== filter.sev) return false;
    if (filter.q) {
      const hay = `${f.rule_id} ${f.message} ${(f.location && f.location.path) || ""}`.toLowerCase();
      if (!hay.includes(filter.q)) return false;
    }
    return true;
  };

  function renderList() {
    const list = $("#findings-list");
    if (!list) return;
    list.innerHTML = "";
    const shown = findings.filter(matchesFilter);
    if (!shown.length) { list.appendChild(el("div", "no-match", "Ningún hallazgo coincide con el filtro.")); return; }
    shown.forEach((f) => list.appendChild(findingCard(f)));
  }

  function findingCard(f) {
    const art = el("article", `finding ${f.severity}`);
    const hd = el("div", "f-head");
    hd.appendChild(el("span", `badge ${f.severity}`, f.severity));
    hd.appendChild(el("code", "f-rule", f.rule_id));
    const loc = el("span", "f-loc"); loc.innerHTML = I.pin;
    loc.append(document.createTextNode(` ${f.location.path}:${f.location.start_line}`));
    hd.appendChild(loc);
    art.appendChild(hd);

    const bd = el("div", "f-body");
    bd.appendChild(el("p", "f-msg", f.message));
    if (f.snippet) bd.appendChild(codeBlock(f.snippet, f.location.start_line));
    if (f.data_flow && f.data_flow.length) bd.appendChild(flowBlock(f.data_flow));
    if (f.fix_suggestion || f.fix_example || (f.references && f.references.length)) {
      bd.appendChild(remediation(f));
    }
    if ((f.cwe && f.cwe.length) || f.owasp) {
      const tags = el("div", "tags");
      (f.cwe || []).forEach((c) => tags.appendChild(el("span", "tag", c)));
      if (f.owasp) tags.appendChild(el("span", "tag", f.owasp));
      bd.appendChild(tags);
    }
    art.appendChild(bd);
    return art;
  }

  function codeBlock(snippet, startLine) {
    const box = el("div", "code");
    const lines = snippet.replace(/\n$/, "").split("\n");
    const first = Math.max(1, startLine - 2); // el snippet incluye ~2 líneas de contexto
    lines.forEach((line, i) => {
      const no = first + i;
      const row = el("div", "ln" + (no === startLine ? " hot" : ""));
      row.append(el("span", "no", String(no)), el("span", "src", line || " "));
      box.appendChild(row);
    });
    return box;
  }

  function flowBlock(steps) {
    const w = el("div", "flow");
    w.appendChild(el("div", "ttl", "Flujo de datos"));
    const ol = el("ol");
    steps.forEach((s) => {
      const li = el("li");
      li.append(el("code", null, `${s.location.path}:${s.location.start_line}`), document.createTextNode(" — " + s.message));
      ol.appendChild(li);
    });
    w.appendChild(ol);
    return w;
  }

  function remediation(f) {
    const box = el("div", "remedy");
    const head = el("div", "remedy-h");
    const ico = el("span", "remedy-ico"); ico.innerHTML = I.wrench;
    head.append(ico, el("span", null, "Cómo solucionarlo"));
    box.appendChild(head);
    if (f.fix_suggestion) box.appendChild(el("p", "remedy-txt", f.fix_suggestion));
    if (f.fix_example) {
      box.appendChild(el("div", "safe-label", "Ejemplo seguro"));
      box.appendChild(el("pre", "safe-code", f.fix_example.replace(/\n$/, "")));
    }
    if (f.references && f.references.length) {
      const refs = el("div", "refs");
      f.references.forEach((url) => {
        const a = el("a");
        a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer";
        a.append(document.createTextNode("Más información "));
        const ic = el("span"); ic.innerHTML = I.ext; a.appendChild(ic);
        refs.appendChild(a);
      });
      box.appendChild(refs);
    }
    return box;
  }

  function emptyState() {
    const e = el("div", "empty");
    const ico = el("div", "ok-ico"); ico.innerHTML = I.check;
    e.appendChild(ico);
    e.appendChild(el("h3", null, "No se han detectado vulnerabilidades"));
    e.appendChild(el("p", null, `Analizamos ${filesScanned} fichero(s) y no encontramos problemas con las reglas actuales.`));
    const btn = el("button", "btn btn-ghost"); btn.style.marginTop = "18px";
    btn.innerHTML = I.back; btn.append(document.createTextNode(" Analizar otro"));
    btn.addEventListener("click", reset);
    e.appendChild(btn);
    return e;
  }

  function reset() {
    files = []; findings = [];
    renderFiles();
    resultsView.innerHTML = "";
    alertEl.classList.add("hidden");
    show(uploadView);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
})();
