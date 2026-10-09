// EgressIQ web UI. All user/payload text is inserted with textContent, never innerHTML.
(() => {
  "use strict";

  const ALLOWED = [".txt", ".json", ".csv", ".log"];
  const MAX_BYTES = 5 * 1024 * 1024;
  const MAX_RENDER_LINES = 4000;
  const DEFAULT_SOURCE = "pasted-input.txt";

  const $ = (id) => document.getElementById(id);
  const el = {
    payload: $("payload"), sourceChip: $("source-chip"), samples: $("samples"),
    fileInput: $("file-input"), inputCard: $("input-card"), liveToggle: $("live-toggle"),
    scanBtn: $("scan-btn"), scanKbd: $("scan-kbd"), copyBtn: $("copy-btn"), pdfBtn: $("pdf-btn"),
    kpiTotal: $("kpi-total"), kpiTotalSub: $("kpi-total-sub"), kpiSecrets: $("kpi-secrets"), kpiPii: $("kpi-pii"),
    kpiRisk: $("kpi-risk"), riskLevel: $("risk-level"), riskScore: $("risk-score"),
    riskMeter: $("risk-meter"), riskSummary: $("risk-summary"), scanMeta: $("scan-meta"),
    rawPane: $("raw-pane"), cleanPane: $("clean-pane"), rawBadge: $("raw-badge"), cleanBadge: $("clean-badge"),
    findingsBody: $("findings-body"), findingsCount: $("findings-count"),
    engineText: $("engine-text"), enginePill: $("engine-pill"), toast: $("toast"), host: $("host"),
    maskBtn: $("mask-btn"), unmaskBtn: $("unmask-btn"), maskedBody: $("masked-body"),
  };
  const MASK_KEY = "egressiq.maskRaw";

  const state = { source: DEFAULT_SOURCE, result: null, seq: 0, controller: null, samples: [], masked: false };

  // ── Helpers ────────────────────────────────────────────
  function node(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  let toastTimer;
  function toast(msg, kind) {
    el.toast.textContent = msg;
    el.toast.className = "toast show" + (kind ? " " + kind : "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.toast.className = "toast"; }, 3200);
  }

  function setSource(name) {
    state.source = name || DEFAULT_SOURCE;
    el.sourceChip.textContent = state.source;
    el.sourceChip.title = "Source name used in the audit report: " + state.source;
  }

  function animateNumber(target, to) {
    const from = Number(target.dataset.val || 0);
    target.dataset.val = to;
    if (to === 0) target.setAttribute("data-zero", ""); else target.removeAttribute("data-zero");
    if (from === to || matchMedia("(prefers-reduced-motion: reduce)").matches) { target.textContent = to; return; }
    const start = performance.now(), dur = 420;
    const step = (now) => {
      const t = Math.min(1, (now - start) / dur);
      target.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - t, 3)));
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  async function errorMessage(res) {
    try { const j = await res.json(); return j.detail || res.statusText; } catch { return res.statusText; }
  }

  // ── Rendering ──────────────────────────────────────────
  function toLines(segments) {
    const lines = [[]];
    for (const seg of segments) {
      const parts = seg.t.split("\n");
      parts.forEach((part, i) => {
        if (i > 0) lines.push([]);
        if (part) lines[lines.length - 1].push({ t: part, f: seg.f });
      });
    }
    if (lines.length > 1 && lines[lines.length - 1].length === 0) lines.pop();
    return lines;
  }

  function renderPane(pane, segments, findings, sanitized) {
    const lines = toLines(segments);
    const frag = document.createDocumentFragment();
    const shown = Math.min(lines.length, MAX_RENDER_LINES);
    for (let i = 0; i < shown; i++) {
      const row = node("div", "ln");
      row.appendChild(node("span", "ln-no", String(i + 1)));
      const code = node("span", "ln-code");
      for (const piece of lines[i]) {
        if (piece.f === undefined) {
          code.appendChild(document.createTextNode(piece.t));
        } else {
          const f = findings[piece.f];
          const cls = sanitized ? "redacted" : "sev-" + f.severity + (state.masked ? " masked" : "");
          const m = node("mark", cls, piece.t);
          m.dataset.f = piece.f;
          m.title = sanitized
            ? `${f.detector} redacted (${f.severity})`
            : `${f.detector} · ${f.severity} · ${f.category}`;
          code.appendChild(m);
        }
      }
      row.appendChild(code);
      frag.appendChild(row);
    }
    pane.replaceChildren(frag);
    if (lines.length > shown) {
      pane.appendChild(node("div", "pane-note",
        `Showing first ${shown.toLocaleString()} of ${lines.length.toLocaleString()} lines. The audit PDF covers the full payload.`));
    }
  }

  function renderFindings(findings) {
    const frag = document.createDocumentFragment();
    findings.forEach((f, i) => {
      const tr = node("tr");
      tr.dataset.f = i;
      tr.tabIndex = 0;
      const sev = node("td"); sev.appendChild(node("span", "sev sev-" + f.severity, f.severity));
      tr.append(sev, node("td", "det", f.detector), node("td", "cat", f.category),
        node("td", "num", String(f.line)), node("td", "mono", f.masked));
      frag.appendChild(tr);
    });
    el.findingsBody.replaceChildren(frag);
    el.findingsCount.textContent = String(findings.length);
    el.findingsBody.closest(".card").classList.toggle("is-clean", findings.length === 0);
  }

  function render(r) {
    state.result = r;
    const s = r.stats;
    animateNumber(el.kpiTotal, s.total);
    animateNumber(el.kpiSecrets, s.secrets_blocked);
    animateNumber(el.kpiPii, s.pii_redacted);
    const sev = s.by_severity;
    const parts = ["critical", "high", "medium", "low"].filter((k) => sev[k]).map((k) => `${sev[k]} ${k}`);
    el.kpiTotalSub.textContent = parts.length ? parts.join(" · ") : "Across all detectors";

    el.kpiRisk.dataset.level = s.risk.level;
    el.riskLevel.textContent = s.risk.level;
    el.riskScore.textContent = s.risk.score;
    el.riskMeter.style.width = Math.max(s.risk.score, s.total ? 4 : 0) + "%";
    el.riskSummary.textContent = s.risk.summary;

    renderRaw();
    renderPane(el.cleanPane, r.clean_segments, r.findings, true);
    el.rawBadge.textContent = s.total === 1 ? "1 leak" : `${s.total} leaks`;
    el.rawBadge.classList.toggle("is-zero", s.total === 0);
    el.cleanBadge.textContent = s.total ? `${s.total} redacted · safe to forward` : "Safe to forward";
    renderFindings(r.findings);

    el.scanMeta.replaceChildren();
    const meta = [
      ["Scanned ", r.lines.toLocaleString(), " lines · "],
      ["", r.chars.toLocaleString(), " chars in "],
      ["", r.elapsed_ms.toFixed(2) + " ms", ""],
    ];
    for (const [a, b, c] of meta) {
      el.scanMeta.append(a); el.scanMeta.appendChild(node("b", null, b)); el.scanMeta.append(c);
    }
  }

  // ── Mask raw values (presenter mode) ───────────────────
  // Swap each finding's raw text for the server-provided masked preview.
  function maskedSegments(segments, findings) {
    return segments.map((s) => (s.f === undefined ? s : { t: findings[s.f].masked, f: s.f }));
  }

  function renderRaw() {
    const r = state.result;
    if (!r) return;
    if (state.masked) {
      const segs = maskedSegments(r.raw_segments, r.findings);
      renderPane(el.rawPane, segs, r.findings, false);
      renderPane(el.maskedBody, segs, r.findings, false);
    } else {
      renderPane(el.rawPane, r.raw_segments, r.findings, false);
      el.maskedBody.replaceChildren();
    }
  }

  function setMasked(on, persist) {
    state.masked = on;
    document.body.classList.toggle("is-masked", on);
    el.maskBtn.setAttribute("aria-pressed", String(on));
    el.maskBtn.querySelector(".mask-label").textContent = on ? "Raw values masked" : "Mask raw values";
    if (persist) { try { localStorage.setItem(MASK_KEY, on ? "1" : "0"); } catch {} }
    renderRaw();
  }

  function initialMask() {
    const q = new URLSearchParams(location.search).get("mask");
    if (q !== null) return q === "1" || q === "true";
    try { return localStorage.getItem(MASK_KEY) === "1"; } catch { return false; }
  }

  // ── Cross-highlighting ─────────────────────────────────
  function setActive(idx, on) {
    document.querySelectorAll(`[data-f="${idx}"]`).forEach((n) => n.classList.toggle("is-active", on));
  }
  function bindHover(container) {
    container.addEventListener("mouseover", (e) => {
      const t = e.target.closest("[data-f]"); if (t) setActive(t.dataset.f, true);
    });
    container.addEventListener("mouseout", (e) => {
      const t = e.target.closest("[data-f]"); if (t) setActive(t.dataset.f, false);
    });
  }
  [el.rawPane, el.cleanPane, el.findingsBody, el.maskedBody].forEach(bindHover);

  function jumpTo(idx) {
    // Position each pane on its own mark; suppress the proportional sync meanwhile.
    scrollLead = "jump";
    clearTimeout(leadTimer);
    leadTimer = setTimeout(() => { scrollLead = null; }, 200);
    for (const pane of [el.rawPane, el.cleanPane]) {
      const m = pane.querySelector(`mark[data-f="${idx}"]`);
      if (!m) continue;
      pane.scrollTop += m.getBoundingClientRect().top - pane.getBoundingClientRect().top - pane.clientHeight / 3;
      m.classList.remove("flash"); void m.offsetWidth; m.classList.add("flash");
    }
    el.rawPane.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
  el.findingsBody.addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-f]"); if (tr) jumpTo(tr.dataset.f);
  });
  el.findingsBody.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      const tr = e.target.closest("tr[data-f]"); if (tr) { e.preventDefault(); jumpTo(tr.dataset.f); }
    }
  });

  // Proportional scroll sync between panes.
  let scrollLead = null, leadTimer;
  function syncScroll(from, to) {
    from.addEventListener("scroll", () => {
      if (scrollLead && scrollLead !== from) return;
      scrollLead = from;
      clearTimeout(leadTimer);
      leadTimer = setTimeout(() => { scrollLead = null; }, 120);
      const max = from.scrollHeight - from.clientHeight;
      to.scrollTop = max > 0 ? (from.scrollTop / max) * (to.scrollHeight - to.clientHeight) : 0;
    });
  }
  syncScroll(el.rawPane, el.cleanPane);
  syncScroll(el.cleanPane, el.rawPane);

  // ── API calls ──────────────────────────────────────────
  async function runScan() {
    const text = el.payload.value;
    if (state.controller) state.controller.abort();
    const controller = new AbortController();
    state.controller = controller;
    const seq = ++state.seq;
    document.body.classList.add("is-busy");
    try {
      const res = await fetch("/api/scan", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, source_name: state.source }), signal: controller.signal,
      });
      if (!res.ok) throw new Error(await errorMessage(res));
      const data = await res.json();
      if (seq === state.seq) render(data);
    } catch (err) {
      if (err.name !== "AbortError") toast("Scan failed: " + err.message, "error");
    } finally {
      if (seq === state.seq) document.body.classList.remove("is-busy");
    }
  }

  async function uploadFile(file) {
    const ext = (file.name.match(/\.[^.]+$/) || [""])[0].toLowerCase();
    if (!ALLOWED.includes(ext)) { toast(`Unsupported file type "${ext || file.name}". Use ${ALLOWED.join(", ")}`, "error"); return; }
    if (file.size > MAX_BYTES) { toast("File exceeds the 5 MB limit", "error"); return; }
    const fd = new FormData();
    fd.append("file", file);
    if (state.controller) state.controller.abort();
    const seq = ++state.seq;
    document.body.classList.add("is-busy");
    try {
      const res = await fetch("/api/upload", { method: "POST", body: fd });
      if (!res.ok) throw new Error(await errorMessage(res));
      const data = await res.json();
      if (seq !== state.seq) return;
      el.payload.value = data.text;
      setSource(data.source_name);
      setPressedSample(null);
      render(data);
      toast(`Scanned ${data.source_name}: ${data.stats.total} finding(s)`, data.stats.total ? "error" : "success");
    } catch (err) {
      toast("Upload failed: " + err.message, "error");
    } finally {
      if (seq === state.seq) document.body.classList.remove("is-busy");
    }
  }

  async function downloadPdf() {
    el.pdfBtn.disabled = true;
    el.pdfBtn.classList.add("is-loading");
    try {
      const res = await fetch("/api/report", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: el.payload.value, source_name: state.source }),
      });
      if (!res.ok) throw new Error(await errorMessage(res));
      const blob = await res.blob();
      const cd = res.headers.get("Content-Disposition") || "";
      const name = (cd.match(/filename="([^"]+)"/) || [, "EgressIQ-Audit.pdf"])[1];
      const url = URL.createObjectURL(blob);
      const a = node("a"); a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      toast("Executive audit PDF downloaded: " + name, "success");
    } catch (err) {
      toast("PDF export failed: " + err.message, "error");
    } finally {
      el.pdfBtn.disabled = false;
      el.pdfBtn.classList.remove("is-loading");
    }
  }

  async function copySanitized() {
    if (!state.result) return;
    try {
      await navigator.clipboard.writeText(state.result.sanitized);
      toast("Sanitized payload copied to clipboard", "success");
    } catch {
      toast("Clipboard unavailable in this browser", "error");
    }
  }

  // ── Samples ────────────────────────────────────────────
  function setPressedSample(id) {
    el.samples.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.id === id)));
  }
  function loadSample(s) {
    el.payload.value = s.text;
    setSource(s.filename);
    setPressedSample(s.id);
    runScan();
  }
  async function initSamples() {
    try {
      const res = await fetch("/api/samples");
      state.samples = await res.json();
      for (const s of state.samples) {
        const b = node("button", null, s.label);
        b.type = "button"; b.dataset.id = s.id; b.title = "Load sample: " + s.filename;
        b.addEventListener("click", () => loadSample(s));
        el.samples.appendChild(b);
      }
      if (state.samples.length) loadSample(state.samples[0]);
    } catch (err) {
      toast("Could not load samples: " + err.message, "error");
    }
  }

  async function initHealth() {
    try {
      const res = await fetch("/api/health");
      const h = await res.json();
      el.engineText.textContent = `Engine online · ${h.detectors} detectors`;
      el.enginePill.classList.add("is-up");
    } catch {
      el.engineText.textContent = "Engine offline";
      el.enginePill.classList.add("is-down");
    }
  }

  // ── Events ─────────────────────────────────────────────
  let debounce;
  el.payload.addEventListener("input", () => {
    if (state.source !== DEFAULT_SOURCE) { setSource(DEFAULT_SOURCE); setPressedSample(null); }
    if (!el.liveToggle.checked) return;
    clearTimeout(debounce);
    debounce = setTimeout(runScan, 250);
  });
  el.payload.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); clearTimeout(debounce); runScan(); }
  });
  el.scanBtn.addEventListener("click", runScan);
  el.maskBtn.addEventListener("click", () => {
    setMasked(!state.masked, true);
    toast(state.masked ? "Raw values masked for screen sharing" : "Raw values visible", "success");
  });
  el.unmaskBtn.addEventListener("click", () => { setMasked(false, true); el.payload.focus(); });
  document.addEventListener("keydown", (e) => {
    const typing = e.target.closest && e.target.closest("textarea, input");
    if (!typing && e.shiftKey && !e.metaKey && !e.ctrlKey && !e.altKey && e.key.toLowerCase() === "m") {
      e.preventDefault(); el.maskBtn.click();
    }
  });
  el.pdfBtn.addEventListener("click", downloadPdf);
  el.copyBtn.addEventListener("click", copySanitized);
  el.fileInput.addEventListener("change", () => {
    if (el.fileInput.files[0]) uploadFile(el.fileInput.files[0]);
    el.fileInput.value = "";
  });

  // Drag & drop onto the input card (and prevent the browser opening files dropped elsewhere).
  let dragDepth = 0;
  el.inputCard.addEventListener("dragenter", (e) => { e.preventDefault(); dragDepth++; el.inputCard.classList.add("is-dragging"); });
  el.inputCard.addEventListener("dragover", (e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; });
  el.inputCard.addEventListener("dragleave", () => { if (--dragDepth <= 0) { dragDepth = 0; el.inputCard.classList.remove("is-dragging"); } });
  el.inputCard.addEventListener("drop", (e) => {
    e.preventDefault(); dragDepth = 0; el.inputCard.classList.remove("is-dragging");
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) uploadFile(file);
  });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());

  if (!/Mac|iPhone|iPad/.test(navigator.platform)) el.scanKbd.textContent = "Ctrl↵";
  el.host.textContent = location.host;

  setMasked(initialMask(), false);
  initHealth();
  initSamples();
})();
