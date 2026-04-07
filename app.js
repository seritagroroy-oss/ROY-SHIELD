const urlInput = document.getElementById("urlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const analyzeTextBtn = document.getElementById("analyzeTextBtn");
const textInput = document.getElementById("textInput");
const resultSection = document.getElementById("resultSection");
const multiResultSection = document.getElementById("multiResultSection");
const loadingOverlay = document.getElementById("loadingOverlay");
const micUrlBtn = document.getElementById("micUrlBtn");
const micTextBtn = document.getElementById("micTextBtn");
const appSections = Array.from(document.querySelectorAll(".app-section"));
const sectionNavLinks = Array.from(document.querySelectorAll(".nav-link[data-section]"));
const sectionSwitchButtons = Array.from(document.querySelectorAll("[data-section-switch]"));

let currentResult = null;
let currentRawUrl = "";
let authMode = "login";
let currentUser = null;
let recognition = null;
let speechSupported = false;
let activeMicTarget = null;
let isListening = false;
const ADMIN_TOKEN_KEY = "royshield_admin_token";

// URL du backend Python — à remplacer par l'URL Render après déploiement
const BACKEND_URL =
  window.ROY_SHIELD_CONFIG?.backendUrl ||
  "http://127.0.0.1:8000";

const AUTH_TOKEN_KEY = "royshield_auth_token";

function getAuthToken() {
  return localStorage.getItem(AUTH_TOKEN_KEY) || "";
}

function getAuthHeaders() {
  const token = getAuthToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function callPythonBackend(url) {
  try {
    const resp = await fetch(BACKEND_URL + "/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...getAuthHeaders() },
      body: JSON.stringify({ url })
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

async function fetchBackendJSON(path) {
  try {
    const response = await fetch(BACKEND_URL + path, {
      headers: { ...getAuthHeaders() }
    });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

// ─── Event listeners ───────────────────────────────────────────────────────────

urlInput.addEventListener("keydown", e => { if (e.key === "Enter") runScan(); });
analyzeBtn.addEventListener("click", runScan);
analyzeTextBtn.addEventListener("click", runTextScan);
textInput.addEventListener("input", onTextInput);
document.getElementById("historyToggleBtn").addEventListener("click", openHistoryPanel);
document.getElementById("vtSettingsBtn").addEventListener("click", openVTModal);
document.getElementById("exportBtn").addEventListener("click", exportReport);
document.getElementById("reportBtn").addEventListener("click", openReportModal);
document.getElementById("workspaceBtn").addEventListener("click", () => showAppSection("workspace"));
document.getElementById("openAuthModalBtn").addEventListener("click", openAuthModal);
document.getElementById("workspaceRefreshBtn").addEventListener("click", refreshWorkspace);
document.getElementById("workspaceLogoutBtn").addEventListener("click", logoutWorkspace);
document.getElementById("shareCurrentReportBtn").addEventListener("click", shareCurrentReport);
document.getElementById("loadAdminReportsBtn").addEventListener("click", loadAdminReports);
if (micUrlBtn) micUrlBtn.addEventListener("click", () => toggleSpeechInput("url"));
if (micTextBtn) micTextBtn.addEventListener("click", () => toggleSpeechInput("text"));
sectionNavLinks.forEach(link => {
  link.addEventListener("click", event => {
    event.preventDefault();
    showAppSection(link.dataset.section);
  });
});
sectionSwitchButtons.forEach(button => {
  button.addEventListener("click", () => showAppSection(button.dataset.sectionSwitch));
});
["dashboardDaysFilter", "dashboardLevelFilter", "dashboardReportTypeFilter"].forEach(id => {
  const element = document.getElementById(id);
  if (element) element.addEventListener("change", refreshLiveDashboard);
});

// #5 — Jauge temps réel
urlInput.addEventListener("input", () => {
  const val = urlInput.value.trim();
  const wrap = document.getElementById("realtimeBarWrap");
  if (!val) { wrap.style.display = "none"; return; }
  wrap.style.display = "flex";
  const r = analyzeURL(val);
  const fill = document.getElementById("realtimeBarFill");
  const label = document.getElementById("realtimeLabel");
  fill.style.width = r.score + "%";
  fill.style.background = r.level === "safe" ? "var(--safe)" : r.level === "warn" ? "var(--warn)" : "var(--danger)";
  label.textContent = r.verdict;
  label.style.color = r.level === "safe" ? "var(--safe)" : r.level === "warn" ? "var(--warn)" : "var(--danger)";
});

// ─── Tabs ──────────────────────────────────────────────────────────────────────

function switchTab(tab) {
  document.getElementById("tabUrl").classList.toggle("active", tab === "url");
  document.getElementById("tabText").classList.toggle("active", tab === "text");
  document.getElementById("panelUrl").classList.toggle("hidden", tab !== "url");
  document.getElementById("panelText").classList.toggle("hidden", tab !== "text");
  updateMicButtons();
}

function showAppSection(section) {
  appSections.forEach(item => {
    item.classList.toggle("is-active", item.dataset.section === section);
  });
  sectionNavLinks.forEach(link => {
    link.classList.toggle("active", link.dataset.section === section);
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ─── Text mode ─────────────────────────────────────────────────────────────────

function onTextInput() {
  const text = textInput.value;
  const urls = extractURLsFromText(text);
  const el = document.getElementById("textFoundCount");
  if (!text.trim()) { el.textContent = "Collez un texte pour extraire les liens"; return; }
  el.textContent = urls.length === 0
    ? "Aucun lien détecté dans ce texte"
    : `${urls.length} lien(s) détecté(s) — prêt à analyser`;
  el.style.color = urls.length > 0 ? "var(--warn)" : "var(--muted)";
}

function runTextScan() {
  const text = textInput.value.trim();
  if (!text) { textInput.focus(); return; }
  const urls = extractURLsFromText(text);
  if (urls.length === 0) {
    showToast("Aucun lien trouvé dans ce texte.", "warn");
    return;
  }
  analyzeTextBtn.disabled = true;
  showLoading("Extraction et analyse de " + urls.length + " lien(s)…").then(async () => {
    const results = [];
    for (const u of urls) {
      const local = analyzeURL(u);
      const py = await callPythonBackend(u);
      results.push(mergeResults(local, py));
    }
    renderMultiResults(results);
    results.forEach(r => saveToHistory(r));
    refreshLiveDashboard();
    analyzeTextBtn.disabled = false;
  });
}

function renderMultiResults(results) {
  resultSection.classList.add("hidden");
  multiResultSection.classList.remove("hidden");

  const counts = { danger: 0, warn: 0, safe: 0 };
  results.forEach(r => counts[r.level]++);
  document.getElementById("multiResultCount").innerHTML =
    `<span style="color:var(--danger)">${counts.danger} arnaque(s)</span> · ` +
    `<span style="color:var(--warn)">${counts.warn} suspect(s)</span> · ` +
    `<span style="color:var(--safe)">${counts.safe} fiable(s)</span>`;

  const list = document.getElementById("multiResultsList");
  list.innerHTML = "";

  results.forEach((r, idx) => {
    const item = document.createElement("div");
    item.className = `multi-result-item level-${r.level}`;
    item.style.animationDelay = `${idx * 60}ms`;
    const levelLabel = { safe: "Fiable", warn: "Suspect", danger: "Arnaque probable" };
    const levelIcon = { safe: "✅", warn: "⚠️", danger: "❌" };
    item.innerHTML = `
      <div class="multi-item-left">
        <span class="multi-item-icon">${levelIcon[r.level]}</span>
        <div>
          <div class="multi-item-verdict">${levelLabel[r.level]}</div>
          <div class="multi-item-url">${r.url.length > 60 ? r.url.substring(0, 57) + "…" : r.url}</div>
        </div>
      </div>
      <div class="multi-item-right">
        <div class="multi-item-score level-${r.level}">${r.score}</div>
        <div class="multi-item-score-label">/ 100</div>
      </div>
    `;
    item.addEventListener("click", () => {
      openReportModal_scan(r);
    });
    list.appendChild(item);
  });

  setTimeout(() => {
    multiResultSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 50);
}

// ─── Single scan ───────────────────────────────────────────────────────────────

const ICONS = { check: "✓", warn: "!", x: "✕" };

function showLoading(text) {
  loadingOverlay.classList.remove("hidden");
  document.getElementById("loadingText").textContent = text || "Analyse en cours…";
  const steps = ["lstep1", "lstep2", "lstep3", "lstep4"].map(id => document.getElementById(id));
  steps.forEach(s => s.classList.remove("active", "done"));
  let i = 0;
  return new Promise(resolve => {
    const tick = () => {
      if (i > 0) { steps[i - 1].classList.remove("active"); steps[i - 1].classList.add("done"); }
      if (i < steps.length) { steps[i].classList.add("active"); i++; setTimeout(tick, 380); }
      else { setTimeout(() => { loadingOverlay.classList.add("hidden"); resolve(); }, 200); }
    };
    tick();
  });
}

function runScan() {
  const raw = urlInput.value.trim();
  if (!raw) {
    urlInput.focus();
    urlInput.style.outline = "2px solid var(--danger)";
    setTimeout(() => { urlInput.style.outline = ""; }, 1200);
    return;
  }
  analyzeBtn.disabled = true;
  showLoading().then(async () => {
    const localResult = analyzeURL(raw);
    const pyResult = await callPythonBackend(raw);
    const merged = mergeResults(localResult, pyResult);
    currentResult = merged;
    currentRawUrl = raw;
    saveToHistory(merged);
    runVirusTotalCheck(raw);
    openReportModal_scan(merged);
    refreshLiveDashboard();
    analyzeBtn.disabled = false;
  });
}

function mergeResults(local, py) {
  if (!py) return { ...local, pythonAvailable: false };
  const combined = {
    url: local.url,
    score: Math.min(Math.max(local.score, py.score), 100),
    signals: [...local.signals, ...(py.python_signals || [])],
    whois: py.whois || {},
    ssl: py.ssl || {},
    content_analyzed: py.content_analyzed || false,
    pythonAvailable: true,
  };
  if (combined.score >= 60) { combined.verdict = "Arnaque probable"; combined.level = "danger"; }
  else if (combined.score >= 30) { combined.verdict = "Site suspect"; combined.level = "warn"; }
  else { combined.verdict = "Site fiable"; combined.level = "safe"; }
  return combined;
}

function openReportModal_scan(result) {
  currentResult = result;
  buildScanReport(result);
  document.getElementById("scanReportModal").classList.remove("hidden");
  document.body.style.overflow = "hidden";
}

function closeScanReport() {
  document.getElementById("scanReportModal").classList.add("hidden");
  document.body.style.overflow = "";
}

function buildScanReport(result) {
  const modal = document.getElementById("scanReportModal");
  modal.className = "scan-report-modal level-" + result.level;

  const emojiMap = { safe: "✅", warn: "⚠️", danger: "❌" };
  const colorMap = { safe: "var(--safe)", warn: "var(--warn)", danger: "var(--danger)" };

  document.getElementById("srVerdict").textContent = result.verdict;
  document.getElementById("srVerdict").style.color = colorMap[result.level];
  document.getElementById("srIcon").textContent = emojiMap[result.level];
  document.getElementById("srUrl").textContent = result.url;
  document.getElementById("srScore").textContent = result.score;
  document.getElementById("srScore").style.color = colorMap[result.level];
  document.getElementById("srScoreBar").style.width = result.score + "%";
  document.getElementById("srScoreBar").style.background = colorMap[result.level];

  const pyBadge = document.getElementById("srPyBadge");
  pyBadge.style.display = result.pythonAvailable ? "inline-flex" : "none";

  const whoisEl = document.getElementById("srWhois");
  if (result.pythonAvailable && result.whois && result.whois.found) {
    const age = result.whois.age_days != null ? result.whois.age_days + " jours" : "inconnu";
    const ageColor = result.whois.age_days < 30 ? "var(--danger)" : result.whois.age_days < 180 ? "var(--warn)" : "var(--safe)";
    whoisEl.innerHTML = `
      <div class="sr-meta-item"><span class="sr-meta-label">Age du domaine</span><span class="sr-meta-val" style="color:${ageColor}">${age}</span></div>
      <div class="sr-meta-item"><span class="sr-meta-label">Registrar</span><span class="sr-meta-val">${result.whois.registrar || "Inconnu"}</span></div>
      <div class="sr-meta-item"><span class="sr-meta-label">Créé le</span><span class="sr-meta-val">${result.whois.creation || "?"}</span></div>
    `;
    whoisEl.parentElement.style.display = "block";
  } else {
    whoisEl.parentElement.style.display = result.pythonAvailable ? "block" : "none";
    whoisEl.innerHTML = result.pythonAvailable
      ? '<div class="sr-meta-item"><span class="sr-meta-label">WHOIS</span><span class="sr-meta-val" style="color:var(--muted)">Non disponible</span></div>'
      : "";
  }

  const sslEl = document.getElementById("srSsl");
  if (result.pythonAvailable && result.ssl && typeof result.ssl.valid !== "undefined") {
    const sslColor = result.ssl.valid ? "var(--safe)" : "var(--danger)";
    const sslText = result.ssl.valid
      ? `Valide — ${result.ssl.days_left} jour(s) restants`
      : `Invalide — ${result.ssl.error || "erreur SSL"}`;
    sslEl.innerHTML = `<div class="sr-meta-item"><span class="sr-meta-label">Certificat SSL</span><span class="sr-meta-val" style="color:${sslColor}">${sslText}</span></div>`;
    sslEl.parentElement.style.display = "block";
  } else {
    sslEl.parentElement.style.display = "none";
  }

  const contentBadge = document.getElementById("srContentBadge");
  contentBadge.style.display = result.content_analyzed ? "inline-flex" : "none";

  const grid = document.getElementById("srSignals");
  grid.innerHTML = "";
  const allSignals = result.signals || [];
  allSignals.forEach((signal, idx) => {
    const item = document.createElement("div");
    item.className = `sr-signal type-${signal.type}`;
    if (signal.source === "python") item.classList.add("sr-signal-python");
    item.style.animationDelay = `${idx * 50}ms`;
    item.innerHTML = `
      <div class="sr-signal-icon">${ICONS[signal.icon] || signal.icon}</div>
      <div class="sr-signal-body">
        <div class="sr-signal-label">${signal.label}${signal.source === "python" ? ' <span class="sr-py-tag">Python</span>' : ""}</div>
        <div class="sr-signal-detail">${signal.detail}</div>
      </div>
    `;
    grid.appendChild(item);
  });

  if (allSignals.length === 0) {
    grid.innerHTML = '<p style="color:var(--muted);font-size:0.85rem;text-align:center;padding:20px">Aucun signal détecté.</p>';
  }
}

function resetScanner() {
  stopSpeechRecognition();
  resultSection.classList.add("hidden");
  multiResultSection.classList.add("hidden");
  document.getElementById("scanReportModal").classList.add("hidden");
  document.body.style.overflow = "";
  urlInput.value = "";
  textInput.value = "";
  document.getElementById("realtimeBarWrap").style.display = "none";
  document.getElementById("textFoundCount").textContent = "Collez un texte pour extraire les liens";
  currentResult = null;
  currentRawUrl = "";
  document.getElementById("bgGlow").style.background = "";
  window.scrollTo({ top: 0, behavior: "smooth" });
  urlInput.focus();
}

function initSpeechRecognition() {
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  speechSupported = Boolean(SpeechRecognition);

  if (!speechSupported) {
    updateMicButtons();
    return;
  }

  recognition = new SpeechRecognition();
  recognition.lang = "fr-FR";
  recognition.interimResults = true;
  recognition.continuous = false;
  recognition.maxAlternatives = 1;

  recognition.onstart = () => {
    isListening = true;
    updateMicButtons();
    showToast(activeMicTarget === "text" ? "Micro actif pour la dictée du texte." : "Micro actif pour la dictée du lien.", "safe");
  };

  recognition.onresult = event => {
    let transcript = "";
    for (let i = event.resultIndex; i < event.results.length; i += 1) {
      transcript += event.results[i][0].transcript;
    }
    transcript = transcript.trim();
    if (!transcript) return;

    if (activeMicTarget === "text") {
      textInput.value = textInput.value.trim() ? `${textInput.value.trim()} ${transcript}` : transcript;
      onTextInput();
    } else {
      urlInput.value = transcript;
      urlInput.dispatchEvent(new Event("input"));
    }
  };

  recognition.onerror = event => {
    isListening = false;
    updateMicButtons();
    const code = event.error || "unknown";
    if (code === "not-allowed" || code === "service-not-allowed") {
      showToast("Permission micro refusee par le navigateur.", "warn");
    } else if (code === "no-speech") {
      showToast("Aucune voix detectee. Reessaie en parlant plus pres du micro.", "warn");
    } else if (code === "audio-capture") {
      showToast("Aucun micro disponible ou actif sur cet appareil.", "warn");
    } else {
      showToast("La reconnaissance vocale a rencontre un probleme.", "warn");
    }
  };

  recognition.onend = () => {
    isListening = false;
    updateMicButtons();
  };

  updateMicButtons();
}

async function toggleSpeechInput(target) {
  if (!speechSupported || !recognition) {
    showToast("La dictée vocale n'est pas supportee par ce navigateur.", "warn");
    return;
  }

  if (isListening && activeMicTarget === target) {
    stopSpeechRecognition();
    return;
  }

  activeMicTarget = target;
  try {
    if (navigator.mediaDevices?.getUserMedia) {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      stream.getTracks().forEach(track => track.stop());
    }
    recognition.start();
  } catch {
    isListening = false;
    updateMicButtons();
    showToast("Impossible d'acceder au micro. Verifie les permissions du navigateur.", "warn");
  }
}

function stopSpeechRecognition() {
  if (recognition && isListening) {
    recognition.stop();
  }
  isListening = false;
  activeMicTarget = null;
  updateMicButtons();
}

function updateMicButtons() {
  const disabled = !speechSupported;
  [micUrlBtn, micTextBtn].forEach(btn => {
    if (!btn) return;
    btn.disabled = disabled;
    btn.classList.remove("is-listening");
  });

  if (disabled) {
    if (micUrlBtn) micUrlBtn.title = "Dictée vocale non supportee sur ce navigateur";
    if (micTextBtn) micTextBtn.title = "Dictée vocale non supportee sur ce navigateur";
    return;
  }

  if (activeMicTarget === "url" && isListening && micUrlBtn) micUrlBtn.classList.add("is-listening");
  if (activeMicTarget === "text" && isListening && micTextBtn) micTextBtn.classList.add("is-listening");
}

// ─── #1 Historique ─────────────────────────────────────────────────────────────

const HISTORY_KEY = "royshield_history";
const MAX_HISTORY = 50;

function saveToHistory(result) {
  let history = getHistory();
  history.unshift({
    url: result.url,
    score: result.score,
    level: result.level,
    verdict: result.verdict,
    date: new Date().toISOString()
  });
  if (history.length > MAX_HISTORY) history = history.slice(0, MAX_HISTORY);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  updateHistoryCount();
}

function getHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
  catch { return []; }
}

function updateHistoryCount() {
  const h = getHistory();
  const countEl = document.getElementById("historyCount");
  if (h.length > 0) {
    countEl.style.display = "inline-flex";
    countEl.textContent = h.length;
  } else {
    countEl.style.display = "none";
  }
}

function openHistoryPanel() {
  renderHistoryList();
  document.getElementById("historyPanel").classList.remove("hidden");
  document.getElementById("panelOverlay").classList.remove("hidden");
}

function closeHistoryPanel() {
  document.getElementById("historyPanel").classList.add("hidden");
  document.getElementById("panelOverlay").classList.add("hidden");
}

function renderHistoryList() {
  const list = document.getElementById("historyList");
  const history = getHistory();
  if (history.length === 0) {
    list.innerHTML = '<p class="history-empty">Aucun scan effectué.</p>';
    return;
  }
  list.innerHTML = history.map((item, idx) => {
    const date = new Date(item.date);
    const dateStr = date.toLocaleDateString("fr-FR") + " " + date.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
    const icon = { safe: "✅", warn: "⚠️", danger: "❌" }[item.level];
    const urlDisplay = item.url.length > 45 ? item.url.substring(0, 42) + "…" : item.url;
    return `
      <div class="history-item" onclick="loadFromHistory(${idx})">
        <div class="history-item-left">
          <span class="history-icon">${icon}</span>
          <div>
            <div class="history-url">${urlDisplay}</div>
            <div class="history-date">${dateStr}</div>
          </div>
        </div>
        <div class="history-score level-${item.level}">${item.score}</div>
      </div>
    `;
  }).join("");
}

function loadFromHistory(idx) {
  const history = getHistory();
  const item = history[idx];
  if (!item) return;
  urlInput.value = item.url;
  closeHistoryPanel();
  analyzeBtn.disabled = true;
  showLoading().then(async () => {
    const local = analyzeURL(item.url);
    const py = await callPythonBackend(item.url);
    const merged = mergeResults(local, py);
    currentResult = merged;
    currentRawUrl = item.url;
    openReportModal_scan(merged);
    refreshLiveDashboard();
    analyzeBtn.disabled = false;
  });
}

function formatRelativeDate(isoString) {
  if (!isoString) return "Aucun scan backend";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return "Aucun scan backend";
  return "Dernier scan: " + date.toLocaleString("fr-FR", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function getDashboardFilters() {
  return {
    days: document.getElementById("dashboardDaysFilter")?.value || "30",
    level: document.getElementById("dashboardLevelFilter")?.value || "",
    reportType: document.getElementById("dashboardReportTypeFilter")?.value || ""
  };
}

function getAdminToken() {
  return localStorage.getItem(ADMIN_TOKEN_KEY) || "";
}

function buildQuery(params) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") query.set(key, String(value));
  });
  const text = query.toString();
  return text ? `?${text}` : "";
}

function renderRecentScans(items) {
  const list = document.getElementById("recentScansList");
  if (!items || items.length === 0) {
    list.innerHTML = "<p class=\"live-feed-empty\">Les scans effectues via l'API apparaitront ici.</p>";
    return;
  }

  list.innerHTML = items.map(item => {
    const levelClass = item.level || "warn";
    const dateLabel = new Date(item.timestamp).toLocaleString("fr-FR", {
      day: "2-digit",
      month: "2-digit",
      hour: "2-digit",
      minute: "2-digit"
    });
    const sourceUrl = item.normalized_url || item.raw_url || "Lien inconnu";
    const urlLabel = sourceUrl.length > 54 ? sourceUrl.slice(0, 51) + "..." : sourceUrl;

    return `
      <div class="live-feed-item level-${levelClass}">
        <div class="live-feed-main">
          <div class="live-feed-url">${urlLabel}</div>
          <div class="live-feed-meta">${item.verdict || "Analyse"} - ${dateLabel}</div>
        </div>
        <div class="live-feed-score">${item.score ?? 0}</div>
      </div>
    `;
  }).join("");
}

function renderTrendChart(containerId, items, options = {}) {
  const container = document.getElementById(containerId);
  if (!container) return;

  if (!items || items.length === 0) {
    container.innerHTML = `<p class="analytics-empty">${options.emptyText || "Aucune donnee disponible."}</p>`;
    return;
  }

  const maxValue = Math.max(...items.map(item => item.count || 0), 1);
  const fillClass = options.reportStyle ? "trend-bar-fill is-report" : "trend-bar-fill";

  container.innerHTML = items.map(item => {
    const ratio = Math.max((item.count || 0) / maxValue, 0.08);
    const height = Math.round(ratio * 100);
    const date = new Date(`${item.day}T00:00:00`);
    const label = Number.isNaN(date.getTime())
      ? item.day
      : date.toLocaleDateString("fr-FR", { weekday: "short" });

    return `
      <div class="trend-bar">
        <div class="trend-bar-track">
          <div class="${fillClass}" style="height:${height}%"></div>
        </div>
        <div class="trend-bar-meta">
          <span class="trend-bar-value">${item.count ?? 0}</span>
          <span class="trend-bar-label">${label.replace(".", "")}</span>
        </div>
      </div>
    `;
  }).join("");
}

function renderRiskMix(stats) {
  const chart = document.getElementById("riskMixChart");
  const legend = document.getElementById("riskMixLegend");
  const summary = document.getElementById("riskMixSummary");
  if (!chart || !legend || !summary) return;

  const safe = stats.safe_scans ?? 0;
  const warn = stats.warn_scans ?? 0;
  const danger = stats.danger_scans ?? 0;
  const total = Math.max(safe + warn + danger, 0);

  summary.textContent = total > 0 ? `${total} scan(s)` : "0 scan";

  if (total === 0) {
    chart.style.background =
      "radial-gradient(circle at center, rgba(7,11,18,0.96) 0 39%, transparent 40%), conic-gradient(rgba(255,255,255,0.08) 0deg 360deg)";
    legend.innerHTML = '<p class="analytics-empty">La repartition apparaitra des que le backend aura des scans.</p>';
    return;
  }

  const safeDeg = (safe / total) * 360;
  const warnDeg = (warn / total) * 360;
  const dangerDeg = 360 - safeDeg - warnDeg;
  const warnEnd = safeDeg + warnDeg;

  chart.style.background = [
    "radial-gradient(circle at center, rgba(7,11,18,0.96) 0 39%, transparent 40%)",
    `conic-gradient(
      var(--safe) 0deg ${safeDeg}deg,
      var(--warn) ${safeDeg}deg ${warnEnd}deg,
      var(--danger) ${warnEnd}deg ${warnEnd + dangerDeg}deg
    )`
  ].join(", ");

  const levels = [
    { key: "safe", label: "Fiables", count: safe },
    { key: "warn", label: "Suspects", count: warn },
    { key: "danger", label: "Dangereux", count: danger }
  ];

  legend.innerHTML = levels.map(level => {
    const percent = total ? Math.round((level.count / total) * 100) : 0;
    return `
      <div class="mix-legend-item">
        <div class="mix-legend-main">
          <span class="mix-legend-dot ${level.key}"></span>
          <span>${level.label}</span>
        </div>
        <span class="mix-legend-value">${level.count} · ${percent}%</span>
      </div>
    `;
  }).join("");
}

function renderReportInsights(reportStats) {
  const summary = document.getElementById("reportsTrendSummary");
  const topType = document.getElementById("topReportType");
  const topMeta = document.getElementById("topReportTypeMeta");
  if (!summary || !topType || !topMeta) return;

  const total = reportStats?.total_reports ?? 0;
  summary.textContent = total > 0 ? `${total} signalement(s)` : "Aucun signalement";

  const entries = Object.entries(reportStats?.by_type || {}).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    topType.textContent = "Aucun";
    topMeta.textContent = "Aucune tendance detectee";
    return;
  }

  const [type, count] = entries[0];
  topType.textContent = type;
  topMeta.textContent = `${count} cas identifies dans les signalements recents`;
}

function renderAnalyticsPanels(stats) {
  renderTrendChart("scanTrendChart", stats?.trend_last_7_days || [], {
    emptyText: "Les tendances apparaitront apres les premiers scans."
  });
  renderTrendChart("reportsTrendChart", stats?.reports?.trend_last_7_days || [], {
    emptyText: "Les signalements apparaitront ici.",
    reportStyle: true
  });
  renderRiskMix(stats || {});
  renderReportInsights(stats?.reports || {});

  const scanTrendSummary = document.getElementById("scanTrendSummary");
  if (scanTrendSummary) {
    const trend = stats?.trend_last_7_days || [];
    const totalOnWindow = trend.reduce((sum, item) => sum + (item.count || 0), 0);
    scanTrendSummary.textContent = totalOnWindow > 0
      ? `${totalOnWindow} scan(s) sur 7 jours`
      : "Aucune activite recente";
  }

  renderAnalyticsDetail(stats || {});
}

function renderAnalyticsDetail(stats) {
  const peakRisk = document.getElementById("analyticsPeakRisk");
  const latestReport = document.getElementById("analyticsLatestReport");
  const dominantLevel = document.getElementById("analyticsDominantLevel");
  const intelList = document.getElementById("analyticsIntelList");
  const stream = document.getElementById("analyticsActivityStream");
  if (!peakRisk || !latestReport || !dominantLevel || !intelList || !stream) return;

  peakRisk.textContent = stats.highest_score ?? 0;
  latestReport.textContent = formatShortDate(stats.reports?.latest_report_at) || "Aucun";

  const levels = [
    { key: "danger", label: "Dangereux", count: stats.danger_scans ?? 0 },
    { key: "warn", label: "Suspects", count: stats.warn_scans ?? 0 },
    { key: "safe", label: "Fiables", count: stats.safe_scans ?? 0 }
  ].sort((a, b) => b.count - a.count);
  dominantLevel.textContent = levels[0]?.count ? `${levels[0].label}` : "Aucune";

  const insights = [];
  const security = stats.security || {};
  if (security.pressure_score != null) {
    insights.push(["Pression securite", `Score de pression ${security.pressure_score}/100 · posture ${security.posture || "stable"}.`]);
  }
  if ((stats.danger_scans ?? 0) > 0) insights.push(["Pression forte", `${stats.danger_scans} lien(s) dangereux sur la période filtrée.`]);
  if ((stats.average_score ?? 0) >= 50) insights.push(["Risque moyen élevé", `Le score moyen atteint ${stats.average_score}/100.`]);
  if ((stats.reports?.total_reports ?? 0) > 0) insights.push(["Communauté active", `${stats.reports.total_reports} signalement(s) ont alimenté la veille.`]);
  if ((stats.source_totals?.backend_enriched ?? 0) > 0) insights.push(["Analyse profonde", `${stats.source_totals.backend_enriched} scan(s) ont été enrichis par le backend.`]);
  (security.alerts || []).forEach(alert => {
    insights.push([alert.title || "Alerte", alert.detail || "Une anomalie a ete detectee."]);
  });

  intelList.innerHTML = insights.length
    ? insights.map(([title, detail]) => `<div class="intel-item"><strong>${title}</strong><span>${detail}</span></div>`).join("")
    : '<p class="analytics-empty">Les principaux enseignements apparaîtront ici.</p>';

  const activityItems = [
    ["Scans observés", `${stats.total_scans ?? 0} scan(s) sur la fenêtre active.`],
    ["Dernier scan", formatShortDate(stats.latest_scan_at) || "Aucun scan backend"],
    ["Dernier signalement", formatShortDate(stats.reports?.latest_report_at) || "Aucun"],
  ];
  stream.innerHTML = activityItems
    .map(([title, detail]) => `<div class="stream-item"><strong>${title}</strong><span>${detail}</span></div>`)
    .join("");
}

function formatShortDate(isoString) {
  if (!isoString) return "";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString("fr-FR", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

async function refreshLiveDashboard() {
  const filters = getDashboardFilters();
  const [stats, recent, recentReports] = await Promise.all([
    fetchBackendJSON(`/stats${buildQuery({ days: filters.days, level: filters.level, report_type: filters.reportType })}`),
    fetchBackendJSON(`/recent-scans${buildQuery({ days: filters.days, level: filters.level, limit: 5 })}`),
    fetchBackendJSON(`/reports/recent${buildQuery({ days: filters.days, report_type: filters.reportType, limit: 5 })}`)
  ]);

  const statusEl = document.getElementById("dashboardStatus");
  if (!statusEl) return;

  if (!stats || !recent) {
    statusEl.textContent = "Backend indisponible";
    statusEl.classList.add("is-offline");
    renderAnalyticsPanels(null);
    return;
  }

  statusEl.textContent = "Connecte";
  statusEl.classList.remove("is-offline");
  document.getElementById("statsTotalScans").textContent = stats.total_scans ?? 0;
  document.getElementById("statsAverageScore").textContent = stats.average_score ?? 0;
  document.getElementById("statsDangerScans").textContent = stats.danger_scans ?? 0;
  document.getElementById("statsBackendEnriched").textContent = stats.source_totals?.backend_enriched ?? 0;
  document.getElementById("statsLatestScan").textContent = formatRelativeDate(stats.latest_scan_at);
  renderAnalyticsPanels(stats);
  renderRecentScans(recent.items || []);
  renderRecentReports(recentReports?.items || []);

  const totalReports = stats.reports?.total_reports ?? 0;
  document.getElementById("reportsSummary").textContent =
    totalReports > 0 ? `${totalReports} signalement(s)` : "Aucun signalement";
}

function renderRecentReports(items) {
  const list = document.getElementById("recentReportsList");
  if (!list) return;

  if (!items || items.length === 0) {
    list.innerHTML = '<p class="live-feed-empty">Les signalements vérifiés apparaîtront ici.</p>';
    return;
  }

  list.innerHTML = items.map(item => {
    const levelClass = item.level || "warn";
    const dateLabel = new Date(item.timestamp).toLocaleString("fr-FR", {
      day: "2-digit",
      month: "2-digit",
      hour: "2-digit",
      minute: "2-digit"
    });
    const reportType = item.report_type || "autre";
    const sourceUrl = item.url || "Lien inconnu";
    const urlLabel = sourceUrl.length > 52 ? sourceUrl.slice(0, 49) + "..." : sourceUrl;

    return `
      <div class="live-feed-item level-${levelClass}">
        <div class="live-feed-main">
          <div class="live-feed-url">${urlLabel}</div>
          <div class="live-feed-meta">${reportType} - ${dateLabel}</div>
        </div>
        <div class="live-feed-score">${item.score ?? "-"}</div>
      </div>
    `;
  }).join("");
}

function clearHistory() {
  localStorage.removeItem(HISTORY_KEY);
  updateHistoryCount();
  renderHistoryList();
  showToast("Historique effacé.", "safe");
}

// ─── #8 VirusTotal ─────────────────────────────────────────────────────────────

const VT_KEY_STORAGE = "royshield_vt_key";

function getVTKey() {
  return localStorage.getItem(VT_KEY_STORAGE) || "";
}

function openVTModal() {
  const key = getVTKey();
  const input = document.getElementById("vtKeyInput");
  input.value = key;
  document.getElementById("vtRemoveBtn").style.display = key ? "inline-flex" : "none";
  document.getElementById("vtModal").classList.remove("hidden");
}

function closeVTModal() {
  document.getElementById("vtModal").classList.add("hidden");
}

function saveVTKey() {
  const key = document.getElementById("vtKeyInput").value.trim();
  if (!key) { showToast("Entrez une clé API valide.", "warn"); return; }
  localStorage.setItem(VT_KEY_STORAGE, key);
  updateVTDot();
  closeVTModal();
  showToast("Clé VirusTotal enregistrée.", "safe");
}

function removeVTKey() {
  localStorage.removeItem(VT_KEY_STORAGE);
  document.getElementById("vtKeyInput").value = "";
  document.getElementById("vtRemoveBtn").style.display = "none";
  updateVTDot();
  showToast("Clé supprimée.", "warn");
}

function toggleVTKeyVisibility() {
  const input = document.getElementById("vtKeyInput");
  input.type = input.type === "password" ? "text" : "password";
}

function updateVTDot() {
  const dot = document.getElementById("vtDot");
  dot.style.background = getVTKey() ? "var(--safe)" : "transparent";
  dot.style.border = getVTKey() ? "none" : "1px solid var(--muted)";
}

async function runVirusTotalCheck(url) {
  const key = getVTKey();
  const vtWrap = document.getElementById("srVtResultWrap");
  const vtHint = document.getElementById("srVtHint");
  if (!key) {
    vtWrap.classList.add("hidden");
    if (vtHint) vtHint.style.display = "block";
    return;
  }
  if (vtHint) vtHint.style.display = "none";
  const vtText = document.getElementById("srVtResultText");
  const vtSpinner = document.getElementById("srVtSpinner");
  vtWrap.classList.remove("hidden");
  vtWrap.className = "vt-result-wrap vt-loading";
  vtSpinner.style.display = "block";
  vtText.textContent = "Vérification VirusTotal en cours…";

  try {
    const encoded = btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encoded}`, {
      headers: { "x-apikey": key }
    });

    if (response.status === 404) {
      const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: { "x-apikey": key, "content-type": "application/x-www-form-urlencoded" },
        body: "url=" + encodeURIComponent(url)
      });
      if (!submitRes.ok) throw new Error("Soumission échouée");
      vtSpinner.style.display = "none";
      vtWrap.className = "vt-result-wrap vt-warn";
      vtText.textContent = "URL soumise à VirusTotal — résultats disponibles dans quelques minutes.";
      return;
    }

    if (!response.ok) throw new Error("Erreur API " + response.status);

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);

    vtSpinner.style.display = "none";
    if (malicious > 0) {
      vtWrap.className = "vt-result-wrap vt-danger";
      vtText.textContent = `VirusTotal : ${malicious} moteur(s) sur ${total} ont détecté ce lien comme malveillant.`;
    } else if (suspicious > 0) {
      vtWrap.className = "vt-result-wrap vt-warn";
      vtText.textContent = `VirusTotal : ${suspicious} moteur(s) trouvent ce lien suspect (${total} vérifications).`;
    } else {
      vtWrap.className = "vt-result-wrap vt-safe";
      vtText.textContent = `VirusTotal : Aucun moteur ne signale ce lien (${total} vérifications).`;
    }
  } catch (e) {
    vtSpinner.style.display = "none";
    vtWrap.className = "vt-result-wrap vt-warn";
    vtText.textContent = "VirusTotal : impossible d'effectuer la vérification (clé invalide ou limite atteinte).";
  }
}

// ─── #4 Export rapport ─────────────────────────────────────────────────────────

function exportReport() {
  if (!currentResult) return;
  const r = currentResult;
  const date = new Date().toLocaleString("fr-FR");
  const levelEmoji = { safe: "✅", warn: "⚠️", danger: "❌" }[r.level];
  const lines = [
    "╔══════════════════════════════════════════╗",
    "║         ROY SHIELD — RAPPORT D'ANALYSE   ║",
    "╚══════════════════════════════════════════╝",
    "",
    `Date      : ${date}`,
    `URL       : ${r.url}`,
    `Verdict   : ${levelEmoji} ${r.verdict}`,
    `Score     : ${r.score} / 100`,
    "",
    "── Signaux détectés ──────────────────────",
    ""
  ];
  r.signals.forEach(s => {
    const icon = s.type === "safe" ? "✓" : s.type === "warn" ? "!" : "✕";
    lines.push(`[${icon}] ${s.label}`);
    lines.push(`    ${s.detail}`);
    lines.push("");
  });
  lines.push("──────────────────────────────────────────");
  lines.push("Cet outil est fourni à titre indicatif.");
  lines.push("Aucun scanner ne garantit une détection à 100%.");

  const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `royshield-rapport-${Date.now()}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("Rapport exporté.", "safe");
}

// ─── #7 Signalement ────────────────────────────────────────────────────────────

const REPORTS_KEY = "royshield_reports";

function openReportModal() {
  if (!currentResult) return;
  document.getElementById("reportUrl").value = currentResult.url;
  document.getElementById("reportComment").value = "";
  document.getElementById("reportModal").classList.remove("hidden");
}

function closeReportModal() {
  document.getElementById("reportModal").classList.add("hidden");
}

async function submitReport() {
  const url = document.getElementById("reportUrl").value;
  const type = document.getElementById("reportType").value;
  const comment = document.getElementById("reportComment").value.trim();

  if (!url) return;

  const payload = {
    url,
    report_type: type,
    comment,
    score: currentResult ? currentResult.score : null,
    verdict: currentResult ? currentResult.verdict : null,
    level: currentResult ? currentResult.level : null
  };

  try {
    const response = await fetch(BACKEND_URL + "/reports", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...getAuthHeaders() },
      body: JSON.stringify(payload)
    });

    if (!response.ok) throw new Error("report submit failed");

    let reports = [];
    try { reports = JSON.parse(localStorage.getItem(REPORTS_KEY)) || []; } catch { }

    reports.unshift({
      url,
      type,
      comment,
      score: currentResult ? currentResult.score : null,
      date: new Date().toISOString()
    });

    localStorage.setItem(REPORTS_KEY, JSON.stringify(reports));
    closeReportModal();
    refreshLiveDashboard();
    showToast("Signalement enregistré. Merci pour votre contribution.", "safe");
  } catch {
    showToast("Impossible d'envoyer le signalement au backend.", "warn");
  }
}

async function shareCurrentReport() {
  const target = document.getElementById("sharedReportResult");
  if (!currentResult) {
    showToast("Aucun scan courant a partager.", "warn");
    return;
  }
  try {
    const response = await fetch(BACKEND_URL + "/reports/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: currentResult.url,
        verdict: currentResult.verdict,
        level: currentResult.level,
        score: currentResult.score,
        signals: currentResult.signals || []
      })
    });
    if (!response.ok) throw new Error("share_failed");
    const data = await response.json();
    const shareUrl = `${BACKEND_URL}/shared-reports/${data.share.token}/view`;
    target.innerHTML = `
      <div class="workspace-history-item">
        <strong>Lien partageable cree</strong>
        <span>${shareUrl}</span>
        <span>Lecture seule · niveau ${data.share.level}</span>
      </div>
    `;
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(shareUrl).catch(() => {});
    }
    showToast("Lien partageable cree et copie si possible.", "safe");
  } catch {
    showToast("Impossible de generer le lien partageable.", "warn");
  }
}

async function loadAdminReports() {
  const input = document.getElementById("adminTokenInput");
  const list = document.getElementById("adminReportsList");
  const token = input.value.trim();
  if (!token) {
    showToast("Entrez un token admin.", "warn");
    return;
  }
  localStorage.setItem(ADMIN_TOKEN_KEY, token);
  try {
    const response = await fetch(BACKEND_URL + "/admin/reports?status=pending&days=90", {
      headers: { "X-Admin-Token": token }
    });
    if (!response.ok) throw new Error("admin_failed");
    const data = await response.json();
    if (!data.items?.length) {
      list.innerHTML = '<p class="analytics-empty">Aucun signalement en attente.</p>';
      return;
    }
    list.innerHTML = data.items.map(item => `
      <div class="workspace-history-item">
        <strong>${item.report_type} · ${item.url}</strong>
        <span>${item.comment || "Sans commentaire"}</span>
        <span>Etat: ${item.status}</span>
        <div class="workspace-profile-actions">
          <button class="workspace-secondary-btn" onclick="moderateReport(${item.id}, 'confirmed')">Confirmer</button>
          <button class="workspace-danger-btn" onclick="moderateReport(${item.id}, 'dismissed')">Rejeter</button>
        </div>
      </div>
    `).join("");
  } catch {
    showToast("Impossible de charger la moderation admin.", "warn");
  }
}

async function moderateReport(reportId, status) {
  const token = getAdminToken() || document.getElementById("adminTokenInput").value.trim();
  if (!token) {
    showToast("Token admin requis.", "warn");
    return;
  }
  try {
    const response = await fetch(BACKEND_URL + `/admin/reports/${reportId}/moderate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Token": token
      },
      body: JSON.stringify({ status, note: status === "confirmed" ? "Valide par moderation." : "Rejete par moderation." })
    });
    if (!response.ok) throw new Error("moderation_failed");
    showToast("Signalement modere.", "safe");
    loadAdminReports();
    refreshLiveDashboard();
  } catch {
    showToast("Impossible de moderer ce signalement.", "warn");
  }
}

function switchAuthTab(mode) {
  authMode = mode;
  document.getElementById("authTabLogin").classList.toggle("active", mode === "login");
  document.getElementById("authTabRegister").classList.toggle("active", mode === "register");
  document.getElementById("authRegisterNameWrap").classList.toggle("hidden", mode !== "register");
  document.getElementById("authSubmitBtn").textContent = mode === "register" ? "Créer le compte" : "Se connecter";
}

function openAuthModal() {
  document.getElementById("authModal").classList.remove("hidden");
}

function closeAuthModal() {
  document.getElementById("authModal").classList.add("hidden");
}

async function submitAuth() {
  const email = document.getElementById("authEmailInput").value.trim();
  const password = document.getElementById("authPasswordInput").value.trim();
  const name = document.getElementById("authNameInput").value.trim();

  if (!email || !password || (authMode === "register" && !name)) {
    showToast("Renseignez les champs requis.", "warn");
    return;
  }

  const endpoint = authMode === "register" ? "/auth/register" : "/auth/login";
  const payload = authMode === "register" ? { name, email, password } : { email, password };

  try {
    const response = await fetch(BACKEND_URL + endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!response.ok) throw new Error("auth_failed");

    const data = await response.json();
    localStorage.setItem(AUTH_TOKEN_KEY, data.token);
    currentUser = data.user || null;
    closeAuthModal();
    updateWorkspaceUI();
    await refreshWorkspace();
    showToast(authMode === "register" ? "Compte créé et session ouverte." : "Connexion réussie.", "safe");
  } catch {
    showToast("Impossible de valider la session.", "warn");
  }
}

async function refreshWorkspace() {
  const token = getAuthToken();
  if (!token) {
    currentUser = null;
    updateWorkspaceUI();
    return;
  }

  const [profile, scans] = await Promise.all([
    fetchBackendJSON("/me"),
    fetchBackendJSON("/me/scans?limit=8&days=90")
  ]);

  if (!profile?.ok) {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    currentUser = null;
    updateWorkspaceUI();
    return;
  }

  currentUser = profile.user;
  updateWorkspaceUI(scans);
}

function updateWorkspaceUI(scanPayload = null) {
  const badge = document.getElementById("workspaceStatusBadge");
  const title = document.getElementById("workspaceCardTitle");
  const subtitle = document.getElementById("workspaceCardSubtitle");
  const profile = document.getElementById("workspaceProfile");
  const authActions = document.getElementById("workspaceAuthActions");
  const history = document.getElementById("workspaceHistoryList");
  const buttonLabel = document.getElementById("workspaceBtnLabel");

  if (!currentUser) {
    badge.textContent = "Hors connexion";
    badge.classList.remove("is-online");
    title.textContent = "Connexion requise";
    subtitle.textContent = "Connectez-vous pour enregistrer vos scans et retrouver votre historique.";
    profile.classList.add("hidden");
    authActions.classList.remove("hidden");
    history.innerHTML = '<p class="analytics-empty">Connectez-vous pour afficher votre historique synchronisé.</p>';
    buttonLabel.textContent = "Workspace";
    return;
  }

  badge.textContent = "Session active";
  badge.classList.add("is-online");
  title.textContent = "Workspace connecté";
  subtitle.textContent = "Vos scans et analyses sont maintenant liés à votre profil.";
  profile.classList.remove("hidden");
  authActions.classList.add("hidden");
  document.getElementById("workspaceProfileName").textContent = currentUser.name || "Analyste";
  document.getElementById("workspaceProfileEmail").textContent = currentUser.email || "";
  buttonLabel.textContent = currentUser.name || "Workspace";

  const items = scanPayload?.items || [];
  if (!items.length) {
    history.innerHTML = '<p class="analytics-empty">Aucun scan personnel enregistré pour le moment.</p>';
    return;
  }

  history.innerHTML = items.map(item => `
    <div class="workspace-history-item">
      <strong>${item.verdict || "Analyse"}</strong>
      <span>${(item.normalized_url || item.raw_url || "").slice(0, 90)}</span>
      <span>${formatShortDate(item.timestamp)} · score ${item.score ?? 0}</span>
    </div>
  `).join("");
}

async function logoutWorkspace() {
  try {
    await fetch(BACKEND_URL + "/auth/logout", {
      method: "POST",
      headers: { ...getAuthHeaders() }
    });
  } catch {
    // no-op
  }
  localStorage.removeItem(AUTH_TOKEN_KEY);
  currentUser = null;
  updateWorkspaceUI();
  showToast("Session fermée.", "safe");
}

// ─── Toast ─────────────────────────────────────────────────────────────────────

let toastTimer = null;

function showToast(message, level = "safe") {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.className = "toast toast-" + level;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.className = "toast hidden"; }, 3000);
}

// ─── Init ──────────────────────────────────────────────────────────────────────

updateHistoryCount();
updateVTDot();
initSpeechRecognition();
switchAuthTab("login");
updateWorkspaceUI();
refreshWorkspace();
refreshLiveDashboard();
setInterval(refreshLiveDashboard, 30000);
