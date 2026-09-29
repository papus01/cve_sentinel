const state = {
  cves: [],
  stats: {}
};

const $ = (selector) => document.querySelector(selector);

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function scoreClass(score) {
  if (score == null) return "unknown";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function renderStats() {
  const s = state.stats;

  $("#stats").innerHTML = `
    <div class="stat"><span>Total</span><strong>${s.total ?? 0}</strong></div>
    <div class="stat critical"><span>Critical</span><strong>${s.critical ?? 0}</strong></div>
    <div class="stat high"><span>High</span><strong>${s.high ?? 0}</strong></div>
    <div class="stat medium"><span>Medium</span><strong>${s.medium ?? 0}</strong></div>
    <div class="stat kev"><span>CISA KEV</span><strong>${s.kev ?? 0}</strong></div>
  `;

  if (s.generated_at) {
    $("#updated").textContent =
      "Updated " + new Date(s.generated_at).toLocaleString();
  }
}

function filtered() {
  const query = $("#search").value.trim().toLowerCase();
  const severity = $("#severity").value;
  const kev = $("#kev").value;

  return state.cves.filter((item) => {
    const haystack = [
      item.id,
      item.vendor,
      item.product,
      item.description,
      ...(item.products || [])
    ].join(" ").toLowerCase();

    const matchesQuery = !query || haystack.includes(query);
    const matchesSeverity = !severity || item.severity === severity;
    const matchesKev = !kev || String(item.kev) === kev;

    return matchesQuery && matchesSeverity && matchesKev;
  });
}

function render() {
  const items = filtered();
  $("#count").textContent = `${items.length} result(s)`;

  if (!items.length) {
    $("#cves").innerHTML =
      `<div class="empty">No vulnerability matches your filters.</div>`;
    return;
  }

  $("#cves").innerHTML = items.map((item) => {
    const score = item.cvss == null ? "N/A" : Number(item.cvss).toFixed(1);
    const klass = scoreClass(item.cvss);

    return `
      <article class="card">
        <div class="card-top">
          <a href="${escapeHtml(item.url)}" target="_blank" rel="noreferrer">
            ${escapeHtml(item.id)}
          </a>
          <span class="badge ${klass}">${escapeHtml(item.severity)}</span>
        </div>

        <div class="score">
          <strong>${score}</strong>
          <span>CVSS</span>
        </div>

        ${item.kev ? `<div class="kev-tag">⚠ CISA KEV · KNOWN EXPLOITED</div>` : ""}

        <p>${escapeHtml(item.description)}</p>

        <div class="meta">
          <span>Published ${item.published ? new Date(item.published).toLocaleDateString() : "—"}</span>
          ${item.vendor ? `<span>${escapeHtml(item.vendor)}</span>` : ""}
          ${item.product ? `<span>${escapeHtml(item.product)}</span>` : ""}
        </div>
      </article>
    `;
  }).join("");
}

async function load() {
  try {
    const [cves, stats] = await Promise.all([
      fetch("../data/cves.json", { cache: "no-store" }).then(r => r.json()),
      fetch("../data/stats.json", { cache: "no-store" }).then(r => r.json())
    ]);

    state.cves = cves;
    state.stats = stats;

    renderStats();
    render();
  } catch (error) {
    $("#cves").innerHTML =
      `<div class="empty">Unable to load vulnerability data.</div>`;
    console.error(error);
  }
}

["search", "severity", "kev"].forEach(id => {
  document.getElementById(id).addEventListener("input", render);
  document.getElementById(id).addEventListener("change", render);
});

load();
