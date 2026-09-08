const scanButton = document.querySelector("#scan-button");
const cancelButton = document.querySelector("#cancel-button");
const targetInput = document.querySelector("#target");
const interfaceInput = document.querySelector("#interface");
const timeoutInput = document.querySelector("#timeout");
const retriesInput = document.querySelector("#retries");
const hostnamesInput = document.querySelector("#resolve-hostnames");
const notifyInput = document.querySelector("#notify-new");
const autoRescanInput = document.querySelector("#auto-rescan");
const rescanIntervalInput = document.querySelector("#rescan-interval");
const interfacesList = document.querySelector("#interfaces");
const statusNode = document.querySelector("#status");
const activeTargetNode = document.querySelector("#active-target");
const activeInterfaceNode = document.querySelector("#active-interface");
const privilegeStateNode = document.querySelector("#privilege-state");
const progressElapsedNode = document.querySelector("#progress-elapsed");
const progressCountsNode = document.querySelector("#progress-counts");
const filterInput = document.querySelector("#filter");
const sortInput = document.querySelector("#sort");
const exportButton = document.querySelector("#export-button");
const cardsContainer = document.querySelector("#cards-container");
const tableContainer = document.querySelector("#table-container");
const tableBody = document.querySelector("#results-body");
const cardsViewButton = document.querySelector("#cards-view");
const tableViewButton = document.querySelector("#table-view");
const chipButtons = [...document.querySelectorAll(".chip")];
const phaseItems = [...document.querySelectorAll(".phase")];
const detailDrawer = document.querySelector("#detail-drawer");
const detailTitle = document.querySelector("#detail-title");
const detailContent = document.querySelector("#detail-content");
const detailNotes = document.querySelector("#detail-notes");
const detailClose = document.querySelector("#detail-close");

const metrics = {
  total: document.querySelector("#metric-total"),
  live: document.querySelector("#metric-live"),
  cached: document.querySelector("#metric-cached"),
  privateMac: document.querySelector("#metric-private"),
  unknownHostnames: document.querySelector("#metric-unknown"),
  gateways: document.querySelector("#metric-gateways"),
  newSinceLastScan: document.querySelector("#metric-new-scan"),
  missingSinceLastScan: document.querySelector("#metric-missing"),
};

let devices = [];
let localIp = null;
let currentFilter = "all";
let eventSource = null;
let scanId = null;
let scanStartedAt = null;
let elapsedTimer = null;
let autoRescanTimer = null;
let progressCounts = { cache: 0, live: 0 };
let notifiedKeys = new Set();
let lastSummary = null;

function escapeText(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    };
    return entities[character];
  });
}

function setStatus(message, tone = "neutral") {
  statusNode.textContent = message;
  statusNode.className = `status ${tone === "neutral" ? "" : tone}`.trim();
}

function setScanningState(isScanning) {
  scanButton.disabled = isScanning;
  scanButton.querySelector("span").textContent = isScanning ? "Scanning" : "Smart Scan";
  cancelButton.classList.toggle("hidden", !isScanning);
}

function setPhase(activePhase) {
  let passed = true;
  phaseItems.forEach((item) => {
    const isActive = item.dataset.phase === activePhase;
    item.classList.toggle("active", isActive);
    if (isActive) {
      passed = false;
    }
    item.classList.toggle("done", passed);
  });
}

function updatePrivilegeState(isPrivileged) {
  privilegeStateNode.textContent = isPrivileged ? "Elevated" : "Limited";
}

function updateProgress(data = progressCounts) {
  progressCounts = { ...progressCounts, ...data };
  progressCountsNode.textContent = `${progressCounts.cache || 0} / ${progressCounts.live || 0}`;
}

function startElapsedTimer() {
  stopElapsedTimer();
  scanStartedAt = Date.now();
  progressElapsedNode.textContent = "0s";
  elapsedTimer = window.setInterval(() => {
    const seconds = Math.max(0, Math.round((Date.now() - scanStartedAt) / 1000));
    progressElapsedNode.textContent = `${seconds}s`;
  }, 1000);
}

function stopElapsedTimer() {
  if (elapsedTimer) {
    window.clearInterval(elapsedTimer);
    elapsedTimer = null;
  }
}

function isUnknownName(value) {
  return ["Unknown", "Unknown Device", "Skipped", ""].includes(String(value ?? ""));
}

function deviceName(device) {
  if (device.alias) return device.alias;
  return isUnknownName(device.hostname) ? device.ip : device.hostname;
}

function deviceInitial(device) {
  const type = device.deviceType || "Unknown";
  if (type === "Gateway") return "GW";
  if (type === "This computer") return "PC";
  if (type === "Phone or tablet") return "PH";
  if (type === "Media or TV") return "TV";
  if (type === "Printer") return "PR";
  return "IP";
}

function badgeClass(value) {
  if (value === "High") return "ok";
  if (value === "Medium") return "cache";
  if (value === "Low") return "warning";
  if (value === "Private/randomized MAC") return "warning";
  if (value === "Unknown" || value === "Unknown Device") return "danger";
  return "neutral";
}

function upsertDevice(device) {
  const index = devices.findIndex((item) => item.key === device.key || item.ip === device.ip);
  if (index === -1) {
    devices.push(device);
  } else {
    devices[index] = { ...devices[index], ...device };
  }
  render();
}

function passesChip(device) {
  if (currentFilter === "all") return true;
  if (currentFilter === "live") return ["arp", "arp+cache"].includes(device.source);
  if (currentFilter === "cached") return device.source === "arp-cache";
  if (currentFilter === "unknown") return isUnknownName(device.hostname) || device.vendor === "Unknown";
  if (currentFilter === "private") return Boolean(device.isPrivateMac);
  if (currentFilter === "gateway") return Boolean(device.isGateway);
  if (currentFilter === "local") return Boolean(device.isLocal);
  if (currentFilter === "new") return Boolean(device.isNew || device.isNewSinceLastScan);
  return true;
}

function filteredDevices() {
  const query = filterInput.value.trim().toLowerCase();
  const visible = devices.filter((device) => {
    const haystack = [
      device.ip,
      device.mac,
      device.vendor,
      device.hostname,
      device.alias,
      device.deviceType,
      device.confidence,
      device.source,
    ].join(" ").toLowerCase();
    return passesChip(device) && (!query || haystack.includes(query));
  });

  return visible.sort((a, b) => {
    if (sortInput.value === "confidence") return (b.confidenceScore || 0) - (a.confidenceScore || 0);
    if (sortInput.value === "type") return String(a.deviceType).localeCompare(String(b.deviceType));
    if (sortInput.value === "vendor") return String(a.vendor).localeCompare(String(b.vendor));
    if (sortInput.value === "lastSeen") return String(b.lastSeen).localeCompare(String(a.lastSeen));
    return ipToNumber(a.ip) - ipToNumber(b.ip);
  });
}

function ipToNumber(ip) {
  return String(ip).split(".").reduce((total, octet) => (total << 8) + Number(octet || 0), 0) >>> 0;
}

function updateMetrics(summary = lastSummary) {
  const computed = summary || {
    total: devices.length,
    live: devices.filter((device) => ["arp", "arp+cache"].includes(device.source)).length,
    cached: devices.filter((device) => device.source === "arp-cache").length,
    privateMac: devices.filter((device) => device.isPrivateMac).length,
    unknownHostnames: devices.filter((device) => isUnknownName(device.hostname)).length,
    gateways: devices.filter((device) => device.isGateway).length,
    newSinceLastScan: devices.filter((device) => device.isNewSinceLastScan).length,
    missingSinceLastScan: 0,
  };

  metrics.total.textContent = computed.total ?? 0;
  metrics.live.textContent = computed.live ?? 0;
  metrics.cached.textContent = computed.cached ?? 0;
  metrics.privateMac.textContent = computed.privateMac ?? 0;
  metrics.unknownHostnames.textContent = computed.unknownHostnames ?? 0;
  metrics.gateways.textContent = computed.gateways ?? 0;
  metrics.newSinceLastScan.textContent = computed.newSinceLastScan ?? 0;
  metrics.missingSinceLastScan.textContent = computed.missingSinceLastScan ?? 0;
}

function render() {
  updateMetrics();
  exportButton.disabled = devices.length === 0;
  const visible = filteredDevices();
  renderCards(visible);
  renderTable(visible);
}

function renderCards(visible) {
  if (visible.length === 0) {
    cardsContainer.innerHTML = `<div class="empty-state">${devices.length ? "No devices match the current filters." : "Start a smart scan to build the local inventory."}</div>`;
    return;
  }

  cardsContainer.innerHTML = visible.map((device) => `
    <article class="device-card ${device.isNewSinceLastScan ? "new-scan" : ""} ${device.isNew ? "new" : ""}" data-key="${escapeText(device.key)}" tabindex="0">
      <div class="device-card-header">
        <div class="device-icon" aria-hidden="true">${escapeText(deviceInitial(device))}</div>
        <div class="device-title">
          <h3>${escapeText(deviceName(device))}</h3>
          <p>${escapeText(device.ip)} / ${escapeText(device.mac)}</p>
        </div>
        <span class="badge ${badgeClass(device.confidence)}">${escapeText(device.confidence)}</span>
      </div>
      <input class="alias-input" data-key="${escapeText(device.key)}" type="text" value="${escapeText(device.alias)}" placeholder="Add device label">
      <div class="device-meta">
        <div><span>Vendor</span><strong>${escapeText(device.vendor)}</strong></div>
        <div><span>Type</span><strong>${escapeText(device.deviceType)}</strong></div>
        <div><span>Source</span><strong>${escapeText(device.source)}</strong></div>
        <div><span>Seen</span><strong>${escapeText(device.seenCount || 0)} times</strong></div>
      </div>
      <div class="notes">
        ${(device.notes || []).map((note) => `<span class="badge neutral">${escapeText(note)}</span>`).join("")}
        ${device.isNew ? `<span class="badge cache">First seen</span>` : ""}
        ${device.isNewSinceLastScan ? `<span class="badge ok">New since last scan</span>` : ""}
        ${device.hasDuplicatePrivateMac ? `<span class="badge warning">Duplicate private MAC</span>` : ""}
      </div>
    </article>
  `).join("");

  bindAliasInputs();
  bindDeviceOpeners();
}

function renderTable(visible) {
  if (visible.length === 0) {
    tableBody.innerHTML = `<tr class="empty-row"><td colspan="8">${devices.length ? "No devices match the current filters." : "Start a scan to populate this table."}</td></tr>`;
    return;
  }

  tableBody.innerHTML = visible.map((device) => `
    <tr data-key="${escapeText(device.key)}" tabindex="0">
      <td>
        <strong>${escapeText(deviceName(device))}</strong>
        <div class="muted">${escapeText(device.deviceType)}</div>
      </td>
      <td class="mono">${escapeText(device.ip)}</td>
      <td class="mono">${escapeText(device.mac)}</td>
      <td><span class="badge ${badgeClass(device.vendor)}">${escapeText(device.vendor)}</span></td>
      <td>${escapeText(device.deviceType)}</td>
      <td><span class="badge ${badgeClass(device.confidence)}">${escapeText(device.confidence)} ${escapeText(device.confidenceScore)}%</span></td>
      <td><span class="badge neutral">${escapeText(device.source)}</span></td>
      <td>${escapeText(device.seenCount || 0)}</td>
    </tr>
  `).join("");

  bindDeviceOpeners();
}

function bindAliasInputs() {
  [...document.querySelectorAll(".alias-input")].forEach((input) => {
    input.addEventListener("click", (event) => event.stopPropagation());
    input.addEventListener("keydown", (event) => event.stopPropagation());
    input.addEventListener("change", async () => {
      const key = input.dataset.key;
      const alias = input.value.trim();
      const device = devices.find((item) => item.key === key);
      if (device) {
        device.alias = alias;
        render();
      }
      await fetch("/api/alias", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, alias }),
      });
    });
  });
}

function bindDeviceOpeners() {
  [...document.querySelectorAll("[data-key]")].forEach((node) => {
    if (node.classList.contains("alias-input")) return;
    node.addEventListener("click", () => openDetails(node.dataset.key));
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openDetails(node.dataset.key);
      }
    });
  });
}

function scanParams() {
  const params = new URLSearchParams();
  scanId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  params.set("scanId", scanId);
  if (targetInput.value.trim()) params.set("target", targetInput.value.trim());
  if (interfaceInput.value.trim()) params.set("interface", interfaceInput.value.trim());
  params.set("timeout", timeoutInput.value);
  params.set("retries", retriesInput.value);
  params.set("resolveHostnames", hostnamesInput.checked ? "true" : "false");
  return params.toString();
}

function runScan() {
  if (eventSource) {
    eventSource.close();
  }

  devices = [];
  notifiedKeys = new Set();
  lastSummary = null;
  progressCounts = { cache: 0, live: 0 };
  render();
  updateProgress();
  startElapsedTimer();
  setPhase("cache");
  setStatus("Starting smart discovery...");
  setScanningState(true);

  eventSource = new EventSource(`/api/scan-stream?${scanParams()}`);

  eventSource.addEventListener("start", (event) => {
    const data = JSON.parse(event.data);
    localIp = data.localIp;
    activeTargetNode.textContent = data.target;
    activeInterfaceNode.textContent = data.interfaceLabel || data.interface;
    updatePrivilegeState(data.isPrivileged);
  });

  eventSource.addEventListener("phase", (event) => {
    const data = JSON.parse(event.data);
    setPhase(data.id);
    setStatus(data.label);
  });

  eventSource.addEventListener("device", (event) => {
    const device = JSON.parse(event.data);
    maybeNotifyNewDevice(device);
    upsertDevice(device);
    setStatus(`Found ${devices.length} device${devices.length === 1 ? "" : "s"} so far.`);
  });

  eventSource.addEventListener("progress", (event) => {
    updateProgress(JSON.parse(event.data));
  });

  eventSource.addEventListener("done", (event) => {
    const data = JSON.parse(event.data);
    stopElapsedTimer();
    if (data.cancelled) {
      setPhase("context");
      setStatus("Scan cancelled.", "warning");
      setScanningState(false);
      scheduleAutoRescan();
      eventSource.close();
      eventSource = null;
      return;
    }
    if (data.ok && data.devices) {
      devices = data.devices;
      lastSummary = data.summary || null;
      render();
      setPhase("done");
      setStatus(`Scan complete. Found ${data.deviceCount} device${data.deviceCount === 1 ? "" : "s"}.`);
    }
    setScanningState(false);
    scheduleAutoRescan();
    eventSource.close();
    eventSource = null;
  });

  eventSource.addEventListener("error", (event) => {
    if (event.data) {
      const data = JSON.parse(event.data);
      setStatus(data.message || "Scan failed.", "error");
    } else {
      setStatus("Scan stream interrupted.", "error");
    }
    stopElapsedTimer();
    setScanningState(false);
    scheduleAutoRescan();
    eventSource.close();
    eventSource = null;
  });
}

async function cancelScan() {
  if (!scanId) return;
  setStatus("Cancelling scan...", "warning");
  try {
    await fetch("/api/cancel", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scanId }),
    });
  } finally {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    stopElapsedTimer();
    setScanningState(false);
    setStatus("Scan cancelled.", "warning");
  }
}

function scheduleAutoRescan() {
  if (autoRescanTimer) {
    window.clearTimeout(autoRescanTimer);
    autoRescanTimer = null;
  }
  if (!autoRescanInput.checked) return;
  const intervalMs = Number(rescanIntervalInput.value || 300) * 1000;
  autoRescanTimer = window.setTimeout(() => {
    if (!eventSource) runScan();
  }, intervalMs);
}

function maybeNotifyNewDevice(device) {
  if (!notifyInput.checked || !device.isNewSinceLastScan || !("Notification" in window)) return;
  if (notifiedKeys.has(device.key)) return;
  if (Notification.permission === "default") {
    Notification.requestPermission();
    return;
  }
  if (Notification.permission !== "granted") return;

  notifiedKeys.add(device.key);
  new Notification("New WiFind device", {
    body: `${deviceName(device)} at ${device.ip}`,
    tag: `wifind-${device.key}`,
  });
}

function openDetails(key) {
  const device = devices.find((item) => item.key === key);
  if (!device) return;

  detailTitle.textContent = deviceName(device);
  const fields = [
    ["IP address", device.ip],
    ["MAC address", device.mac],
    ["Device name / hostname", device.hostname],
    ["Vendor", device.vendor],
    ["Type", device.deviceType],
    ["Confidence", `${device.confidence} ${device.confidenceScore}%`],
    ["Source", device.source],
    ["First seen", device.firstSeen],
    ["Last seen", device.lastSeen],
    ["Seen count", device.seenCount],
    ["Key", device.key],
  ];
  detailContent.innerHTML = fields.map(([label, value]) => `
    <div>
      <dt>${escapeText(label)}</dt>
      <dd>${escapeText(value ?? "")}</dd>
    </div>
  `).join("");
  detailNotes.innerHTML = (device.notes || []).map((note) => `<span class="badge neutral">${escapeText(note)}</span>`).join("");
  detailDrawer.classList.remove("hidden");
  detailDrawer.setAttribute("aria-hidden", "false");
}

function closeDetails() {
  detailDrawer.classList.add("hidden");
  detailDrawer.setAttribute("aria-hidden", "true");
}

function exportCsv() {
  if (devices.length === 0) return;

  const headers = ["Alias", "Device Name / Hostname", "IP", "MAC", "Vendor", "Type", "Confidence", "Source", "New Since Last Scan", "First Seen", "Last Seen", "Seen Count"];
  const rows = devices.map((device) => [
    device.alias,
    device.hostname,
    device.ip,
    device.mac,
    device.vendor,
    device.deviceType,
    `${device.confidence} ${device.confidenceScore}%`,
    device.source,
    device.isNewSinceLastScan ? "Yes" : "No",
    device.firstSeen,
    device.lastSeen,
    device.seenCount,
  ]);
  const csv = [headers, ...rows]
    .map((row) => row.map((value) => `"${String(value ?? "").replaceAll('"', '""')}"`).join(","))
    .join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `wifind-inventory-${new Date().toISOString().slice(0, 19).replaceAll(":", "-")}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

async function loadContext() {
  try {
    const response = await fetch("/api/context", { cache: "no-store" });
    const context = await response.json();
    if (!context.ok) {
      setStatus(context.error, "warning");
      return;
    }

    targetInput.placeholder = context.defaultTarget;
    interfaceInput.placeholder = context.activeInterfaceLabel || context.activeInterface;
    activeTargetNode.textContent = context.defaultTarget;
    activeInterfaceNode.textContent = context.activeInterfaceLabel || context.activeInterface;
    updatePrivilegeState(context.isPrivileged);
    localIp = context.localIp;
    interfacesList.innerHTML = context.interfaces
      .map((adapter) => `<option value="${escapeText(adapter.name)}" label="${escapeText(adapter.label)}"></option>`)
      .join("");

    setPhase("context");
    if (!context.isPrivileged) {
      setStatus("Start the server as Administrator/root for packet scanning.", "warning");
    } else {
      setStatus("Ready. Smart Scan will use the active adapter, live ARP, cache, and hostname enrichment.");
    }
  } catch (error) {
    setStatus("Could not load local network context.", "error");
  }
}

scanButton.addEventListener("click", runScan);
cancelButton.addEventListener("click", cancelScan);
filterInput.addEventListener("input", render);
sortInput.addEventListener("change", render);
exportButton.addEventListener("click", exportCsv);
autoRescanInput.addEventListener("change", scheduleAutoRescan);
rescanIntervalInput.addEventListener("change", scheduleAutoRescan);
notifyInput.addEventListener("change", () => {
  if (notifyInput.checked && "Notification" in window && Notification.permission === "default") {
    Notification.requestPermission();
  }
});
detailClose.addEventListener("click", closeDetails);
detailDrawer.addEventListener("click", (event) => {
  if (event.target === detailDrawer) closeDetails();
});
window.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeDetails();
});
cardsViewButton.addEventListener("click", () => {
  cardsViewButton.classList.add("active");
  tableViewButton.classList.remove("active");
  cardsContainer.classList.remove("hidden");
  tableContainer.classList.add("hidden");
});
tableViewButton.addEventListener("click", () => {
  tableViewButton.classList.add("active");
  cardsViewButton.classList.remove("active");
  tableContainer.classList.remove("hidden");
  cardsContainer.classList.add("hidden");
});
chipButtons.forEach((button) => {
  button.addEventListener("click", () => {
    currentFilter = button.dataset.filter;
    chipButtons.forEach((item) => item.classList.toggle("active", item === button));
    render();
  });
});

loadContext();
