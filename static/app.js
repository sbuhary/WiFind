const scanButton = document.querySelector("#scan-button");
const targetInput = document.querySelector("#target");
const interfaceInput = document.querySelector("#interface");
const timeoutInput = document.querySelector("#timeout");
const retriesInput = document.querySelector("#retries");
const hostnamesInput = document.querySelector("#resolve-hostnames");
const interfacesList = document.querySelector("#interfaces");
const statusNode = document.querySelector("#status");
const activeTargetNode = document.querySelector("#active-target");
const activeInterfaceNode = document.querySelector("#active-interface");
const privilegeStateNode = document.querySelector("#privilege-state");
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

const metrics = {
  total: document.querySelector("#metric-total"),
  live: document.querySelector("#metric-live"),
  cached: document.querySelector("#metric-cached"),
  privateMac: document.querySelector("#metric-private"),
  unknownHostnames: document.querySelector("#metric-unknown"),
  gateways: document.querySelector("#metric-gateways"),
};

let devices = [];
let localIp = null;
let currentFilter = "all";
let eventSource = null;

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

function deviceName(device) {
  return device.alias || device.hostname && device.hostname !== "Unknown" ? (device.alias || device.hostname) : device.ip;
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
  if (value === "Unknown") return "danger";
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
  if (currentFilter === "unknown") return device.hostname === "Unknown" || device.vendor === "Unknown";
  if (currentFilter === "private") return Boolean(device.isPrivateMac);
  if (currentFilter === "gateway") return Boolean(device.isGateway);
  if (currentFilter === "local") return Boolean(device.isLocal);
  if (currentFilter === "new") return Boolean(device.isNew);
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

function updateMetrics(summary = null) {
  const computed = summary || {
    total: devices.length,
    live: devices.filter((device) => ["arp", "arp+cache"].includes(device.source)).length,
    cached: devices.filter((device) => device.source === "arp-cache").length,
    privateMac: devices.filter((device) => device.isPrivateMac).length,
    unknownHostnames: devices.filter((device) => ["Unknown", "Skipped"].includes(device.hostname)).length,
    gateways: devices.filter((device) => device.isGateway).length,
  };

  metrics.total.textContent = computed.total ?? 0;
  metrics.live.textContent = computed.live ?? 0;
  metrics.cached.textContent = computed.cached ?? 0;
  metrics.privateMac.textContent = computed.privateMac ?? 0;
  metrics.unknownHostnames.textContent = computed.unknownHostnames ?? 0;
  metrics.gateways.textContent = computed.gateways ?? 0;
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
    <article class="device-card ${device.isNew ? "new" : ""}">
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
        ${device.isNew ? `<span class="badge cache">New</span>` : ""}
      </div>
    </article>
  `).join("");

  bindAliasInputs();
}

function renderTable(visible) {
  if (visible.length === 0) {
    tableBody.innerHTML = `<tr class="empty-row"><td colspan="8">${devices.length ? "No devices match the current filters." : "Start a scan to populate this table."}</td></tr>`;
    return;
  }

  tableBody.innerHTML = visible.map((device) => `
    <tr>
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
}

function bindAliasInputs() {
  [...document.querySelectorAll(".alias-input")].forEach((input) => {
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

function scanParams() {
  const params = new URLSearchParams();
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
  render();
  setPhase("cache");
  setStatus("Starting smart discovery...");
  scanButton.disabled = true;
  scanButton.querySelector("span").textContent = "Scanning";

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
    upsertDevice(device);
    setStatus(`Found ${devices.length} device${devices.length === 1 ? "" : "s"} so far.`);
  });

  eventSource.addEventListener("done", (event) => {
    const data = JSON.parse(event.data);
    if (data.ok && data.devices) {
      devices = data.devices;
      updateMetrics(data.summary);
      render();
      setPhase("done");
      setStatus(`Scan complete. Found ${data.deviceCount} device${data.deviceCount === 1 ? "" : "s"}.`);
    }
    scanButton.disabled = false;
    scanButton.querySelector("span").textContent = "Smart Scan";
    eventSource.close();
  });

  eventSource.addEventListener("error", (event) => {
    if (event.data) {
      const data = JSON.parse(event.data);
      setStatus(data.message || "Scan failed.", "error");
    } else {
      setStatus("Scan stream interrupted.", "error");
    }
    scanButton.disabled = false;
    scanButton.querySelector("span").textContent = "Smart Scan";
    eventSource.close();
  });
}

function exportCsv() {
  if (devices.length === 0) return;

  const headers = ["Alias", "Hostname", "IP", "MAC", "Vendor", "Type", "Confidence", "Source", "First Seen", "Last Seen", "Seen Count"];
  const rows = devices.map((device) => [
    device.alias,
    device.hostname,
    device.ip,
    device.mac,
    device.vendor,
    device.deviceType,
    `${device.confidence} ${device.confidenceScore}%`,
    device.source,
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
filterInput.addEventListener("input", render);
sortInput.addEventListener("change", render);
exportButton.addEventListener("click", exportCsv);
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
