// NoSpy UI Controller

async function tauriInvoke(cmd, args = {}) {
  try {
    if (window.__TAURI__?.core?.invoke) {
      return await window.__TAURI__.core.invoke(cmd, args);
    } else if (window.__TAURI__?.invoke) {
      return await window.__TAURI__.invoke(cmd, args);
    } else if (window.__TAURI_INTERNALS__?.invoke) {
      return await window.__TAURI_INTERNALS__.invoke(cmd, args);
    }
    return null;
  } catch (err) {
    console.error(`IPC error (${cmd}):`, err);
    throw err;
  }
}

const state = {
  activeTab: 'dashboard',
  scanMode: 'quick',
  isScanning: false,
  groqConfigured: false,
  currentDesourcePath: '',
  summary: null,
  threats: [],
  processes: [],
  networkSockets: [],
  autoruns: [],
  quarantine: [],
  sourceReports: [],
};

const elements = {
  appLoader: document.getElementById('app-loader'),
  headerDragHandle: document.getElementById('header-drag-handle'),
  sidebarDragHandle: document.getElementById('sidebar-drag-handle'),
  winMinBtn: document.getElementById('win-min-btn'),
  winMaxBtn: document.getElementById('win-max-btn'),
  winCloseBtn: document.getElementById('win-close-btn'),

  groqModal: document.getElementById('groq-modal'),
  groqKeyInput: document.getElementById('groq-key-input'),
  groqSaveBtn: document.getElementById('groq-save-btn'),
  groqSkipBtn: document.getElementById('groq-skip-btn'),
  headerGroqBtn: document.getElementById('header-groq-btn'),
  headerGroqLabel: document.getElementById('header-groq-label'),

  navItems: document.querySelectorAll('.nav-item'),
  tabViews: document.querySelectorAll('.tab-view'),
  viewTitle: document.getElementById('view-title'),
  viewSubtitle: document.getElementById('view-subtitle'),
  sidebarThreatCount: document.getElementById('sidebar-threat-count'),
  sidebarQuarantineCount: document.getElementById('sidebar-quarantine-count'),
  sidebarRtBadge: document.getElementById('sidebar-rt-badge'),

  sidebarTelemetryCard: document.getElementById('sidebar-telemetry-card'),
  sideCpuVal: document.getElementById('side-cpu-val'),
  sideCpuBar: document.getElementById('side-cpu-bar'),
  sideRamVal: document.getElementById('side-ram-val'),
  sideRamBar: document.getElementById('side-ram-bar'),

  headerQuickScanBtn: document.getElementById('header-quick-scan-btn'),
  headerDeepScanBtn: document.getElementById('header-deep-scan-btn'),

  bannerEmblem: document.getElementById('banner-emblem'),
  dashStatusHeading: document.getElementById('dash-status-heading'),
  dashStatusDesc: document.getElementById('dash-status-desc'),
  dashQuickScanBtn: document.getElementById('dash-quick-scan-btn'),
  dashDesourceBtn: document.getElementById('dash-desource-btn'),
  metricProcesses: document.getElementById('metric-processes'),
  metricProcSuspicious: document.getElementById('metric-proc-suspicious'),
  metricSockets: document.getElementById('metric-sockets'),
  metricSockSuspicious: document.getElementById('metric-sock-suspicious'),
  metricAutoruns: document.getElementById('metric-autoruns'),
  metricAutoSuspicious: document.getElementById('metric-auto-suspicious'),
  metricQuarantine: document.getElementById('metric-quarantine'),
  overviewProcsTbody: document.getElementById('overview-procs-tbody'),
  viewAllProcsBtn: document.getElementById('view-all-procs-btn'),

  // Real-time tab
  rtStatusHeading: document.getElementById('rt-status-heading'),
  rtStatusDesc: document.getElementById('rt-status-desc'),
  rtPollNowBtn: document.getElementById('rt-poll-now-btn'),
  rtToggleBtn: document.getElementById('rt-toggle-btn'),
  rtEventsCount: document.getElementById('rt-events-count'),
  rtFlaggedCount: document.getElementById('rt-flagged-count'),
  rtEventsTbody: document.getElementById('rt-events-tbody'),

  // Scanner tab
  segmentBtns: document.querySelectorAll('.segment-btn'),
  startScanBtn: document.getElementById('start-scan-btn'),
  quarantineAllBtn: document.getElementById('quarantine-all-btn'),
  scanGroqCard: document.getElementById('scan-groq-card'),
  scanGroqText: document.getElementById('scan-groq-text'),
  scanLoaderCard: document.getElementById('scan-loader-card'),
  scanStepTitle: document.getElementById('scan-step-title'),
  scanTargetText: document.getElementById('scan-target-text'),
  resultsCountText: document.getElementById('results-count-text'),
  threatCardsList: document.getElementById('threat-cards-list'),
  scannerEmptyState: document.getElementById('scanner-empty-state'),

  // De-Source tab
  desourcePathInput: document.getElementById('desource-path-input'),
  desourceInspectBtn: document.getElementById('desource-inspect-btn'),
  desourceAllBtn: document.getElementById('desource-all-btn'),
  desourceViewerCard: document.getElementById('desource-viewer-card'),
  desourceViewTitle: document.getElementById('desource-view-title'),
  desourceViewMeta: document.getElementById('desource-view-meta'),
  desourceGroqBtn: document.getElementById('desource-groq-btn'),
  desourceQuarantineBtn: document.getElementById('desource-quarantine-btn'),
  desourceGroqBox: document.getElementById('desource-groq-box'),
  desourceGroqOutput: document.getElementById('desource-groq-output'),
  desourceCodeOutput: document.getElementById('desource-code-output'),
  desourceTbody: document.getElementById('desource-tbody'),

  // Ransomware tab
  rwStatusHeading: document.getElementById('rw-status-heading'),
  rwStatusDesc: document.getElementById('rw-status-desc'),
  rwRearmBtn: document.getElementById('rw-rearm-btn'),
  rwRefreshBtn: document.getElementById('rw-refresh-btn'),
  rwFoldersTbody: document.getElementById('rw-folders-tbody'),

  // Processes, Network, Autoruns, Quarantine
  procSearchInput: document.getElementById('proc-search-input'),
  refreshProcsBtn: document.getElementById('refresh-procs-btn'),
  processesTbody: document.getElementById('processes-tbody'),

  netSearchInput: document.getElementById('net-search-input'),
  refreshNetBtn: document.getElementById('refresh-net-btn'),
  networkTbody: document.getElementById('network-tbody'),

  autorunSearchInput: document.getElementById('autorun-search-input'),
  refreshAutorunsBtn: document.getElementById('refresh-autoruns-btn'),
  autorunsTbody: document.getElementById('autoruns-tbody'),

  refreshQuarantineBtn: document.getElementById('refresh-quarantine-btn'),
  quarantineTbody: document.getElementById('quarantine-tbody'),

  // Stats tab
  statsCpuPct: document.getElementById('stats-cpu-pct'),
  statsCpuBrand: document.getElementById('stats-cpu-brand'),
  cpuGraphArea: document.getElementById('cpu-graph-area'),
  cpuGraphLine: document.getElementById('cpu-graph-line'),
  cpuGraphDot: document.getElementById('cpu-graph-dot'),

  statsRamPct: document.getElementById('stats-ram-pct'),
  statsRamDetail: document.getElementById('stats-ram-detail'),
  ramGraphArea: document.getElementById('ram-graph-area'),
  ramGraphLine: document.getElementById('ram-graph-line'),
  ramGraphDot: document.getElementById('ram-graph-dot'),

  statsProcTotal: document.getElementById('stats-proc-total'),
  statsUptimeText: document.getElementById('stats-uptime-text'),
  statsSwapText: document.getElementById('stats-swap-text'),
  statsAutoBtn: document.getElementById('stats-auto-btn'),
  statsRefreshBtn: document.getElementById('stats-refresh-btn'),
  statsRamList: document.getElementById('stats-ram-list'),
  statsCpuList: document.getElementById('stats-cpu-list'),

  toastContainer: document.getElementById('toast-container'),
};

let statsInterval = null;
let realtimeInterval = null;
let statsLiveEnabled = true;
const GRAPH_POINTS = 28;
const cpuHistory = [];
const ramHistory = [];

function getAppInitial(name) {
  if (!name) return '•';
  const cleaned = name.replace(/\.exe$/i, '').trim();
  return cleaned.charAt(0).toUpperCase() || '•';
}

function formatAppName(name) {
  if (!name) return 'Unknown';
  return name.replace(/\.exe$/i, '');
}

function tableLoaderRow(colspan, label = 'Loading...') {
  return `
    <tr>
      <td colspan="${colspan}" class="table-loader-cell">
        <div class="inline-loader">
          <div class="loader-ring sm" style="width:20px;height:20px;">
            <svg viewBox="0 0 48 48">
              <circle class="ring-track" cx="24" cy="24" r="20" fill="none" stroke-width="4" />
              <circle class="ring-Head" cx="24" cy="24" r="20" fill="none" stroke-width="4" />
            </svg>
          </div>
          <span>${label}</span>
        </div>
      </td>
    </tr>
  `;
}

function showToast(message) {
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  elements.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(6px)';
    setTimeout(() => toast.remove(), 220);
  }, 3200);
}

function switchTab(tabName) {
  state.activeTab = tabName;

  elements.navItems.forEach((item) => {
    item.classList.toggle('active', item.dataset.tab === tabName);
  });

  elements.tabViews.forEach((view) => {
    view.classList.toggle('active', view.id === `tab-${tabName}`);
  });

  const tabTitles = {
    dashboard: { title: 'Overview', sub: 'Real-time protection, source analysis, and telemetry' },
    realtime: { title: 'Real-Time Guard', sub: 'Continuous background process, network, source, and canary monitoring' },
    scanner: { title: 'Threat Scanner', sub: 'Full heuristic, de-source, and Groq AI assisted system inspection' },
    desource: { title: 'De-Source Inspector', sub: 'Static binary disassembly, string extraction, entropy, and script analysis' },
    ransomware: { title: 'Ransomware Shield', sub: 'Cryptographic canary honeypots, shadow copy guard, and folder protection' },
    stats: { title: 'Resource Graph', sub: 'Live processor and memory consumption across running applications' },
    processes: { title: 'Processes', sub: 'Running executables and memory usage' },
    network: { title: 'Network', sub: 'Active TCP and UDP sockets mapped to processes' },
    autoruns: { title: 'Startup Items', sub: 'Registry Run keys and startup folder entries' },
    quarantine: { title: 'Quarantine', sub: 'Isolated files prevented from executing' },
  };

  if (tabTitles[tabName]) {
    elements.viewTitle.textContent = tabTitles[tabName].title;
    elements.viewSubtitle.textContent = tabTitles[tabName].sub;
  }

  if (tabName === 'processes') loadProcesses();
  else if (tabName === 'network') loadNetworkSockets();
  else if (tabName === 'autoruns') loadAutoruns();
  else if (tabName === 'quarantine') loadQuarantineVault();
  else if (tabName === 'dashboard') loadSummary();
  else if (tabName === 'stats') loadStats(true);
  else if (tabName === 'realtime') pollRealtimeMonitor();
  else if (tabName === 'ransomware') loadRansomwareStatus();
  else if (tabName === 'desource' && state.sourceReports.length === 0) runBatchDesource();
}

function setupEventListeners() {
  // Custom Window Controls & Dragging
  elements.winMinBtn.addEventListener('click', () => tauriInvoke('window_minimize'));
  elements.winMaxBtn.addEventListener('click', () => tauriInvoke('window_toggle_maximize'));
  elements.winCloseBtn.addEventListener('click', () => tauriInvoke('window_close'));

  const handleDrag = (e) => {
    if (e.target.closest('button') || e.target.closest('input')) return;
    if (e.buttons === 1) {
      if (e.detail === 2) {
        tauriInvoke('window_toggle_maximize');
      } else {
        tauriInvoke('window_start_dragging');
      }
    }
  };

  elements.headerDragHandle.addEventListener('mousedown', handleDrag);
  elements.sidebarDragHandle.addEventListener('mousedown', handleDrag);

  // Groq Modal Controls
  elements.headerGroqBtn.addEventListener('click', () => {
    elements.groqModal.classList.remove('hidden');
    elements.groqKeyInput.focus();
  });

  elements.groqSkipBtn.addEventListener('click', () => {
    elements.groqModal.classList.add('hidden');
  });

  elements.groqSaveBtn.addEventListener('click', async () => {
    const key = elements.groqKeyInput.value.trim();
    try {
      const configured = await tauriInvoke('save_groq_api_key', { key });
      state.groqConfigured = Boolean(configured);
      updateGroqBadge();
      elements.groqModal.classList.add('hidden');
      showToast(state.groqConfigured ? 'Groq AI key saved for scanning' : 'Groq AI key cleared');
    } catch (err) {
      showToast(`Failed to save Groq key: ${err}`);
    }
  });

  elements.navItems.forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  if (elements.sidebarTelemetryCard) {
    elements.sidebarTelemetryCard.addEventListener('click', () => switchTab('stats'));
  }

  document.querySelectorAll('.metric-card').forEach((card) => {
    card.addEventListener('click', () => {
      if (card.dataset.targetTab) switchTab(card.dataset.targetTab);
    });
  });

  elements.viewAllProcsBtn.addEventListener('click', () => switchTab('processes'));
  elements.dashDesourceBtn.addEventListener('click', () => switchTab('desource'));

  const triggerScan = (mode) => {
    switchTab('scanner');
    setScanMode(mode);
    startScan();
  };

  elements.dashQuickScanBtn.addEventListener('click', () => triggerScan('quick'));
  elements.headerQuickScanBtn.addEventListener('click', () => triggerScan('quick'));
  elements.headerDeepScanBtn.addEventListener('click', () => triggerScan('deep'));

  elements.startScanBtn.addEventListener('click', () => {
    if (!state.isScanning) startScan();
  });

  elements.quarantineAllBtn.addEventListener('click', () => quarantineAllThreats());

  elements.segmentBtns.forEach((btn) => {
    btn.addEventListener('click', () => setScanMode(btn.dataset.scanMode));
  });

  // Real-time Guard buttons
  elements.rtPollNowBtn.addEventListener('click', () => pollRealtimeMonitor());
  elements.rtToggleBtn.addEventListener('click', async () => {
    const enabled = await tauriInvoke('toggle_realtime_shield');
    updateRealtimeUIState(enabled);
    showToast(enabled ? 'Real-Time Detection enabled' : 'Real-Time Detection paused');
  });

  // De-Source Inspector buttons
  elements.desourceInspectBtn.addEventListener('click', () => {
    const p = elements.desourcePathInput.value.trim();
    if (p) inspectSingleFileSource(p);
  });
  elements.desourceAllBtn.addEventListener('click', () => runBatchDesource());
  elements.desourceGroqBtn.addEventListener('click', () => runGroqOnCurrentSource());
  elements.desourceQuarantineBtn.addEventListener('click', async () => {
    if (state.currentDesourcePath) {
      await quarantineFile(state.currentDesourcePath, 'Suspicious De-Sourced Binary');
    }
  });

  // Ransomware buttons
  elements.rwRearmBtn.addEventListener('click', async () => {
    const count = await tauriInvoke('deploy_ransomware_canaries');
    showToast(`Re-armed ${count} ransomware canary trap files`);
    loadRansomwareStatus();
  });
  elements.rwRefreshBtn.addEventListener('click', () => loadRansomwareStatus());

  elements.refreshProcsBtn.addEventListener('click', () => loadProcesses());
  elements.refreshNetBtn.addEventListener('click', () => loadNetworkSockets());
  elements.refreshAutorunsBtn.addEventListener('click', () => loadAutoruns());
  elements.refreshQuarantineBtn.addEventListener('click', () => loadQuarantineVault());
  elements.statsRefreshBtn.addEventListener('click', () => loadStats(false));
  elements.statsAutoBtn.addEventListener('click', () => {
    statsLiveEnabled = !statsLiveEnabled;
    elements.statsAutoBtn.textContent = statsLiveEnabled ? 'Live Graph: On' : 'Live Graph: Off';
  });

  elements.procSearchInput.addEventListener('input', () => filterProcesses());
  elements.netSearchInput.addEventListener('input', () => filterNetwork());
  elements.autorunSearchInput.addEventListener('input', () => filterAutoruns());
}

function updateGroqBadge() {
  if (elements.headerGroqLabel) {
    elements.headerGroqLabel.textContent = state.groqConfigured ? 'Groq AI: Active' : 'Groq AI: Setup';
  }
}

function setScanMode(mode) {
  state.scanMode = mode;
  elements.segmentBtns.forEach((b) => {
    b.classList.toggle('active', b.dataset.scanMode === mode);
  });
}

// 1. OVERVIEW
async function loadSummary(isInitialBoot = false) {
  try {
    const [summary, procs, stats] = await Promise.all([
      tauriInvoke('get_system_summary'),
      tauriInvoke('get_all_processes'),
      tauriInvoke('get_resource_stats'),
    ]);

    if (stats) {
      renderStats(stats);
    }

    if (summary) {
      state.summary = summary;
      state.groqConfigured = Boolean(summary.groq_configured);
      updateGroqBadge();

      elements.metricProcesses.textContent = summary.total_processes;
      elements.metricProcSuspicious.textContent = `${summary.suspicious_processes} flagged`;
      elements.metricSockets.textContent = summary.active_connections;
      elements.metricSockSuspicious.textContent = `${summary.suspicious_connections} flagged`;
      elements.metricQuarantine.textContent = summary.quarantined_count;
      elements.sidebarQuarantineCount.textContent = summary.quarantined_count;

      const totalFlagged =
        summary.suspicious_processes + summary.suspicious_autoruns + summary.suspicious_connections;

      if (totalFlagged > 0) {
        elements.dashStatusHeading.textContent = `${totalFlagged} item${totalFlagged > 1 ? 's' : ''} flagged for review`;
        elements.dashStatusDesc.textContent =
          'Suspicious processes, startup hooks, or network connections were found.';
        elements.sidebarThreatCount.style.display = 'inline-block';
        elements.sidebarThreatCount.textContent = totalFlagged;
        if (elements.bannerEmblem) elements.bannerEmblem.classList.add('flagged');
      } else {
        elements.dashStatusHeading.textContent = 'No threats detected';
        elements.dashStatusDesc.textContent =
          'Real-time process guard, ransomware canary traps, and source checks are active.';
        elements.sidebarThreatCount.style.display = 'none';
        if (elements.bannerEmblem) elements.bannerEmblem.classList.remove('flagged');
      }
    }

    if (procs) {
      state.processes = procs;
      renderOverviewProcesses(procs.slice(0, 8));
    }
  } catch (err) {
    console.error('Error loading overview:', err);
  } finally {
    if (isInitialBoot && elements.appLoader) {
      setTimeout(() => {
        elements.appLoader.classList.add('hidden');
        // Show Groq prompt if not yet configured
        if (!state.groqConfigured) {
          setTimeout(() => {
            elements.groqModal.classList.remove('hidden');
          }, 350);
        }
      }, 280);
    }
  }
}

function renderOverviewProcesses(list) {
  elements.overviewProcsTbody.innerHTML = '';
  list.forEach((proc) => {
    const tr = document.createElement('tr');
    if (proc.is_suspicious) tr.className = 'suspicious-row';
    const memMb = (proc.memory_bytes / (1024 * 1024)).toFixed(1);

    tr.innerHTML = `
      <td class="mono-cell">${proc.pid}</td>
      <td>
        <div class="app-cell">
          <div class="app-avatar">${getAppInitial(proc.name)}</div>
          <span style="color: var(--text-primary); font-weight: 500;">${proc.name}</span>
        </div>
      </td>
      <td class="mono-cell" style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${proc.exe_path}">
        ${proc.exe_path || 'System Process'}
      </td>
      <td class="mono-cell">${memMb} MB</td>
      <td>
        <span class="status-label-pill ${proc.is_suspicious ? 'suspicious' : 'clean'}">
          ${proc.is_suspicious ? 'Flagged' : 'Normal'}
        </span>
      </td>
      <td style="text-align: right;">
        ${proc.exe_path ? `<button class="glass-btn secondary sm desource-proc-btn">De-Source</button>` : ''}
      </td>
    `;

    const dsBtn = tr.querySelector('.desource-proc-btn');
    if (dsBtn) {
      dsBtn.addEventListener('click', () => {
        switchTab('desource');
        elements.desourcePathInput.value = proc.exe_path;
        inspectSingleFileSource(proc.exe_path);
      });
    }

    elements.overviewProcsTbody.appendChild(tr);
  });
}

// 2. REAL-TIME DETECTION
function updateRealtimeUIState(enabled) {
  if (elements.sidebarRtBadge) {
    elements.sidebarRtBadge.textContent = enabled ? 'On' : 'Paused';
  }
  if (elements.rtStatusHeading) {
    elements.rtStatusHeading.textContent = enabled
      ? 'Real-Time Detection Active'
      : 'Real-Time Detection Paused';
  }
  if (elements.rtToggleBtn) {
    elements.rtToggleBtn.textContent = enabled
      ? 'Pause Real-Time Guard'
      : 'Resume Real-Time Guard';
  }
}

async function pollRealtimeMonitor() {
  try {
    const rt = await tauriInvoke('poll_realtime_monitor');
    if (!rt) return;

    updateRealtimeUIState(rt.enabled);
    if (elements.rtEventsCount) elements.rtEventsCount.textContent = rt.events_inspected;
    if (elements.rtFlaggedCount) elements.rtFlaggedCount.textContent = rt.threats_flagged;

    if (elements.rtEventsTbody) {
      elements.rtEventsTbody.innerHTML = '';
      rt.recent_events.forEach((ev) => {
        const tr = document.createElement('tr');
        const isFlagged = ev.status === 'Flagged';
        if (isFlagged) tr.className = 'suspicious-row';

        tr.innerHTML = `
          <td class="mono-cell">${ev.timestamp}</td>
          <td style="color: var(--text-primary); font-weight: 500;">${ev.event_type}</td>
          <td class="mono-cell">${ev.target}</td>
          <td style="color: var(--text-secondary);">${ev.detail}</td>
          <td>
            <span class="status-label-pill ${isFlagged ? 'suspicious' : 'clean'}">
              ${ev.status}
            </span>
          </td>
        `;
        elements.rtEventsTbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error('Real-time poll error:', err);
  }
}

// 3. SCANNER
async function startScan() {
  if (state.isScanning) return;
  state.isScanning = true;

  elements.startScanBtn.disabled = true;
  elements.startScanBtn.querySelector('span').textContent = 'Scanning...';
  elements.scanLoaderCard.style.display = 'flex';
  elements.scanGroqCard.style.display = 'none';
  elements.quarantineAllBtn.style.display = 'none';
  elements.scanStepTitle.textContent =
    state.scanMode === 'deep'
      ? 'Running deep scan + de-sourcing executables...'
      : 'Running quick scan + de-source check...';
  elements.scanTargetText.textContent =
    'Inspecting processes, binary source entropy, startup keys, network sockets, and ransomware traps';

  try {
    const cmd = state.scanMode === 'deep' ? 'run_deep_scan' : 'run_quick_scan';
    const result = await tauriInvoke(cmd);

    elements.scanLoaderCard.style.display = 'none';
    elements.startScanBtn.disabled = false;
    elements.startScanBtn.querySelector('span').textContent = 'Start Scan';
    state.isScanning = false;
    renderScanResults(result);
  } catch (err) {
    elements.scanLoaderCard.style.display = 'none';
    elements.startScanBtn.disabled = false;
    elements.startScanBtn.querySelector('span').textContent = 'Start Scan';
    state.isScanning = false;
    showToast(`Scan failed: ${err}`);
  }
}

function renderScanResults(result) {
  state.threats = result.threats || [];
  const count = state.threats.length;

  elements.resultsCountText.textContent = `Scanned ${result.total_scanned} items (de-sourced ${result.desourced_count || 0} binaries) in ${result.elapsed_ms} ms · ${count} ${count === 1 ? 'finding' : 'findings'}`;
  elements.threatCardsList.innerHTML = '';

  if (result.groq_ai_summary) {
    elements.scanGroqCard.style.display = 'flex';
    elements.scanGroqText.textContent = result.groq_ai_summary;
  } else {
    elements.scanGroqCard.style.display = 'none';
  }

  if (count === 0) {
    elements.quarantineAllBtn.style.display = 'none';
    elements.threatCardsList.appendChild(elements.scannerEmptyState);
    elements.scannerEmptyState.style.display = 'flex';
  } else {
    elements.quarantineAllBtn.style.display = 'inline-flex';
    elements.sidebarThreatCount.style.display = 'inline-block';
    elements.sidebarThreatCount.textContent = count;

    state.threats.forEach((threat) => {
      elements.threatCardsList.appendChild(createThreatCard(threat));
    });
  }

  loadSummary();
}

function createThreatCard(threat) {
  const card = document.createElement('div');
  const sevLower = threat.severity ? threat.severity.toLowerCase() : 'medium';
  card.className = 'threat-card glass-card';

  const metaParts = [
    threat.pid ? `PID ${threat.pid}` : '',
    threat.file_path || '',
    threat.remote_addr || '',
    threat.registry_key || '',
  ]
    .filter(Boolean)
    .join(' · ');

  card.innerHTML = `
    <div class="threat-details">
      <div class="threat-title-row">
        <span class="threat-title">${threat.name}</span>
        <span class="threat-tag ${sevLower}">${threat.severity}</span>
        <span class="threat-tag">${threat.category}</span>
      </div>
      <p class="threat-desc">${threat.description}</p>
      <div class="threat-meta-row">${metaParts}</div>
    </div>
    <div class="threat-actions-cell">
      ${threat.file_path ? `<button class="glass-btn secondary sm desource-threat-btn">De-Source</button>` : ''}
      ${threat.pid ? `<button class="glass-btn danger sm kill-proc-btn">End Process</button>` : ''}
      ${threat.file_path ? `<button class="glass-btn primary sm quarantine-file-btn">Quarantine</button>` : ''}
      ${threat.registry_key ? `<button class="glass-btn secondary sm remove-reg-btn">Remove Entry</button>` : ''}
    </div>
  `;

  const dsBtn = card.querySelector('.desource-threat-btn');
  if (dsBtn) {
    dsBtn.addEventListener('click', () => {
      switchTab('desource');
      elements.desourcePathInput.value = threat.file_path;
      inspectSingleFileSource(threat.file_path);
    });
  }

  const killBtn = card.querySelector('.kill-proc-btn');
  if (killBtn) {
    killBtn.addEventListener('click', async () => {
      await terminateProcess(threat.pid);
      card.remove();
    });
  }

  const qBtn = card.querySelector('.quarantine-file-btn');
  if (qBtn) {
    qBtn.addEventListener('click', async () => {
      await quarantineFile(threat.file_path, threat.name);
      card.remove();
    });
  }

  const regBtn = card.querySelector('.remove-reg-btn');
  if (regBtn) {
    regBtn.addEventListener('click', async () => {
      const parts = threat.registry_key.split('\\');
      const valName = parts.pop();
      const loc = parts.join('\\');
      await removeAutorun(loc, valName);
      card.remove();
    });
  }

  return card;
}

async function quarantineAllThreats() {
  let count = 0;
  for (const t of state.threats) {
    if (t.pid) await terminateProcess(t.pid);
    if (t.file_path) {
      await quarantineFile(t.file_path, t.name);
      count++;
    }
  }
  showToast(`Quarantined ${count} item(s)`);
  elements.threatCardsList.innerHTML = '';
  elements.threatCardsList.appendChild(elements.scannerEmptyState);
  elements.quarantineAllBtn.style.display = 'none';
  loadSummary();
}

// 4. DE-SOURCE / SOURCE INSPECTOR
async function inspectSingleFileSource(path) {
  try {
    state.currentDesourcePath = path;
    elements.desourceViewerCard.style.display = 'flex';
    elements.desourceGroqBox.style.display = 'none';
    elements.desourceViewTitle.textContent = `Inspecting ${path}...`;
    elements.desourceCodeOutput.textContent = '// Extracting binary strings, PE headers, and calculating Shannon entropy...';

    const report = await tauriInvoke('inspect_file_source', {
      path,
      useGroq: state.groqConfigured,
    });

    if (report) {
      renderDesourceViewer(report);
    }
  } catch (err) {
    elements.desourceCodeOutput.textContent = `// Error inspecting file: ${err}`;
    showToast(`Could not de-source file: ${err}`);
  }
}

function renderDesourceViewer(report) {
  state.currentDesourcePath = report.file_path;
  elements.desourceViewerCard.style.display = 'flex';
  elements.desourceViewTitle.textContent = `${report.file_name} — ${report.verdict}`;
  elements.desourceViewMeta.textContent = `${report.file_format} · Entropy: ${report.entropy.toFixed(2)} bits/byte · Risk Score: ${report.risk_score}/100 · SHA-256: ${report.sha256.substring(0, 16)}…`;
  elements.desourceCodeOutput.textContent = report.desourced_preview;

  if (report.groq_analysis) {
    elements.desourceGroqBox.style.display = 'flex';
    elements.desourceGroqOutput.textContent = report.groq_analysis;
  } else {
    elements.desourceGroqBox.style.display = 'none';
  }
}

async function runGroqOnCurrentSource() {
  if (!state.currentDesourcePath) return;
  if (!state.groqConfigured) {
    elements.groqModal.classList.remove('hidden');
    return;
  }
  try {
    elements.desourceGroqBox.style.display = 'flex';
    elements.desourceGroqOutput.textContent = 'Querying Groq AI (llama-3.3-70b-versatile) for deep source analysis...';
    const analysis = await tauriInvoke('analyze_source_with_groq', {
      path: state.currentDesourcePath,
    });
    elements.desourceGroqOutput.textContent = analysis;
  } catch (err) {
    elements.desourceGroqOutput.textContent = `Groq AI analysis error: ${err}`;
  }
}

async function runBatchDesource() {
  try {
    elements.desourceTbody.innerHTML = tableLoaderRow(7, 'De-sourcing active executables & calculating entropy...');
    const reports = await tauriInvoke('scan_all_sources');
    state.sourceReports = reports || [];
    renderBatchDesourceTable(state.sourceReports);
  } catch (err) {
    showToast(`Batch de-source failed: ${err}`);
  }
}

function renderBatchDesourceTable(reports) {
  elements.desourceTbody.innerHTML = '';
  if (reports.length === 0) {
    elements.desourceTbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 28px;">No accessible user binaries to de-source</td></tr>';
    return;
  }

  reports.forEach((rep) => {
    const tr = document.createElement('tr');
    const isHighRisk = rep.risk_score >= 55;
    if (isHighRisk) tr.className = 'suspicious-row';

    tr.innerHTML = `
      <td>
        <div class="app-cell">
          <div class="app-avatar">${getAppInitial(rep.file_name)}</div>
          <span style="color: var(--text-primary); font-weight: 500;" title="${rep.file_path}">${rep.file_name}</span>
        </div>
      </td>
      <td class="mono-cell">${rep.file_format}</td>
      <td class="mono-cell">${rep.entropy.toFixed(2)} ${rep.is_packed_or_encrypted ? '(Packed)' : ''}</td>
      <td class="mono-cell">${rep.suspicious_apis.length} APIs</td>
      <td class="mono-cell">${rep.risk_score} / 100</td>
      <td>
        <span class="status-label-pill ${isHighRisk ? 'suspicious' : 'clean'}">
          ${rep.verdict}
        </span>
      </td>
      <td style="text-align: right;">
        <button class="glass-btn secondary sm view-source-btn">View Source</button>
      </td>
    `;

    tr.querySelector('.view-source-btn').addEventListener('click', () => {
      elements.desourcePathInput.value = rep.file_path;
      renderDesourceViewer(rep);
    });

    elements.desourceTbody.appendChild(tr);
  });
}

// 5. RANSOMWARE PROTECTION
async function loadRansomwareStatus() {
  try {
    elements.rwFoldersTbody.innerHTML = tableLoaderRow(5, 'Verifying protected directories and cryptographic canary traps...');
    const status = await tauriInvoke('get_ransomware_status');
    if (!status) return;

    elements.rwFoldersTbody.innerHTML = '';
    status.protected_folders.forEach((folder) => {
      const tr = document.createElement('tr');
      const isCompromised = !folder.canary_intact || folder.suspicious_files_found > 0;
      if (isCompromised) tr.className = 'suspicious-row';

      tr.innerHTML = `
        <td style="color: var(--text-primary); font-weight: 500;">${folder.label}</td>
        <td class="mono-cell">${folder.path}</td>
        <td class="mono-cell" title="${folder.canary_path}">.nospy_canary_trap.txt</td>
        <td class="mono-cell">${folder.suspicious_files_found} found</td>
        <td>
          <span class="status-label-pill ${isCompromised ? 'suspicious' : 'clean'}">
            ${folder.canary_intact ? 'SHA-256 Verified' : 'Tampered'}
          </span>
        </td>
      `;
      elements.rwFoldersTbody.appendChild(tr);
    });
  } catch (err) {
    showToast(`Failed to check ransomware status: ${err}`);
  }
}

// 6. PROCESSES
async function loadProcesses() {
  try {
    elements.processesTbody.innerHTML = tableLoaderRow(7, 'Loading processes...');
    const procs = await tauriInvoke('get_all_processes');
    state.processes = procs || [];
    renderProcesses(state.processes);
  } catch (err) {
    showToast(`Failed to load processes: ${err}`);
  }
}

function renderProcesses(list) {
  elements.processesTbody.innerHTML = '';
  if (list.length === 0) {
    elements.processesTbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 28px;">No matching processes</td></tr>';
    return;
  }

  list.forEach((proc) => {
    const tr = document.createElement('tr');
    if (proc.is_suspicious) tr.className = 'suspicious-row';

    const memMb = (proc.memory_bytes / (1024 * 1024)).toFixed(1);
    const cpuPct = proc.cpu_usage.toFixed(1);

    tr.innerHTML = `
      <td class="mono-cell">${proc.pid}</td>
      <td>
        <div class="app-cell">
          <div class="app-avatar">${getAppInitial(proc.name)}</div>
          <span style="color: var(--text-primary); font-weight: 500;">${proc.name}</span>
        </div>
      </td>
      <td class="mono-cell" style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${proc.exe_path}">
        ${proc.exe_path || 'System Process'}
      </td>
      <td class="mono-cell">${cpuPct}%</td>
      <td class="mono-cell">${memMb} MB</td>
      <td>
        <span class="status-label-pill ${proc.is_suspicious ? 'suspicious' : 'clean'}" title="${proc.suspicion_reason || ''}">
          ${proc.is_suspicious ? 'Flagged' : 'Normal'}
        </span>
      </td>
      <td style="text-align: right;">
        <div style="display: inline-flex; gap: 6px;">
          ${proc.exe_path ? `<button class="glass-btn secondary sm ds-btn">De-Source</button>` : ''}
          <button class="glass-btn secondary sm kill-btn">End</button>
        </div>
      </td>
    `;

    const dsBtn = tr.querySelector('.ds-btn');
    if (dsBtn) {
      dsBtn.addEventListener('click', () => {
        switchTab('desource');
        elements.desourcePathInput.value = proc.exe_path;
        inspectSingleFileSource(proc.exe_path);
      });
    }

    tr.querySelector('.kill-btn').addEventListener('click', async () => {
      await terminateProcess(proc.pid);
      tr.remove();
    });

    elements.processesTbody.appendChild(tr);
  });
}

function filterProcesses() {
  const q = elements.procSearchInput.value.toLowerCase().trim();
  if (!q) return renderProcesses(state.processes);
  renderProcesses(
    state.processes.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.pid.toString().includes(q) ||
        p.exe_path.toLowerCase().includes(q)
    )
  );
}

async function terminateProcess(pid) {
  try {
    await tauriInvoke('terminate_process', { pid: Number(pid) });
    showToast(`Terminated PID ${pid}`);
    loadSummary();
  } catch (err) {
    showToast(`Could not terminate PID ${pid}: ${err}`);
  }
}

// 7. NETWORK
async function loadNetworkSockets() {
  try {
    elements.networkTbody.innerHTML = tableLoaderRow(7, 'Loading network connections...');
    const sockets = await tauriInvoke('get_all_network_sockets');
    state.networkSockets = sockets || [];
    renderNetworkSockets(state.networkSockets);
  } catch (err) {
    showToast(`Failed to load network connections: ${err}`);
  }
}

function renderNetworkSockets(list) {
  elements.networkTbody.innerHTML = '';
  if (list.length === 0) {
    elements.networkTbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 28px;">No matching connections</td></tr>';
    return;
  }

  list.forEach((sock) => {
    const tr = document.createElement('tr');
    if (sock.is_suspicious) tr.className = 'suspicious-row';

    tr.innerHTML = `
      <td class="mono-cell">${sock.protocol}</td>
      <td>
        <div class="app-cell">
          <div class="app-avatar">${getAppInitial(sock.process_name)}</div>
          <span style="color: var(--text-primary); font-weight: 500;">${sock.process_name}</span>
        </div>
      </td>
      <td class="mono-cell">${sock.pid}</td>
      <td class="mono-cell">${sock.local_addr}</td>
      <td class="mono-cell">${sock.remote_addr}</td>
      <td class="mono-cell">${sock.state}</td>
      <td>
        <span class="status-label-pill ${sock.is_suspicious ? 'suspicious' : 'clean'}" title="${sock.risk_reason || ''}">
          ${sock.is_suspicious ? 'Flagged' : 'Normal'}
        </span>
      </td>
    `;
    elements.networkTbody.appendChild(tr);
  });
}

function filterNetwork() {
  const q = elements.netSearchInput.value.toLowerCase().trim();
  if (!q) return renderNetworkSockets(state.networkSockets);
  renderNetworkSockets(
    state.networkSockets.filter(
      (s) =>
        s.process_name.toLowerCase().includes(q) ||
        s.pid.toString().includes(q) ||
        s.remote_addr.toLowerCase().includes(q) ||
        s.local_addr.toLowerCase().includes(q)
    )
  );
}

// 8. STARTUP / AUTORUNS
async function loadAutoruns() {
  try {
    elements.autorunsTbody.innerHTML = tableLoaderRow(6, 'Loading startup items...');
    const autoruns = await tauriInvoke('get_all_autoruns');
    state.autoruns = autoruns || [];
    renderAutoruns(state.autoruns);
  } catch (err) {
    showToast(`Failed to load startup entries: ${err}`);
  }
}

function renderAutoruns(list) {
  elements.autorunsTbody.innerHTML = '';
  if (list.length === 0) {
    elements.autorunsTbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 28px;">No startup entries found</td></tr>';
    return;
  }

  list.forEach((item) => {
    const tr = document.createElement('tr');
    if (item.is_suspicious) tr.className = 'suspicious-row';

    tr.innerHTML = `
      <td>
        <div class="app-cell">
          <div class="app-avatar">${getAppInitial(item.name)}</div>
          <span style="color: var(--text-primary); font-weight: 500;">${item.name}</span>
        </div>
      </td>
      <td>${item.source}</td>
      <td class="mono-cell" style="max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.location}">
        ${item.location}
      </td>
      <td class="mono-cell" style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.command}">
        ${item.command}
      </td>
      <td>
        <span class="status-label-pill ${item.is_suspicious ? 'suspicious' : 'clean'}" title="${item.reason || ''}">
          ${item.is_suspicious ? 'Flagged' : 'Normal'}
        </span>
      </td>
      <td style="text-align: right;">
        <button class="glass-btn secondary sm del-autorun-btn">Remove</button>
      </td>
    `;

    tr.querySelector('.del-autorun-btn').addEventListener('click', async () => {
      await removeAutorun(item.location, item.name);
      tr.remove();
    });

    elements.autorunsTbody.appendChild(tr);
  });
}

function filterAutoruns() {
  const q = elements.autorunSearchInput.value.toLowerCase().trim();
  if (!q) return renderAutoruns(state.autoruns);
  renderAutoruns(
    state.autoruns.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.command.toLowerCase().includes(q) ||
        a.location.toLowerCase().includes(q)
    )
  );
}

async function removeAutorun(location, name) {
  try {
    await tauriInvoke('remove_autorun', { location, name });
    showToast(`Removed startup entry: ${name}`);
    loadSummary();
  } catch (err) {
    showToast(`Could not remove '${name}': ${err}`);
  }
}

// 9. QUARANTINE
async function loadQuarantineVault() {
  try {
    elements.quarantineTbody.innerHTML = tableLoaderRow(5, 'Loading quarantine...');
    const items = await tauriInvoke('list_quarantine');
    state.quarantine = items || [];
    renderQuarantine(state.quarantine);
  } catch (err) {
    showToast(`Failed to load quarantine: ${err}`);
  }
}

function renderQuarantine(list) {
  elements.quarantineTbody.innerHTML = '';
  elements.sidebarQuarantineCount.textContent = list.length;
  elements.metricQuarantine.textContent = list.length;

  if (list.length === 0) {
    elements.quarantineTbody.innerHTML =
      '<tr><td colspan="5" style="text-align:center; padding: 32px; color: var(--text-tertiary);">No files in quarantine</td></tr>';
    return;
  }

  list.forEach((item) => {
    const tr = document.createElement('tr');
    const dateFormatted = new Date(item.quarantined_at).toLocaleDateString();
    const shortHash = item.sha256_hash ? `${item.sha256_hash.substring(0, 14)}…` : '—';

    tr.innerHTML = `
      <td style="color: var(--text-primary); font-weight: 500;">${item.threat_name}</td>
      <td class="mono-cell" title="${item.original_path}">${item.original_path}</td>
      <td class="mono-cell" title="${item.sha256_hash}">${shortHash}</td>
      <td class="mono-cell">${dateFormatted}</td>
      <td style="text-align: right;">
        <div style="display: inline-flex; gap: 6px;">
          <button class="glass-btn secondary sm restore-btn">Restore</button>
          <button class="glass-btn danger sm purge-btn">Delete</button>
        </div>
      </td>
    `;

    tr.querySelector('.restore-btn').addEventListener('click', async () => {
      try {
        await tauriInvoke('restore_quarantined_file', { id: item.id });
        showToast('File restored');
        tr.remove();
        loadQuarantineVault();
      } catch (err) {
        showToast(`Restore failed: ${err}`);
      }
    });

    tr.querySelector('.purge-btn').addEventListener('click', async () => {
      try {
        await tauriInvoke('delete_quarantined_file', { id: item.id });
        showToast('File permanently deleted');
        tr.remove();
        loadQuarantineVault();
      } catch (err) {
        showToast(`Delete failed: ${err}`);
      }
    });

    elements.quarantineTbody.appendChild(tr);
  });
}

async function quarantineFile(path, threatName) {
  try {
    await tauriInvoke('quarantine_file', { path, threatName });
    showToast(`Quarantined ${threatName}`);
    loadSummary();
  } catch (err) {
    showToast(`Quarantine failed: ${err}`);
  }
}

// 10. RESOURCE STATS & SMOOTH GRAPH UI
function formatBytes(bytes) {
  const gb = bytes / (1024 * 1024 * 1024);
  if (gb >= 1) return `${gb.toFixed(2)} GB`;
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(1)} MB`;
}

function formatUptime(sec) {
  const hrs = Math.floor(sec / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  return `${hrs}h ${mins}m`;
}

function buildSmoothGraphPaths(values, width = 460, height = 120) {
  const topPad = 10;
  const bottomPad = 6;
  const usableHeight = height - topPad - bottomPad;
  const stepX = width / (GRAPH_POINTS - 1);

  const coords = values.map((val, idx) => {
    const clamped = Math.min(100, Math.max(0, val));
    const x = idx * stepX;
    const y = topPad + usableHeight * (1 - clamped / 100);
    return { x, y };
  });

  if (coords.length === 0) {
    return { linePath: '', areaPath: '', topPercent: 90 };
  }

  let d = `M ${coords[0].x.toFixed(1)} ${coords[0].y.toFixed(1)}`;
  for (let i = 0; i < coords.length - 1; i++) {
    const p0 = coords[i];
    const p1 = coords[i + 1];
    const cpx1 = p0.x + (p1.x - p0.x) * 0.45;
    const cpy1 = p0.y;
    const cpx2 = p0.x + (p1.x - p0.x) * 0.55;
    const cpy2 = p1.y;
    d += ` C ${cpx1.toFixed(1)} ${cpy1.toFixed(1)}, ${cpx2.toFixed(1)} ${cpy2.toFixed(1)}, ${p1.x.toFixed(1)} ${p1.y.toFixed(1)}`;
  }

  const last = coords[coords.length - 1];
  const areaPath = `${d} L ${last.x.toFixed(1)} ${height} L ${coords[0].x.toFixed(1)} ${height} Z`;
  const topPercent = (last.y / height) * 100;

  return { linePath: d, areaPath, topPercent };
}

function updateTelemetryGraph(historyArr, newValue, lineEl, areaEl, dotEl) {
  if (historyArr.length === 0) {
    for (let i = 0; i < GRAPH_POINTS - 1; i++) {
      historyArr.push(Math.max(1, newValue * 0.92));
    }
  }
  historyArr.push(newValue);
  while (historyArr.length > GRAPH_POINTS) {
    historyArr.shift();
  }

  const { linePath, areaPath, topPercent } = buildSmoothGraphPaths(historyArr, 460, 120);
  if (lineEl) lineEl.setAttribute('d', linePath);
  if (areaEl) areaEl.setAttribute('d', areaPath);
  if (dotEl) {
    dotEl.style.top = `${topPercent.toFixed(1)}%`;
  }
}

async function loadStats(showLoader = false) {
  try {
    if (showLoader && !elements.statsRamList.children.length) {
      const loaderHtml = `
        <div style="padding: 32px; text-align: center;">
          <div class="inline-loader">
            <div class="loader-ring sm" style="width:18px;height:18px;">
              <svg viewBox="0 0 48 48">
                <circle class="ring-track" cx="24" cy="24" r="20" fill="none" stroke-width="4" />
                <circle class="ring-Head" cx="24" cy="24" r="20" fill="none" stroke-width="4" />
              </svg>
            </div>
            <span>Sampling system resources...</span>
          </div>
        </div>
      `;
      elements.statsRamList.innerHTML = loaderHtml;
      elements.statsCpuList.innerHTML = loaderHtml;
    }

    const stats = await tauriInvoke('get_resource_stats');
    if (stats) {
      renderStats(stats);
    }
  } catch (err) {
    console.error('Failed to load resource stats:', err);
  }
}

function renderStats(stats) {
  const cpuPct = Math.min(100, Math.max(0, stats.global_cpu_usage));
  elements.statsCpuPct.textContent = `${cpuPct.toFixed(1)}%`;
  elements.statsCpuBrand.textContent = `${stats.cpu_brand} · ${stats.cpu_cores} logical cores`;
  updateTelemetryGraph(
    cpuHistory,
    cpuPct,
    elements.cpuGraphLine,
    elements.cpuGraphArea,
    elements.cpuGraphDot
  );

  const ramPct = Math.min(100, Math.max(0, stats.memory_usage_percent));
  elements.statsRamPct.textContent = `${ramPct.toFixed(1)}%`;
  elements.statsRamDetail.textContent = `${formatBytes(stats.used_memory_bytes)} of ${formatBytes(stats.total_memory_bytes)} used`;
  updateTelemetryGraph(
    ramHistory,
    ramPct,
    elements.ramGraphLine,
    elements.ramGraphArea,
    elements.ramGraphDot
  );

  if (elements.sideCpuVal) elements.sideCpuVal.textContent = `${cpuPct.toFixed(0)}%`;
  if (elements.sideCpuBar) elements.sideCpuBar.style.width = `${cpuPct}%`;
  if (elements.sideRamVal) elements.sideRamVal.textContent = `${ramPct.toFixed(0)}%`;
  if (elements.sideRamBar) elements.sideRamBar.style.width = `${ramPct}%`;

  elements.statsProcTotal.textContent = `${stats.total_processes}`;
  elements.statsUptimeText.textContent = formatUptime(stats.uptime_seconds);
  elements.statsSwapText.textContent = formatBytes(stats.used_swap_bytes);

  elements.statsRamList.innerHTML = '';
  const maxMem = stats.top_memory_apps[0]?.memory_bytes || 1;
  stats.top_memory_apps.forEach((app) => {
    const row = document.createElement('div');
    row.className = 'consumer-row';
    const relBar = Math.min(100, Math.max(3, (app.memory_bytes / maxMem) * 100));
    const instBadge = app.instance_count > 1 ? `${app.instance_count} processes` : '';

    row.innerHTML = `
      <div class="app-avatar lg">${getAppInitial(app.name)}</div>
      <div class="consumer-main">
        <div class="consumer-top-line">
          <div class="consumer-name-wrap">
            <span class="consumer-name" title="${app.exe_path || app.name}">${formatAppName(app.name)}</span>
            <span class="consumer-instances">${instBadge}</span>
          </div>
          <span class="consumer-metric">${formatBytes(app.memory_bytes)} · ${app.memory_percent.toFixed(1)}%</span>
        </div>
        <div class="consumer-bar-bg">
          <div class="consumer-bar-fill" style="width: ${relBar}%"></div>
        </div>
      </div>
      <button class="glass-btn secondary sm kill-consumer-btn" title="End PID ${app.pid}">End</button>
    `;

    row.querySelector('.kill-consumer-btn').addEventListener('click', async () => {
      await terminateProcess(app.pid);
      loadStats(false);
    });

    elements.statsRamList.appendChild(row);
  });

  elements.statsCpuList.innerHTML = '';
  const maxCpu = Math.max(stats.top_cpu_apps[0]?.cpu_usage || 1, 1);
  stats.top_cpu_apps.forEach((app) => {
    const row = document.createElement('div');
    row.className = 'consumer-row';
    const relBar = Math.min(100, Math.max(3, (app.cpu_usage / maxCpu) * 100));
    const instBadge = app.instance_count > 1 ? `${app.instance_count} processes` : '';

    row.innerHTML = `
      <div class="app-avatar lg">${getAppInitial(app.name)}</div>
      <div class="consumer-main">
        <div class="consumer-top-line">
          <div class="consumer-name-wrap">
            <span class="consumer-name" title="${app.exe_path || app.name}">${formatAppName(app.name)}</span>
            <span class="consumer-instances">${instBadge}</span>
          </div>
          <span class="consumer-metric">${app.cpu_usage.toFixed(1)}% · ${formatBytes(app.memory_bytes)}</span>
        </div>
        <div class="consumer-bar-bg">
          <div class="consumer-bar-fill" style="width: ${relBar}%"></div>
        </div>
      </div>
      <button class="glass-btn secondary sm kill-consumer-btn" title="End PID ${app.pid}">End</button>
    `;

    row.querySelector('.kill-consumer-btn').addEventListener('click', async () => {
      await terminateProcess(app.pid);
      loadStats(false);
    });

    elements.statsCpuList.appendChild(row);
  });
}

window.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  loadSummary(true);
  pollRealtimeMonitor();

  statsInterval = setInterval(() => {
    if (statsLiveEnabled) {
      loadStats(false);
    }
  }, 2000);

  realtimeInterval = setInterval(() => {
    pollRealtimeMonitor();
  }, 4000);
});
