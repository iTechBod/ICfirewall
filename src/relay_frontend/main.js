import { Actor, HttpAgent } from 'https://esm.sh/@dfinity/agent';

const isLocalReplica = window.location.hostname.endsWith('.localhost')
  || window.location.hostname === 'localhost'
  || window.location.hostname === '127.0.0.1';

const CANISTER_ID = isLocalReplica
  ? ''
  : '';

const HOST = isLocalReplica ? 'http://localhost:4943' : 'https://icp0.io';

const idlFactory = ({ IDL }) => {
  const SystemStats = IDL.Record({
    mode: IDL.Text,
    activeQueueLength: IDL.Nat,
    totalProcessed: IDL.Nat,
    totalBlocked: IDL.Nat,
  });

  const ThreatEvent = IDL.Record({
    timestamp: IDL.Int,
    threatType: IDL.Text,
    severity: IDL.Text,
    snippet: IDL.Text,
  });

  const PromptResult = IDL.Record({
    allowed: IDL.Bool,
    mode: IDL.Text,
    response: IDL.Text,
    reason: IDL.Text,
  });

  return IDL.Service({
    getStats: IDL.Func([], [SystemStats], ['query']),
    getThreats: IDL.Func([], [IDL.Vec(ThreatEvent)], ['query']),
    setMode: IDL.Func([IDL.Text], [IDL.Text], []),
    processPrompt: IDL.Func([IDL.Text], [PromptResult], []),
  });
};

const agent = new HttpAgent({
  host: HOST,
  verifyQuerySignatures: !isLocalReplica,
});

if (isLocalReplica) {
  try {
    await agent.fetchRootKey();
  } catch (error) {
    console.error('Local replica root key unavailable:', error);
  }
}

const actor = Actor.createActor(idlFactory, {
  agent,
  canisterId: CANISTER_ID,
});

const modeButtons = document.querySelectorAll('[data-mode]');
const statProcessed = document.getElementById('stat-processed');
const statBlocked = document.getElementById('stat-blocked');
const statQueue = document.getElementById('stat-queue');
const statStatus = document.getElementById('stat-status');
const threatTable = document.getElementById('threat-table');
const topbarTime = document.getElementById('topbar-time');
const modeFeedback = document.getElementById('mode-feedback');
const coffeeBtn = document.getElementById('coffee-btn');
const devWebsiteBtn = document.getElementById('dev-website-btn');

// Chat UI Elements
const chatForm = document.getElementById('chat-form');
const promptInput = document.getElementById('prompt-input');
const sendPromptBtn = document.getElementById('send-prompt-btn');
const chatStatus = document.getElementById('chat-status');
const chatOutputCard = document.getElementById('chat-output-card');
const outputBadge = document.getElementById('output-badge');
const outputModeTag = document.getElementById('output-mode-tag');
const outputText = document.getElementById('output-text');
const outputReason = document.getElementById('output-reason');

let modeRequestInFlight = false;
let dashboardRefreshInFlight = false;
let dashboardRefreshTimer;

function setModeFeedback(message, state = '') {
  if (!modeFeedback) return;
  modeFeedback.textContent = message;
  modeFeedback.dataset.state = state;
}

function setModeButtonsDisabled(disabled) {
  modeButtons.forEach((button) => {
    button.disabled = disabled;
    button.classList.toggle('is-loading', disabled);
  });
}

function updateClock() {
  if (!topbarTime) return;
  topbarTime.textContent = new Date().toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function setButtonState(mode) {
  const normalized = mode.split(' ')[0].toLowerCase();
  const buttonModeMap = { off: 'Off', medium: 'Medium', on: 'On' };

  modeButtons.forEach((button) => {
    const active = button.dataset.mode === buttonModeMap[normalized];
    button.classList.toggle('active', active);
  });
}

function formatTimestamp(timestamp) {
  const ts = Number(timestamp) / 1_000_000;
  const date = new Date(ts);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
}

function renderThreats(threats) {
  const rows = threats.map((event) => `
    <tr>
      <td>${formatTimestamp(event.timestamp)}</td>
      <td>${event.severity}</td>
      <td>${event.threatType}</td>
      <td>${event.snippet}</td>
    </tr>
  `).join('');

  threatTable.innerHTML = `
    <tr><th>Time</th><th>Severity</th><th>Threat Type</th><th>Payload Snippet</th></tr>
    ${rows || '<tr><td colspan="4">No threats recorded.</td></tr>'}
  `;
}

async function refreshStats(showFeedback = true) {
  try {
    const stats = await actor.getStats();
    statProcessed.textContent = String(stats.totalProcessed);
    statBlocked.textContent = String(stats.totalBlocked);
    statQueue.textContent = String(stats.activeQueueLength);
    statStatus.textContent = stats.mode;
    statStatus.className = 'status-ok';
    setButtonState(stats.mode.replace(/ .*$/, '').trim());

    if (showFeedback) {
      setModeFeedback(`Firewall ${stats.mode.split(' ')[0].toLowerCase()} and synced`, 'success');
    } else if (!modeRequestInFlight) {
      setModeFeedback(`Live • ${stats.mode.split(' ')[0].toLowerCase()} synced`, 'success');
    }
  } catch (error) {
    console.error('Failed to load stats:', error);
    statStatus.textContent = 'Offline';
    statStatus.className = 'status-error';
    if (showFeedback) {
      setModeFeedback(`Backend unavailable: ${error?.message || 'connection failed'}`, 'error');
    }
  }
}

async function refreshThreats() {
  try {
    const threats = await actor.getThreats();
    renderThreats(threats);
  } catch (error) {
    console.error('Failed to load threats:', error);
    threatTable.innerHTML = '<tr><th>Time</th><th>Severity</th><th>Threat Type</th><th>Payload Snippet</th></tr><tr><td colspan="4">Threat feed unavailable.</td></tr>';
  }
}

async function refreshDashboard(showFeedback = false) {
  if (dashboardRefreshInFlight || document.hidden) return;
  dashboardRefreshInFlight = true;

  try {
    await Promise.all([refreshStats(showFeedback), refreshThreats()]);
  } finally {
    dashboardRefreshInFlight = false;
  }
}

function startLiveRefresh() {
  clearInterval(dashboardRefreshTimer);
  dashboardRefreshTimer = window.setInterval(() => {
    refreshDashboard(false);
  }, 3000);
}

async function setMode(mode) {
  if (modeRequestInFlight) return;
  modeRequestInFlight = true;
  setButtonState(mode);
  setModeButtonsDisabled(true);
  setModeFeedback(`Applying ${mode.toLowerCase()} boundary...`, 'loading');

  try {
    const response = await actor.setMode(mode);
    if (response !== 'Mode updated.') {
      throw new Error(`Unexpected canister response: ${response}`);
    }
    statStatus.textContent = `${mode} boundary`;
    statStatus.className = 'status-ok';
    setModeFeedback(`Firewall ${mode.toLowerCase()} applied`, 'success');

    await Promise.allSettled([refreshStats(false), refreshThreats()]);
  } catch (error) {
    console.error('Failed to update mode:', error);
    statStatus.textContent = 'Sync error';
    statStatus.className = 'status-error';
    setModeFeedback(`Could not apply ${mode.toLowerCase()}: ${error?.message || 'backend rejected the request'}`, 'error');
  } finally {
    modeRequestInFlight = false;
    setModeButtonsDisabled(false);
  }
}

async function handlePromptSubmit(event) {
  event.preventDefault();
  const promptText = promptInput.value.trim();
  if (!promptText) return;

  sendPromptBtn.disabled = true;
  chatStatus.textContent = 'Evaluating boundary...';

  try {
    const result = await actor.processPrompt(promptText);

    chatOutputCard.classList.remove('hidden');
    outputText.textContent = result.response;
    outputReason.textContent = `Reason: ${result.reason}`;
    outputModeTag.textContent = `MODE: ${result.mode.toUpperCase()}`;

    if (result.allowed) {
      outputBadge.textContent = 'CLEARED';
      outputBadge.classList.remove('is-blocked');
    } else {
      outputBadge.textContent = 'BLOCKED';
      outputBadge.classList.add('is-blocked');
    }

    chatStatus.textContent = 'Evaluation complete';
    promptInput.value = '';
    await refreshDashboard(false);
  } catch (error) {
    console.error('Failed to evaluate prompt:', error);
    chatStatus.textContent = 'Error processing prompt';
  } finally {
    sendPromptBtn.disabled = false;
  }
}

function copyPrincipal() {
  navigator.clipboard.writeText('57fkl-hfo3q-4sije-2dfvt-ikhqe-ti54q-ysccf-555lf-zc4bm-nykce-lae');
  alert('Principal copied to clipboard!');
}

function openDevWebsite() {
  window.open('https://2n2uw-uaaaa-aaaag-at2hq-cai.icp.net', '_blank', 'noopener,noreferrer');
}

if (coffeeBtn) {
  coffeeBtn.addEventListener('click', copyPrincipal);
}

if (devWebsiteBtn) {
  devWebsiteBtn.addEventListener('click', openDevWebsite);
}

if (chatForm) {
  chatForm.addEventListener('submit', handlePromptSubmit);
}

modeButtons.forEach((button) => {
  button.addEventListener('click', async () => {
    await setMode(button.dataset.mode);
  });
});

window.copyPrincipal = copyPrincipal;
window.openDevWebsite = openDevWebsite;
updateClock();
window.setInterval(updateClock, 1000);

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) refreshDashboard(false);
});

async function initializeDashboard() {
  await refreshDashboard(true);
  startLiveRefresh();
}

initializeDashboard();
