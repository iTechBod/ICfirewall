import { Actor, HttpAgent } from 'https://esm.sh/@dfinity/agent';
import { AuthClient } from 'https://esm.sh/@dfinity/auth-client';

const isLocalReplica = window.location.hostname.endsWith('.localhost')
  || window.location.hostname === 'localhost'
  || window.location.hostname === '127.0.0.1';

const CANISTER_ID = isLocalReplica
  ? 'YOUR_PRODUCTION_CANISTER_ID_HERE'
  : 'YOUR_PRODUCTION_CANISTER_ID_HERE'; // Replace with your live canister ID or environment config

const HOST = isLocalReplica ? 'http://localhost:4943' : 'https://icp0.io';
const II_URL = isLocalReplica ? 'http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:4943' : 'https://identity.ic0.app';

const OWNER_PID = 'YOUR_MASTER_PRINCIPAL_ID_HERE'; // Replace with your master owner principal ID
const STORAGE_KEY = 'cortex_mesh_chat_history_v1';

const idlFactory = ({ IDL }) => {
  const SystemStats = IDL.Record({
    mode: IDL.Text,
    activeQueueLength: IDL.Nat,
    totalProcessed: IDL.Nat,
    totalBlocked: IDL.Nat,
    masterPid: IDL.Text,
    adminCount: IDL.Nat,
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
    ticketId: IDL.Opt(IDL.Nat),
  });

  const SecurityRulesConfig = IDL.Record({
    blockPromptInjection: IDL.Bool,
    blockDestructiveCommands: IDL.Bool,
    blockPrivilegeEscalation: IDL.Bool,
    maxContextLength: IDL.Nat,
  });

  return IDL.Service({
    getStats: IDL.Func([], [SystemStats], ['query']),
    getThreats: IDL.Func([], [IDL.Vec(ThreatEvent)], ['query']),
    setMode: IDL.Func([IDL.Text], [IDL.Text], []),
    processPrompt: IDL.Func([IDL.Text], [PromptResult], []),
    checkIsAdmin: IDL.Func([IDL.Text], [IDL.Bool], ['query']),
    checkResponse: IDL.Func([IDL.Nat], [IDL.Opt(IDL.Text)], ['query']),
    claimMasterPID: IDL.Func([IDL.Text], [IDL.Text], []),
    getMasterPID: IDL.Func([], [IDL.Text], ['query']),
    getCallerPID: IDL.Func([], [IDL.Text], []),
    getAdmins: IDL.Func([], [IDL.Vec(IDL.Text)], ['query']),
    addAdmin: IDL.Func([IDL.Text], [IDL.Text], []),
    removeAdmin: IDL.Func([IDL.Text], [IDL.Text], []),
    getSecurityRules: IDL.Func([], [SecurityRulesConfig], ['query']),
    updateSecurityRules: IDL.Func([SecurityRulesConfig], [IDL.Text], []),
  });
};

let authClient;
let actor;
let currentPID = null;

async function buildActor(identity) {
  const agent = new HttpAgent({ host: HOST, identity, verifyQuerySignatures: !isLocalReplica });
  if (isLocalReplica) {
    try { await agent.fetchRootKey(); } catch (e) { console.error(e); }
  }
  return Actor.createActor(idlFactory, { agent, canisterId: CANISTER_ID });
}

// UI Elements
const modeButtons = document.querySelectorAll('[data-mode]');
const statProcessed = document.getElementById('stat-processed');
const statBlocked = document.getElementById('stat-blocked');
const statQueue = document.getElementById('stat-queue');
const statStatus = document.getElementById('stat-status');
const threatTbody = document.getElementById('threat-tbody');
const topbarTime = document.getElementById('topbar-time');
const modeFeedback = document.getElementById('mode-feedback');

const adminControlPanel = document.getElementById('admin-control-panel');
const guestControlPanel = document.getElementById('guest-control-panel');
const claimPanel = document.getElementById('claim-panel');
const masterStudioPanel = document.getElementById('master-studio-panel');
const claimMasterBtn = document.getElementById('claim-master-btn');
const userPidDisplay = document.getElementById('userPidDisplay');

const chatForm = document.getElementById('chat-form');
const promptInput = document.getElementById('prompt-input');
const sendPromptBtn = document.getElementById('send-prompt-btn');
const chatStatus = document.getElementById('chat-status');
const chatHistoryContainer = document.getElementById('chat-history-container');
const clearHistoryBtn = document.getElementById('clear-history-btn');

const addAdminForm = document.getElementById('add-admin-form');
const newAdminInput = document.getElementById('new-admin-input');
const adminListContainer = document.getElementById('admin-list-container');
const rulesForm = document.getElementById('rules-form');
const ruleInjection = document.getElementById('rule-injection');
const ruleDestructive = document.getElementById('rule-destructive');
const rulePrivilege = document.getElementById('rule-privilege');
const ruleMaxContext = document.getElementById('rule-max-context');

let modeRequestInFlight = false;
let dashboardRefreshInFlight = false;
let dashboardRefreshTimer;
let activePollInterval = null;

async function initAuth() {
  authClient = await AuthClient.create();
  if (await authClient.isAuthenticated()) {
    await handleAuthenticated(authClient.getIdentity());
  } else {
    actor = await buildActor(authClient.getIdentity());
    if (userPidDisplay) {
      userPidDisplay.textContent = 'Not logged in (Click II Passkey Login above)';
    }
    await evaluatePermissions();
  }
  loadStoredChatHistory();
  await initializeDashboard();
}

async function handleAuthenticated(identity) {
  actor = await buildActor(identity);
  currentPID = identity.getPrincipal().toText();
  
  if (userPidDisplay) {
    userPidDisplay.textContent = currentPID;
  }
  
  const authBtnText = document.getElementById('auth-btn-text');
  if (authBtnText) authBtnText.textContent = 'Logout';
  await evaluatePermissions();
}

async function evaluatePermissions() {
  try {
    const master = await actor.getMasterPID();
    
    if (master === 'Unassigned') {
      if (currentPID === OWNER_PID) {
        claimPanel.style.display = 'block';
      } else {
        claimPanel.style.display = 'none';
      }
      adminControlPanel.style.display = 'none';
      guestControlPanel.style.display = 'none';
      masterStudioPanel.style.display = 'none';
      return;
    } else {
      claimPanel.style.display = 'none';
    }

    let isAdmin = false;
    let isOwner = false;
    if (currentPID) {
      isAdmin = await actor.checkIsAdmin(currentPID);
      isOwner = (master === currentPID);
    }

    if (isAdmin) {
      adminControlPanel.style.display = 'block';
      guestControlPanel.style.display = 'none';
    } else {
      adminControlPanel.style.display = 'none';
      guestControlPanel.style.display = 'block';
    }

    if (isOwner) {
      masterStudioPanel.style.display = 'block';
      await loadAdminList();
      await loadSecurityRules();
    } else {
      masterStudioPanel.style.display = 'none';
    }
  } catch (e) {
    console.error('Permission check failed:', e);
  }
}

claimMasterBtn?.addEventListener('click', async () => {
  if (!currentPID) {
    alert('Please log in with Internet Identity first.');
    return;
  }
  if (currentPID !== OWNER_PID) {
    alert('Unauthorized: Only the designated master owner principal can execute claims.');
    return;
  }
  try {
    const res = await actor.claimMasterPID(currentPID);
    alert(res);
    window.location.reload();
  } catch (e) {
    alert('Claim failed: ' + e.message);
  }
});

async function loadAdminList() {
  try {
    const admins = await actor.getAdmins();
    if (admins.length === 0) {
      adminListContainer.innerHTML = '<small style="color:var(--faint);">No secondary admins added.</small>';
      return;
    }
    adminListContainer.innerHTML = admins.map(pid => `
      <div class="admin-row" style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.05);">
        <span style="font-family:monospace; font-size:11px;">${pid.substring(0, 12)}...${pid.substring(pid.length - 6)}</span>
        <button type="button" class="network-pill interactive-btn" style="padding:2px 8px; font-size:9px; color:var(--coral);" onclick="window.removeAdminPID('${pid}')">Revoke</button>
      </div>
    `).join('');
  } catch (e) {
    console.error('Failed to load admin list:', e);
  }
}

window.removeAdminPID = async function(pid) {
  if (!confirm(`Revoke admin privileges for ${pid}?`)) return;
  try {
    const res = await actor.removeAdmin(pid);
    alert(res);
    await loadAdminList();
  } catch (e) {
    alert('Error: ' + e.message);
  }
};

addAdminForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const pid = newAdminInput.value.trim();
  if (!pid) return;
  try {
    const res = await actor.addAdmin(pid);
    alert(res);
    newAdminInput.value = '';
    await loadAdminList();
  } catch (e) {
    alert('Error: ' + e.message);
  }
});

async function loadSecurityRules() {
  try {
    const rules = await actor.getSecurityRules();
    ruleInjection.checked = rules.blockPromptInjection;
    ruleDestructive.checked = rules.blockDestructiveCommands;
    rulePrivilege.checked = rules.blockPrivilegeEscalation;
    ruleMaxContext.value = Number(rules.maxContextLength);
  } catch (e) {
    console.error('Failed to load rules:', e);
  }
}

rulesForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const newConfig = {
    blockPromptInjection: ruleInjection.checked,
    blockDestructiveCommands: ruleDestructive.checked,
    blockPrivilegeEscalation: rulePrivilege.checked,
    maxContextLength: BigInt(ruleMaxContext.value || 12000),
  };
  try {
    const res = await actor.updateSecurityRules(newConfig);
    alert(res);
  } catch (e) {
    alert('Failed to update rules: ' + e.message);
  }
});

document.getElementById('auth-btn')?.addEventListener('click', async () => {
  if (await authClient.isAuthenticated()) {
    await authClient.logout();
    window.location.reload();
  } else {
    authClient.login({
      identityProvider: II_URL,
      onSuccess: () => handleAuthenticated(authClient.getIdentity()),
    });
  }
});

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
  topbarTime.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

function setButtonState(mode) {
  const normalized = mode.split(' ')[0].toLowerCase();
  const buttonModeMap = { off: 'Off', medium: 'Medium', on: 'On' };
  modeButtons.forEach((button) => {
    button.classList.toggle('active', button.dataset.mode === buttonModeMap[normalized]);
  });
}

function formatTimestamp(timestamp) {
  const ts = Number(timestamp) / 1_000_000;
  const date = new Date(ts);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
}

function renderThreats(threats) {
  if (!threatTbody) return;
  if (!threats || threats.length === 0) {
    threatTbody.innerHTML = '<tr><td colspan="4" class="empty-state">No threats recorded.</td></tr>';
    return;
  }
  threatTbody.innerHTML = threats.map((event) => `
    <tr>
      <td>${formatTimestamp(event.timestamp)}</td>
      <td>${event.severity}</td>
      <td>${event.threatType}</td>
      <td>${event.snippet}</td>
    </tr>
  `).join('');
}

async function refreshStats(showFeedback = true) {
  try {
    const stats = await actor.getStats();
    if (statProcessed) statProcessed.textContent = String(stats.totalProcessed);
    if (statBlocked) statBlocked.textContent = String(stats.totalBlocked);
    if (statQueue) statQueue.textContent = String(stats.activeQueueLength);
    if (statStatus) {
      statStatus.textContent = stats.mode;
      statStatus.className = 'status-ok';
    }
    setButtonState(stats.mode.replace(/ .*$/, '').trim());
    if (showFeedback) setModeFeedback(`Firewall ${stats.mode.split(' ')[0].toLowerCase()} and synced`, 'success');
  } catch (error) {
    if (statStatus) { statStatus.textContent = 'Offline'; statStatus.className = 'status-error'; }
    if (showFeedback) setModeFeedback(`Backend unavailable: ${error?.message || 'connection failed'}`, 'error');
  }
}

async function refreshThreats() {
  try {
    const threats = await actor.getThreats();
    renderThreats(threats);
  } catch (error) {
    if (threatTbody) threatTbody.innerHTML = '<tr><td colspan="4" class="empty-state">Threat feed unavailable.</td></tr>';
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
  dashboardRefreshTimer = window.setInterval(() => refreshDashboard(false), 5000);
}

async function setMode(mode) {
  if (modeRequestInFlight) return;
  modeRequestInFlight = true;
  setButtonState(mode);
  setModeButtonsDisabled(true);
  setModeFeedback(`Applying ${mode.toLowerCase()} boundary...`, 'loading');

  try {
    const response = await actor.setMode(mode);
    if (response !== 'Mode updated.') throw new Error(response);
    if (statStatus) { statStatus.textContent = `${mode} boundary`; statStatus.className = 'status-ok'; }
    setModeFeedback(`Firewall ${mode.toLowerCase()} applied`, 'success');
    await Promise.allSettled([refreshStats(false), refreshThreats()]);
  } catch (error) {
    setModeFeedback(`Could not apply ${mode.toLowerCase()}: ${error?.message || 'unauthorized'}`, 'error');
  } finally {
    modeRequestInFlight = false;
    setModeButtonsDisabled(false);
  }
}

function saveChatHistoryToStorage() {
  if (!chatHistoryContainer) return;
  const items = [];
  chatHistoryContainer.querySelectorAll('.chat-message-bubble').forEach(bubble => {
    items.push({ html: bubble.outerHTML });
  });
  localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
}

function loadStoredChatHistory() {
  if (!chatHistoryContainer) return;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const items = JSON.parse(raw);
    if (items && items.length > 0) {
      const emptyState = document.getElementById('chat-history-empty');
      if (emptyState) emptyState.remove();
      chatHistoryContainer.innerHTML = items.map(i => i.html).join('');
      chatHistoryContainer.scrollTop = chatHistoryContainer.scrollHeight;
    }
  } catch (e) {
    console.error('Failed to load chat cache:', e);
  }
}

function appendMessageToHistory(role, text, mode, isBlocked, reason) {
  const emptyState = document.getElementById('chat-history-empty');
  if (emptyState) emptyState.remove();

  const bubble = document.createElement('div');
  bubble.className = `chat-message-bubble ${role === 'user' ? 'user-msg' : 'ai-msg'}`;
  const timestamp = new Date().toLocaleTimeString();

  if (role === 'user') {
    bubble.innerHTML = `
      <div class="chat-msg-header"><span>USER PROMPT</span><span>${timestamp}</span></div>
      <p class="chat-msg-body">${escapeHtml(text)}</p>
    `;
  } else {
    const badgeColor = isBlocked ? 'var(--coral)' : '#79e4a5';
    bubble.innerHTML = `
      <div class="chat-msg-header">
        <span style="color:${badgeColor}">${isBlocked ? 'BLOCKED' : 'ALLOWED'} (${mode})</span>
        <span>${timestamp}</span>
      </div>
      <p class="chat-msg-body">${escapeHtml(text)}</p>
      ${reason ? `<small style="color:var(--faint); font-family:'DM Mono',monospace; font-size:10px; display:block; margin-top:6px;">Reason: ${escapeHtml(reason)}</small>` : ''}
    `;
  }

  chatHistoryContainer.appendChild(bubble);
  chatHistoryContainer.scrollTop = chatHistoryContainer.scrollHeight;
  saveChatHistoryToStorage();
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

clearHistoryBtn?.addEventListener('click', () => {
  localStorage.removeItem(STORAGE_KEY);
  chatHistoryContainer.innerHTML = `
    <div class="chat-history-empty" id="chat-history-empty">
      <p style="color:var(--faint); font-family:'DM Mono',monospace; font-size:12px; text-align:center; padding:24px 0;">No active prompts in session memory. Enter a prompt below to begin evaluation stream.</p>
    </div>
  `;
});

async function pollForAIResponse(ticketId, mode) {
  appendMessageToHistory('ai', 'Awaiting response from daemon agent...', mode, false, 'Queued on canister bridge');
  
  const bubbles = chatHistoryContainer.querySelectorAll('.ai-msg');
  const targetBubbleBody = bubbles[bubbles.length - 1].querySelector('.chat-msg-body');

  if (activePollInterval) clearInterval(activePollInterval);

  let attempts = 0;
  activePollInterval = setInterval(async () => {
    attempts++;
    try {
      const responseOpt = await actor.checkResponse(ticketId);
      if (responseOpt && responseOpt.length > 0) {
        clearInterval(activePollInterval);
        activePollInterval = null;
        if (targetBubbleBody) targetBubbleBody.innerText = responseOpt[0];
        if (chatStatus) chatStatus.textContent = 'Response received';
        saveChatHistoryToStorage();
      } else if (attempts > 30) {
        clearInterval(activePollInterval);
        activePollInterval = null;
        if (targetBubbleBody) targetBubbleBody.innerText = 'Timeout waiting for daemon response.';
        if (chatStatus) chatStatus.textContent = 'Polling timeout';
        saveChatHistoryToStorage();
      }
    } catch (err) {
      console.error('Polling error:', err);
    }
  }, 1500);
}

async function handlePromptSubmit(event) {
  event.preventDefault();
  const promptText = promptInput.value.trim();
  if (!promptText) return;

  sendPromptBtn.disabled = true;
  chatStatus.textContent = 'Transmitting prompt...';

  appendMessageToHistory('user', promptText);
  promptInput.value = '';

  try {
    const result = await actor.processPrompt(promptText);
    
    if (result.allowed) {
      chatStatus.textContent = 'Prompt queued for evaluation';
      if (result.ticketId && result.ticketId.length > 0) {
        pollForAIResponse(result.ticketId[0], result.mode.toUpperCase());
      } else {
        appendMessageToHistory('ai', result.response, result.mode.toUpperCase(), false, result.reason);
        chatStatus.textContent = 'Ready';
      }
    } else {
      appendMessageToHistory('ai', result.response, result.mode.toUpperCase(), true, result.reason);
      chatStatus.textContent = 'Evaluation complete (Blocked)';
    }

    await refreshDashboard(false);
  } catch (error) {
    chatStatus.textContent = `Error: ${error?.message || error}`;
    appendMessageToHistory('ai', 'Failed to process prompt through canister.', 'ERROR', true, error?.message);
  } finally {
    sendPromptBtn.disabled = false;
  }
}

function copyPrincipal() {
  navigator.clipboard.writeText('YOUR_MASTER_PRINCIPAL_ID_HERE');
  alert('Principal copied to clipboard!');
}

function openDevWebsite() {
  window.open('https://your-developer-hub.icp0.io', '_blank', 'noopener,noreferrer');
}

document.getElementById('coffee-btn')?.addEventListener('click', copyPrincipal);
document.getElementById('dev-website-btn')?.addEventListener('click', openDevWebsite);
chatForm?.addEventListener('submit', handlePromptSubmit);

modeButtons.forEach((button) => {
  button.addEventListener('click', async () => {
    await setMode(button.dataset.mode);
  });
});

updateClock();
window.setInterval(updateClock, 1000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshDashboard(false); });

async function initializeDashboard() {
  await refreshDashboard(true);
  startLiveRefresh();
}

initAuth();
