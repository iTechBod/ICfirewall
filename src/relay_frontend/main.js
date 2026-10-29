import { Actor, HttpAgent } from 'https://esm.sh/@dfinity/agent';
import { AuthClient } from 'https://esm.sh/@dfinity/auth-client';

const isLocalReplica =
  window.location.hostname.endsWith('.localhost') ||
  window.location.hostname === 'localhost' ||
  window.location.hostname === '127.0.0.1';

const CANISTER_ID = window.ICF_CANISTER_ID || '';
const HOST = isLocalReplica ? 'http://localhost:4943' : 'https://icp0.io';
const II_URL = isLocalReplica
  ? 'http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:4943'
  : 'https://identity.internetcomputer.org';

const STORAGE_KEY = 'icfirewall_chat_history_v1';

// --- Web Crypto E2EE Helper Layer ---
async function getOrCreateSessionKey() {
  let rawKey = sessionStorage.getItem('icfirewall_e2ee_key');
  let cryptoKey;
  if (!rawKey) {
    cryptoKey = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const exported = await window.crypto.subtle.exportKey('raw', cryptoKey);
    sessionStorage.setItem('icfirewall_e2ee_key', Array.from(new Uint8Array(exported)).join(','));
  } else {
    const keyBytes = new Uint8Array(rawKey.split(',').map(Number));
    cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }
  return cryptoKey;
}

async function encryptPayload(text) {
  try {
    const key = await getOrCreateSessionKey();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(text);
    const cipherBuffer = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    
    const combined = new Uint8Array(iv.byteLength + cipherBuffer.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(cipherBuffer), iv.byteLength);
    return btoa(String.fromCharCode(...combined));
  } catch (e) {
    console.error('Encryption fallback to plaintext:', e);
    return text;
  }
}

async function decryptPayload(cipherBase64) {
  try {
    const key = await getOrCreateSessionKey();
    const rawData = Uint8Array.from(atob(cipherBase64), c => c.charCodeAt(0));
    const iv = rawData.slice(0, 12);
    const data = rawData.slice(12);
    const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    return cipherBase64;
  }
}

const idlFactory = ({ IDL }) => {
  const SystemStats = IDL.Record({
    mode: IDL.Text,
    activeQueueLength: IDL.Nat,
    totalProcessed: IDL.Nat,
    totalBlocked: IDL.Nat,
    masterPid: IDL.Text,
    daemonPid: IDL.Text,
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
    getDaemonPID: IDL.Func([], [IDL.Text], ['query']),
    setDaemonPrincipal: IDL.Func([IDL.Text], [IDL.Text], []),
    getAdmins: IDL.Func([], [IDL.Vec(IDL.Text)], ['query']),
    addAdmin: IDL.Func([IDL.Text], [IDL.Text], []),
    removeAdmin: IDL.Func([IDL.Text], [IDL.Text], []),
    getSecurityRules: IDL.Func([], [SecurityRulesConfig], ['query']),
    updateSecurityRules: IDL.Func([SecurityRulesConfig], [IDL.Text], []),
    getVetKeyPublicKey: IDL.Func([], [IDL.Vec(IDL.Nat8)], []),
  });
};

let authClient = null;
let actor;
let currentPID = null;
const activePollIntervals = {};
let dashboardRefreshInFlight = false;
let dashboardRefreshTimer = null;
let modeRequestInFlight = false;

async function buildActor(identity) {
  const agent = new HttpAgent({
    host: HOST,
    identity,
    verifyQuerySignatures: !isLocalReplica,
  });
  if (isLocalReplica) {
    try {
      await agent.fetchRootKey();
    } catch (e) {
      console.error(e);
    }
  }
  return Actor.createActor(idlFactory, { agent, canisterId: CANISTER_ID });
}

// DOM Elements
const authBtn = document.getElementById('auth-btn');
const authBtnText = document.getElementById('auth-btn-text');
const topbarTime = document.getElementById('topbar-time');
const coffeeBtn = document.getElementById('coffee-btn');
const devWebsiteBtn = document.getElementById('dev-website-btn');
const claimPanel = document.getElementById('claim-panel');
const claimMasterBtn = document.getElementById('claim-master-btn');
const adminControlPanel = document.getElementById('admin-control-panel');
const guestControlPanel = document.getElementById('guest-control-panel');
const masterStudioPanel = document.getElementById('master-studio-panel');
const addAdminForm = document.getElementById('add-admin-form');
const newAdminInput = document.getElementById('new-admin-input');
const adminListContainer = document.getElementById('admin-list-container');
const rulesForm = document.getElementById('rules-form');
const ruleInjection = document.getElementById('rule-injection');
const ruleDestructive = document.getElementById('rule-destructive');
const rulePrivilege = document.getElementById('rule-privilege');
const ruleMaxContext = document.getElementById('rule-max-context');
const userPidDisplay = document.getElementById('userPidDisplay');
const copyPidBtn = document.getElementById('copyPidBtn');
const chatForm = document.getElementById('chat-form');
const promptInput = document.getElementById('prompt-input');
const sendPromptBtn = document.getElementById('send-prompt-btn');
const chatStatus = document.getElementById('chat-status');
const chatHistoryContainer = document.getElementById('chat-history-container');
const clearHistoryBtn = document.getElementById('clear-history-btn');
const statProcessed = document.getElementById('stat-processed');
const statBlocked = document.getElementById('stat-blocked');
const statQueue = document.getElementById('stat-queue');
const statStatus = document.getElementById('stat-status');
const threatTbody = document.getElementById('threat-tbody');
const modeButtons = document.querySelectorAll('[data-mode]');
const modeFeedback = document.getElementById('mode-feedback');
const fetchVetkeyBtn = document.getElementById('fetch-vetkey-btn');
const vetkeyDisplay = document.getElementById('vetkey-display');

function updateClock() {
  if (!topbarTime) return;
  const now = new Date();
  topbarTime.textContent = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
}
setInterval(updateClock, 1000);
updateClock();

coffeeBtn?.addEventListener('click', async () => {
  try {
    const master = await actor.getMasterPID();
    if (!master || master === 'Unassigned') {
      alert('Master principal is currently unassigned.');
      return;
    }
    await navigator.clipboard.writeText(master);
    alert('Master principal copied to clipboard: ' + master);
  } catch (e) {
    alert('Failed to copy master principal: ' + e.message);
  }
});

devWebsiteBtn?.addEventListener('click', () => {
  window.open('https://internetcomputer.org', '_blank');
});

copyPidBtn?.addEventListener('click', async () => {
  const text = userPidDisplay?.textContent?.trim() || '';
  if (!text || text.startsWith('Not logged') || text === '—') {
    alert('No principal available to copy. Please log in first.');
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    const originalText = copyPidBtn.textContent;
    copyPidBtn.textContent = 'Copied!';
    setTimeout(() => { copyPidBtn.textContent = originalText; }, 1500);
  } catch (e) {
    alert('Failed to copy principal: ' + e.message);
  }
});

fetchVetkeyBtn?.addEventListener('click', async () => {
  if (!actor) {
    alert('Actor not initialized.');
    return;
  }
  try {
    fetchVetkeyBtn.textContent = 'Checking vetKDS support...';
    const pubKeyBytes = await actor.getVetKeyPublicKey();
    const hexKey = Array.from(pubKeyBytes, b => b.toString(16).padStart(2, '0')).join('');
    if (vetkeyDisplay) {
      vetkeyDisplay.textContent = `vetKDS Public Key (Hex): ${hexKey}`;
    }
    fetchVetkeyBtn.textContent = 'Fetch vetKDS Public Key';
  } catch (err) {
    console.error('vetKDS fetch error:', err);
    let errMsg = err.message || String(err);
    if (errMsg.includes('IC0536') || errMsg.includes("no method 'vet_keys_public_key'") || errMsg.includes('Management canister has no method')) {
      errMsg = 'Your subnet does not support vetkeys yet.';
    } else {
      errMsg = `Your subnet does not support vetkeys yet. (${errMsg})`;
    }
    if (vetkeyDisplay) {
      vetkeyDisplay.textContent = errMsg;
    }
    fetchVetkeyBtn.textContent = 'Fetch vetKDS Public Key';
  }
});

function setModeFeedback(message, state = 'success') {
  if (!modeFeedback) return;
  modeFeedback.textContent = message;
  modeFeedback.dataset.state = state;
}

function setModeButtonsDisabled(disabled) {
  modeButtons.forEach((btn) => {
    btn.disabled = disabled;
    btn.classList.toggle('is-loading', disabled);
  });
}

function applyModeVisualTheme(normalizedMode) {
  document.body.classList.remove('mode-off-active', 'mode-medium-active', 'mode-on-active');
  if (normalizedMode === 'off') document.body.classList.add('mode-off-active');
  else if (normalizedMode === 'medium') document.body.classList.add('mode-medium-active');
  else if (normalizedMode === 'on') document.body.classList.add('mode-on-active');
}

async function setMode(mode) {
  if (modeRequestInFlight) return;
  modeRequestInFlight = true;
  setModeButtonsDisabled(true);
  setModeFeedback(`Applying mode ${mode}...`, 'loading');

  try {
    const res = await actor.setMode(mode);
    if (res !== 'Mode updated.') throw new Error(res);
    setModeFeedback(`Mode updated to ${mode}`, 'success');
    applyModeVisualTheme(mode.toLowerCase());
    await refreshDashboard(false);
  } catch (e) {
    setModeFeedback(`Failed to update mode: ${e.message}`, 'error');
  } finally {
    modeRequestInFlight = false;
    setModeButtonsDisabled(false);
  }
}

modeButtons.forEach((button) => {
  button.addEventListener('click', async () => {
    const mode = button.dataset.mode;
    if (mode) await setMode(mode);
  });
});

async function refreshStats(showFeedback = false) {
  try {
    const stats = await actor.getStats();
    if (statProcessed) statProcessed.textContent = String(stats.totalProcessed);
    if (statBlocked) statBlocked.textContent = String(stats.totalBlocked);
    if (statQueue) statQueue.textContent = String(stats.activeQueueLength);
    if (statStatus) {
      statStatus.textContent = stats.mode;
      statStatus.className = 'status-ok';
    }
    
    const normalized = (stats.mode || '').split(' ')[0].toLowerCase();
    const map = { off: 'Off', medium: 'Medium', on: 'On' };
    modeButtons.forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.mode === map[normalized]);
    });
    applyModeVisualTheme(normalized);
  } catch (e) {
    if (statStatus) {
      statStatus.textContent = 'Offline';
      statStatus.className = 'status-error';
    }
    throw e;
  }
}

async function refreshThreats() {
  if (!threatTbody) return;
  try {
    const threats = await actor.getThreats();
    renderThreats(threats);
  } catch (e) {
    console.error('Failed to load threats:', e);
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatTimestamp(timestamp) {
  try {
    const ms = Number(BigInt(timestamp) / 1000000n);
    return new Date(ms).toLocaleString();
  } catch (e) {
    return String(timestamp);
  }
}

function renderThreats(threats) {
  if (!threatTbody) return;
  if (!threats || !threats.length) {
    threatTbody.innerHTML = `<tr><td colspan="4" style="color:var(--faint); text-align:center; padding:16px;">No threats recorded.</td></tr>`;
    return;
  }
  threatTbody.innerHTML = threats
    .map(
      (t) => `
    <tr>
      <td>${escapeHtml(formatTimestamp(t.timestamp))}</td>
      <td><span style="color:var(--coral);">${escapeHtml(t.severity)}</span></td>
      <td>${escapeHtml(t.threatType)}</td>
      <td style="font-family:'DM Mono',monospace;">${escapeHtml(t.snippet)}</td>
    </tr>`
    )
    .join('');
}

async function refreshDashboard(showFeedback = false) {
  if (dashboardRefreshInFlight || document.hidden) return;
  dashboardRefreshInFlight = true;
  try {
    await Promise.all([refreshStats(showFeedback), refreshThreats()]);
  } catch (e) {
    console.error('Dashboard refresh error:', e);
  } finally {
    dashboardRefreshInFlight = false;
  }
}

function startLiveRefresh() {
  if (dashboardRefreshTimer) clearInterval(dashboardRefreshTimer);
  dashboardRefreshTimer = setInterval(() => { refreshDashboard(false); }, 5000);
}

async function initializeDashboard() {
  await refreshDashboard(true);
  startLiveRefresh();
}

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) refreshDashboard(false);
});

async function loadSecurityRules() {
  try {
    const config = await actor.getSecurityRules();
    if (ruleInjection) ruleInjection.checked = config.blockPromptInjection;
    if (ruleDestructive) ruleDestructive.checked = config.blockDestructiveCommands;
    if (rulePrivilege) rulePrivilege.checked = config.blockPrivilegeEscalation;
    if (ruleMaxContext) ruleMaxContext.value = Number(config.maxContextLength);
  } catch (e) {
    console.error('Failed to load security rules:', e);
  }
}

rulesForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const newConfig = {
      blockPromptInjection: ruleInjection?.checked ?? true,
      blockDestructiveCommands: ruleDestructive?.checked ?? true,
      blockPrivilegeEscalation: rulePrivilege?.checked ?? true,
      maxContextLength: BigInt(ruleMaxContext?.value || 12000),
    };
    const res = await actor.updateSecurityRules(newConfig);
    alert(res);
  } catch (err) {
    alert('Failed to save rules: ' + err.message);
  }
});

async function loadAdminList() {
  try {
    const admins = await actor.getAdmins();
    if (!adminListContainer) return;
    if (!admins.length) {
      adminListContainer.innerHTML = 'No secondary admins.';
      return;
    }
    adminListContainer.innerHTML = admins
      .map(
        (pid) => `
      <div style="display:flex; justify-content:space-between; align-items:center; padding:4px 0; font-family:'DM Mono',monospace; font-size:11px;">
        <span>${escapeHtml(pid.slice(0, 10))}…${escapeHtml(pid.slice(-6))}</span>
        <button class="network-pill interactive-btn" style="padding:2px 6px; font-size:8px;" onclick="window.removeAdminPID('${pid}')">Revoke</button>
      </div>`
      )
      .join('');
  } catch (e) {
    console.error(e);
  }
}

window.removeAdminPID = async (pid) => {
  if (!confirm(`Revoke admin ${pid}?`)) return;
  try {
    const res = await actor.removeAdmin(pid);
    alert(res);
    await loadAdminList();
  } catch (e) {
    alert('Failed to revoke admin: ' + e.message);
  }
};

addAdminForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const pid = newAdminInput?.value?.trim();
  if (!pid) return;
  try {
    const res = await actor.addAdmin(pid);
    alert(res);
    if (newAdminInput) newAdminInput.value = '';
    await loadAdminList();
  } catch (e) {
    alert('Failed to add admin: ' + e.message);
  }
});

async function evaluatePermissions() {
  try {
    const master = await actor.getMasterPID();
    if (master === 'Unassigned') {
      if (claimPanel) claimPanel.style.display = 'block';
      if (adminControlPanel) adminControlPanel.style.display = 'none';
      if (masterStudioPanel) masterStudioPanel.style.display = 'none';
      if (guestControlPanel) guestControlPanel.style.display = 'none';
      return;
    }
    if (claimPanel) claimPanel.style.display = 'none';

    let isAdmin = false;
    let isOwner = false;
    if (currentPID) {
      isAdmin = await actor.checkIsAdmin(currentPID);
      isOwner = isAdmin || (master === currentPID);
    }

    if (adminControlPanel) adminControlPanel.style.display = (isAdmin || isOwner) ? 'block' : 'none';
    if (masterStudioPanel) masterStudioPanel.style.display = isOwner ? 'block' : 'none';
    if (guestControlPanel) guestControlPanel.style.display = (!isAdmin && !isOwner) ? 'block' : 'none';

    if (isOwner) {
      await loadAdminList();
      await loadSecurityRules();
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
  try {
    const res = await actor.claimMasterPID(currentPID);
    alert(res);
    window.location.reload();
  } catch (e) {
    alert('Claim failed: ' + e.message);
  }
});

function appendMessageToHistory(role, text, mode = '', isBlocked = false, reason = '') {
  document.getElementById('chat-history-empty')?.remove();
  const bubble = document.createElement('div');
  bubble.className = `chat-message-bubble ${role === 'user' ? 'user-msg' : 'ai-msg'}`;
  const ts = new Date().toLocaleTimeString();
  if (role === 'user') {
    bubble.innerHTML = `<div class="chat-msg-header"><span>USER</span><span>${ts}</span></div><p class="chat-msg-body">${escapeHtml(text)}</p>`;
  } else {
    bubble.innerHTML = `<div class="chat-msg-header"><span style="color:${isBlocked ? 'var(--coral)' : '#79e4a5'}">${isBlocked ? 'BLOCKED' : 'ALLOWED'} (${escapeHtml(mode)})</span><span>${ts}</span></div><p class="chat-msg-body">${escapeHtml(text)}</p>${reason ? `<div style="margin-top:4px; font-size:10px; color:var(--faint);">Reason: ${escapeHtml(reason)}</div>` : ''}`;
  }
  if (chatHistoryContainer) {
    chatHistoryContainer.appendChild(bubble);
    chatHistoryContainer.scrollTop = chatHistoryContainer.scrollHeight;
  }
  saveChatHistoryToStorage();
}

function saveChatHistoryToStorage() {
  if (!chatHistoryContainer) return;
  const items = [];
  chatHistoryContainer.querySelectorAll('.chat-message-bubble').forEach((b) => { items.push({ html: b.outerHTML }); });
  localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
}

function loadStoredChatHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const items = JSON.parse(raw);
    if (items?.length && chatHistoryContainer) {
      document.getElementById('chat-history-empty')?.remove();
      chatHistoryContainer.innerHTML = items.map((i) => i.html).join('');
    }
  } catch (e) {
    console.error(e);
  }
}

clearHistoryBtn?.addEventListener('click', () => {
  localStorage.removeItem(STORAGE_KEY);
  if (chatHistoryContainer) {
    chatHistoryContainer.innerHTML = `<div class="chat-history-empty" id="chat-history-empty"><p style="color:var(--faint); font-family:'DM Mono', monospace; font-size:12px; text-align:center; padding:24px 0;">History cleared.</p></div>`;
  }
});

function pollForAIResponse(ticketId, mode) {
  appendMessageToHistory('ai', 'Awaiting response from daemon agent...', mode, false, 'Queued on canister bridge');
  const bubbles = chatHistoryContainer?.querySelectorAll('.ai-msg');
  const targetBubbleBody = bubbles?.[bubbles.length - 1]?.querySelector('.chat-msg-body');

  if (activePollIntervals[ticketId]) clearInterval(activePollIntervals[ticketId]);

  let attempts = 0;
  activePollIntervals[ticketId] = setInterval(async () => {
    attempts++;
    try {
      const responseOpt = await actor.checkResponse(ticketId);
      if (responseOpt && responseOpt.length > 0) {
        clearInterval(activePollIntervals[ticketId]);
        delete activePollIntervals[ticketId];
        const decryptedResponse = await decryptPayload(responseOpt[0]);
        if (targetBubbleBody) targetBubbleBody.innerText = decryptedResponse;
        if (chatStatus) chatStatus.textContent = 'Response received';
        saveChatHistoryToStorage();
      } else if (attempts > 40) {
        clearInterval(activePollIntervals[ticketId]);
        delete activePollIntervals[ticketId];
        if (targetBubbleBody) targetBubbleBody.innerText = 'Timeout waiting for daemon response.';
        if (chatStatus) chatStatus.textContent = 'Polling timeout';
        saveChatHistoryToStorage();
      }
    } catch (err) {
      console.error('Polling error:', err);
    }
  }, 1500);
}

chatForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = promptInput?.value?.trim();
  if (!text) return;

  if (sendPromptBtn) sendPromptBtn.disabled = true;
  if (chatStatus) chatStatus.textContent = 'Encrypting & Transmitting...';
  appendMessageToHistory('user', text);
  if (promptInput) promptInput.value = '';

  try {
    const encryptedText = await encryptPayload(text);
    const result = await actor.processPrompt(encryptedText);
    if (result.allowed) {
      if (result.ticketId && result.ticketId.length > 0) {
        if (chatStatus) chatStatus.textContent = 'Queued for daemon';
        pollForAIResponse(result.ticketId[0], result.mode);
      } else {
        const decryptedResponse = await decryptPayload(result.response);
        appendMessageToHistory('ai', decryptedResponse, result.mode, false, result.reason);
        if (chatStatus) chatStatus.textContent = 'Processed';
      }
    } else {
      appendMessageToHistory('ai', result.response, result.mode, true, result.reason);
      if (chatStatus) chatStatus.textContent = 'Blocked';
    }
    await refreshDashboard(false);
  } catch (err) {
    if (chatStatus) chatStatus.textContent = 'Error';
    appendMessageToHistory('ai', 'Failed to process prompt.', 'ERROR', true, err.message);
  } finally {
    if (sendPromptBtn) sendPromptBtn.disabled = false;
  }
});

async function handleAuthenticated(identity) {
  actor = await buildActor(identity);
  currentPID = identity.getPrincipal().toText();
  if (userPidDisplay) userPidDisplay.textContent = currentPID;
  if (authBtnText) authBtnText.textContent = 'Logout';
  await evaluatePermissions();
}

authBtn?.addEventListener('click', async () => {
  if (!authClient) {
    alert('Authentication client is still loading. Please try again.');
    return;
  }
  if (await authClient.isAuthenticated()) {
    await authClient.logout();
    window.location.reload();
  } else {
    authClient.login({
      identityProvider: II_URL,
      windowOpenerFeatures: 'width=500,height=600,left=200,top=100,toolbar=0,location=0,menubar=0',
      onSuccess: () => handleAuthenticated(authClient.getIdentity()),
      onError: (err) => console.error('Internet Identity login error:', err),
    });
  }
});

async function initAuth() {
  if (!CANISTER_ID) {
    console.error("Critical Error: CANISTER_ID is not configured.");
    if (sendPromptBtn) sendPromptBtn.disabled = true;
    if (chatStatus) chatStatus.textContent = 'Config Error: Missing Canister ID';
    return;
  }

  try {
    authClient = await AuthClient.create();
    if (await authClient.isAuthenticated()) {
      await handleAuthenticated(authClient.getIdentity());
    } else {
      actor = await buildActor(authClient.getIdentity());
      if (userPidDisplay) userPidDisplay.textContent = 'Not logged in';
      await evaluatePermissions();
    }
  } catch (err) {
    console.error("Auth initialization failed:", err);
    actor = await buildActor(null);
    if (userPidDisplay) userPidDisplay.textContent = 'Offline / Unauthenticated';
    await evaluatePermissions();
  }

  loadStoredChatHistory();
  await initializeDashboard();
}

initAuth();
