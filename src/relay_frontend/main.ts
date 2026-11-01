import { Actor, HttpAgent } from '@dfinity/agent';
import { AuthClient } from '@dfinity/auth-client';
import { TransportSecretKey, encryptPrompt, decryptResult, b64ToBytes } from './crypto';

console.log("🔥 main.ts module evaluation started...");

const isLocalReplica =
  window.location.hostname.endsWith('.localhost') ||
  window.location.hostname === 'localhost' ||
  window.location.hostname === '127.0.0.1';

const CANISTER_ID = 'v7c4r-xqaaa-aaaam-ad2ga-cai';
const HOST = isLocalReplica ? 'http://localhost:4943' : 'https://icp0.io';
const II_URL = isLocalReplica
  ? 'http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:4943'
  : 'https://identity.internetcomputer.org';

const STORAGE_KEY = 'icfirewall_chat_history_v2';
const idlFactory = ({ IDL }: { IDL: any }) => {
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
    getTicketStatus: IDL.Func([IDL.Nat], [IDL.Opt(IDL.Text)], ['query']),
    getRole: IDL.Func([], [IDL.Text], ['query']),
    isMasterClaimed: IDL.Func([], [IDL.Bool], ['query']),
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
    reservePrivateTicket: IDL.Func([], [IDL.Nat], []),
    deriveResultKey: IDL.Func([IDL.Nat, IDL.Vec(IDL.Nat8)], [IDL.Vec(IDL.Nat8)], []),
    submitPrivate: IDL.Func([IDL.Nat, IDL.Vec(IDL.Nat8)], [PromptResult], []),
  });
};

let globalAuthClient: AuthClient | null = null;
let actor: any;
let currentPID: string | null = null;
const activePollIntervals: Record<string, any> = {};
let cachedPublicKey: Uint8Array | null = null;
let onOwnerPanels: (() => Promise<void>) | null = null; // set once the DOM handlers exist
let dashboardRefreshInFlight = false;
let dashboardRefreshTimer: any = null;
let modeRequestInFlight = false;
let cachedThreats: any[] = [];

async function buildActor(identity: any) {
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

declare global {
  interface Window {
    authClient?: AuthClient;
  }
}

async function handleAuthenticated(identity: any) {
  actor = await buildActor(identity);
  currentPID = identity.getPrincipal().toText();

  console.log("==========================================");
  console.log("🔑 YOUR AUTHENTICATED PRINCIPAL ID:");
  console.log(currentPID);
  console.log("==========================================");

  const userPidDisplay = document.getElementById('userPidDisplay');
  const authBtnText = document.getElementById('auth-btn-text');
  if (userPidDisplay) {
    userPidDisplay.textContent = currentPID;
    userPidDisplay.style.maxWidth = 'none';
    userPidDisplay.style.userSelect = 'all';
  }
  if (authBtnText) authBtnText.textContent = 'Logout';
  await evaluatePermissions();
}

async function evaluatePermissions() {
  if (!actor) return;
  try {
    const [role, claimed] = await Promise.all([actor.getRole(), actor.isMasterClaimed()]);
    const isOwner = role === 'master';
    const isAdmin = role === 'admin' || isOwner;
    const show = (id: string, on: boolean) => {
      const el = document.getElementById(id);
      if (el) el.style.display = on ? 'block' : 'none';
    };
    show('admin-control-panel', isAdmin);
    show('master-studio-panel', isOwner);
    show('guest-control-panel', !isAdmin);
    // claim is only offered to a logged-in principal that a controller has already proposed
    show('claim-panel', !claimed && !!currentPID);
    if (isOwner && onOwnerPanels) await onOwnerPanels();
  } catch (e) {
    console.error('Permission check failed:', e);
  }
}

// Pre-initialize the auth client so the click handler never has to await before opening the popup.
let isAuthed = false;
AuthClient.create().then(async (client) => {
  globalAuthClient = client;
  window.authClient = client; // Expose globally for Safari console access

  isAuthed = await client.isAuthenticated();
  if (isAuthed) {
    await handleAuthenticated(client.getIdentity());
  } else {
    actor = await buildActor(client.getIdentity());
    const userPidDisplay = document.getElementById('userPidDisplay');
    if (userPidDisplay) userPidDisplay.textContent = 'Not logged in';
    await evaluatePermissions();
  }
}).catch((err) => {
  console.error('AuthClient pre-init failed:', err);
});

document.addEventListener('DOMContentLoaded', async () => {
  console.log("🚀 ICfirewall DOMContentLoaded Fired Successfully!");

  const authBtn = document.getElementById('auth-btn');
  const authBtnText = document.getElementById('auth-btn-text');
  const claimMasterBtn = document.getElementById('claim-master-btn');
  const authDaemonBtn = document.getElementById('auth-daemon-btn');
  const addAdminForm = document.getElementById('add-admin-form');
  const newAdminInput = document.getElementById('new-admin-input') as HTMLInputElement;
  const adminListContainer = document.getElementById('admin-list-container');
  const rulesForm = document.getElementById('rules-form');
  const ruleInjection = document.getElementById('rule-injection') as HTMLInputElement;
  const ruleDestructive = document.getElementById('rule-destructive') as HTMLInputElement;
  const rulePrivilege = document.getElementById('rule-privilege') as HTMLInputElement;
  const ruleMaxContext = document.getElementById('rule-max-context') as HTMLInputElement;
  const userPidDisplay = document.getElementById('userPidDisplay');
  const chatForm = document.getElementById('chat-form');
  const promptInput = document.getElementById('prompt-input') as HTMLTextAreaElement;
  const privateToggle = document.getElementById('private-toggle') as HTMLInputElement;
  const sendPromptBtn = document.getElementById('send-prompt-btn') as HTMLButtonElement;
  const chatStatus = document.getElementById('chat-status');
  const chatHistoryContainer = document.getElementById('chat-history-container');
  const clearHistoryBtn = document.getElementById('clear-history-btn');
  const statProcessed = document.getElementById('stat-processed');
  const statBlocked = document.getElementById('stat-blocked');
  const statQueue = document.getElementById('stat-queue');
  const statStatus = document.getElementById('stat-status');
  const threatTbody = document.getElementById('threat-tbody');
  const exportTelemetryBtn = document.getElementById('export-telemetry-btn');
  const modeButtons = document.querySelectorAll('[data-mode]');
  const modeFeedback = document.getElementById('mode-feedback');
  const fetchVetkeyBtn = document.getElementById('fetch-vetkey-btn') as HTMLButtonElement;
  const vetkeyDisplay = document.getElementById('vetkey-display');

  // II login. client.login() is called synchronously inside the click, so the popup keeps its user activation.
  authBtn?.addEventListener('click', () => {
    const client = globalAuthClient;
    if (!client) {
      if (authBtnText) authBtnText.textContent = 'Loading... click again';
      return;
    }
    if (isAuthed) {
      client.logout().then(() => window.location.reload());
      return;
    }
    if (authBtnText) authBtnText.textContent = 'Connecting...';
    client.login({
      identityProvider: II_URL,
      maxTimeToLive: BigInt(8) * BigInt(3_600_000_000_000), // 8 hours, in nanoseconds
      windowOpenerFeatures: 'toolbar=0,location=0,menubar=0,width=500,height=600,left=100,top=100',
      onSuccess: async () => {
        try {
          isAuthed = true;
          await handleAuthenticated(client.getIdentity());
        } catch (err: any) {
          console.error('post-login setup failed', err);
          if (authBtnText) authBtnText.textContent = 'II Passkey Login';
        }
      },
      onError: (err) => {
        console.error('II login failed', err);
        if (authBtnText) authBtnText.textContent = 'II Passkey Login';
        if (userPidDisplay) userPidDisplay.textContent = 'Login cancelled or failed. Try again.';
      },
    });
  });

  authDaemonBtn?.addEventListener('click', async () => {
    if (!actor) {
      alert('Actor not initialized.');
      return;
    }
    try {
      const daemonPid = "vq74b-k5mg5-efcaf-2l2nb-2xn7b-avcq7-tx4zd-7ercn-geedz-mxmsp-mqe";
      authDaemonBtn.textContent = 'Authorizing...';
      const res = await actor.setDaemonPrincipal(daemonPid);
      alert('Success! ' + res);
      authDaemonBtn.textContent = 'Authorize icf-daemon Now';
    } catch (err: any) {
      console.error('Daemon authorization error:', err);
      alert('Failed to authorize daemon: ' + (err.message || err));
      authDaemonBtn.textContent = 'Authorize icf-daemon Now';
    }
  });

  fetchVetkeyBtn?.addEventListener('click', async () => {
    if (!actor) {
      alert('Actor not initialized.');
      return;
    }
    try {
      fetchVetkeyBtn.textContent = 'Fetching vetKDS Public Key...';
      const pubKeyBytes = await actor.getVetKeyPublicKey();
      const hexKey = Array.from(pubKeyBytes, (b: number) => b.toString(16).padStart(2, '0')).join('');
      if (vetkeyDisplay) {
        vetkeyDisplay.textContent = `vetKDS Public Key (Hex): ${hexKey}`;
      }
      fetchVetkeyBtn.textContent = 'Fetch vetKDS Public Key';
    } catch (err: any) {
      console.error('vetKDS fetch error:', err);
      let errMsg = err.message || String(err);
      if (errMsg.includes('IC0536')) {
        errMsg = 'This subnet does not offer vetKD.';
      } else {
        errMsg = `vetKDS Unavailable: ${errMsg}`;
      }
      if (vetkeyDisplay) {
        vetkeyDisplay.textContent = errMsg;
      }
      fetchVetkeyBtn.textContent = 'Fetch vetKDS Public Key';
    }
  });

  function setModeFeedback(message: string, state = 'success') {
    if (!modeFeedback) return;
    modeFeedback.textContent = message;
    modeFeedback.setAttribute('data-state', state);
  }

  function setModeButtonsDisabled(disabled: boolean) {
    modeButtons.forEach((btn: any) => {
      btn.disabled = disabled;
      btn.classList.toggle('is-loading', disabled);
    });
  }

  function applyModeVisualTheme(normalizedMode: string) {
    document.body.classList.remove('mode-off-active', 'mode-medium-active', 'mode-on-active');
    if (normalizedMode === 'off') document.body.classList.add('mode-off-active');
    else if (normalizedMode === 'medium') document.body.classList.add('mode-medium-active');
    else if (normalizedMode === 'on') document.body.classList.add('mode-on-active');
  }

  async function setMode(mode: string) {
    if (modeRequestInFlight || !actor) return;
    modeRequestInFlight = true;
    setModeButtonsDisabled(true);
    setModeFeedback(`Applying mode ${mode}...`, 'loading');

    try {
      const res = await actor.setMode(mode);
      if (res !== 'Mode updated.') throw new Error(res);
      setModeFeedback(`Mode updated to ${mode}`, 'success');
      applyModeVisualTheme(mode.toLowerCase());
      await refreshDashboard();
    } catch (e: any) {
      setModeFeedback(`Failed to update mode: ${e.message}`, 'error');
    } finally {
      modeRequestInFlight = false;
      setModeButtonsDisabled(false);
    }
  }

  modeButtons.forEach((button: any) => {
    button.addEventListener('click', async () => {
      const mode = button.dataset.mode;
      if (mode) await setMode(mode);
    });
  });

  async function refreshStats() {
    if (!actor) return;
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
      const map: Record<string, string> = { off: 'Off', medium: 'Medium', on: 'On' };
      modeButtons.forEach((btn: any) => {
        btn.classList.toggle('active', btn.dataset.mode === map[normalized]);
      });
      applyModeVisualTheme(normalized);
    } catch (e) {
      if (statStatus) {
        statStatus.textContent = 'Offline';
        statStatus.className = 'status-error';
      }
    }
  }

  async function refreshThreats() {
    if (!threatTbody || !actor) return;
    try {
      cachedThreats = await actor.getThreats();
      renderThreats(cachedThreats);
    } catch (e) {
      console.error('Failed to load threats:', e);
    }
  }

  function formatTimestamp(timestamp: any) {
    try {
      const ms = Number(BigInt(timestamp) / 1000000n);
      return new Date(ms).toLocaleString();
    } catch (e) {
      return String(timestamp);
    }
  }

  function renderThreats(threats: any[]) {
    if (!threatTbody) return;
    if (!threats || !threats.length) {
      threatTbody.innerHTML = `<tr><td colspan="4" style="color:var(--faint); text-align:center; padding:16px;">No threats recorded.</td></tr>`;
      return;
    }
    threatTbody.replaceChildren(
      ...threats.map((t) => {
        const tr = document.createElement('tr');
        const cell = (text: string, style = '') => {
          const td = document.createElement('td');
          td.textContent = text;
          if (style) td.style.cssText = style;
          return td;
        };
        tr.append(
          cell(formatTimestamp(t.timestamp)),
          cell(t.severity, `color:${t.severity === 'CRITICAL' ? 'var(--coral)' : 'var(--amber)'}; font-weight:bold;`),
          cell(t.threatType),
          cell(t.snippet, "font-family:'DM Mono',monospace;"),
        );
        return tr;
      }),
    );
  }

  exportTelemetryBtn?.addEventListener('click', () => {
    if (!cachedThreats.length) {
      alert('No threat telemetry records to export.');
      return;
    }
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(cachedThreats, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `icfirewall_threat_telemetry_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  });

  async function refreshDashboard() {
    if (dashboardRefreshInFlight || document.hidden || !actor) return;
    dashboardRefreshInFlight = true;
    try {
      await Promise.all([refreshStats(), refreshThreats()]);
    } catch (e) {
      console.error('Dashboard refresh error:', e);
    } finally {
      dashboardRefreshInFlight = false;
    }
  }

  function startLiveRefresh() {
    if (dashboardRefreshTimer) clearInterval(dashboardRefreshTimer);
    dashboardRefreshTimer = setInterval(() => { refreshDashboard(); }, 5000);
  }

  async function loadSecurityRules() {
    if (!actor) return;
    try {
      const config = await actor.getSecurityRules();
      if (ruleInjection) ruleInjection.checked = config.blockPromptInjection;
      if (ruleDestructive) ruleDestructive.checked = config.blockDestructiveCommands;
      if (rulePrivilege) rulePrivilege.checked = config.blockPrivilegeEscalation;
      if (ruleMaxContext) ruleMaxContext.value = String(Number(config.maxContextLength));
    } catch (e) {
      console.error('Failed to load security rules:', e);
    }
  }

  rulesForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!actor) return;
    try {
      const newConfig = {
        blockPromptInjection: ruleInjection?.checked ?? true,
        blockDestructiveCommands: ruleDestructive?.checked ?? true,
        blockPrivilegeEscalation: rulePrivilege?.checked ?? true,
        maxContextLength: BigInt(ruleMaxContext?.value || 12000),
      };
      const res = await actor.updateSecurityRules(newConfig);
      alert(res);
    } catch (err: any) {
      alert('Failed to save rules: ' + err.message);
    }
  });

  async function loadAdminList() {
    if (!actor) return;
    try {
      const admins = await actor.getAdmins();
      if (!adminListContainer) return;
      if (!admins.length) {
        adminListContainer.textContent = 'No secondary admins.';
        return;
      }
      adminListContainer.replaceChildren(
        ...admins.map((pid: string) => {
          const row = document.createElement('div');
          row.style.cssText = "display:flex; justify-content:space-between; align-items:center; padding:4px 0; font-family:'DM Mono',monospace; font-size:11px;";
          const label = document.createElement('span');
          label.textContent = `${pid.slice(0, 10)}…${pid.slice(-6)}`;
          const btn = document.createElement('button');
          btn.className = 'network-pill interactive-btn';
          btn.style.cssText = 'padding:2px 6px; font-size:8px;';
          btn.textContent = 'Revoke';
          btn.dataset.revoke = pid;
          row.append(label, btn);
          return row;
        }),
      );
    } catch (e) {
      console.error(e);
    }
  }

  adminListContainer?.addEventListener('click', async (ev) => {
    const pid = (ev.target as HTMLElement)?.dataset?.revoke;
    if (!pid || !actor) return;
    if (!confirm(`Revoke admin ${pid}?`)) return;
    try {
      alert(await actor.removeAdmin(pid));
      await loadAdminList();
    } catch (e: any) {
      alert('Failed to revoke admin: ' + e.message);
    }
  });

  addAdminForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const pid = newAdminInput?.value?.trim();
    if (!pid || !actor) return;
    try {
      const res = await actor.addAdmin(pid);
      alert(res);
      if (newAdminInput) newAdminInput.value = '';
      await loadAdminList();
    } catch (e: any) {
      alert('Failed to add admin: ' + e.message);
    }
  });

  claimMasterBtn?.addEventListener('click', async () => {
    if (!currentPID || !actor) {
      alert('Please log in with Internet Identity first.');
      return;
    }
    try {
      const res = await actor.claimMasterPID(currentPID);
      alert(res);
      window.location.reload();
    } catch (e: any) {
      alert('Claim failed: ' + e.message);
    }
  });

  type HistItem = { role: 'user' | 'ai'; text: string; mode: string; blocked: boolean; reason: string; ts: string; persist: boolean };
  let historyItems: HistItem[] = [];

  function renderBubble(item: HistItem): { bubble: HTMLElement; body: HTMLElement } {
    const bubble = document.createElement('div');
    bubble.className = `chat-message-bubble ${item.role === 'user' ? 'user-msg' : 'ai-msg'}`;
    const header = document.createElement('div');
    header.className = 'chat-msg-header';
    const left = document.createElement('span');
    const right = document.createElement('span');
    if (item.role === 'user') {
      left.textContent = 'USER';
    } else {
      left.textContent = `${item.blocked ? 'BLOCKED' : 'ALLOWED'} (${item.mode})`;
      left.style.color = item.blocked ? 'var(--coral)' : '#79e4a5';
    }
    right.textContent = item.ts;
    header.append(left, right);
    const body = document.createElement('p');
    body.className = 'chat-msg-body';
    body.textContent = item.text;
    bubble.append(header, body);
    if (item.reason) {
      const r = document.createElement('div');
      r.className = 'chat-msg-reason';
      r.style.cssText = 'margin-top:4px; font-size:10px; color:var(--faint);';
      r.textContent = `Reason: ${item.reason}`;
      bubble.append(r);
    }
    return { bubble, body };
  }

  function appendMessageToHistory(role: 'user' | 'ai', text: string, mode = '', isBlocked = false, reason = '', persist = true) {
    document.getElementById('chat-history-empty')?.remove();
    const item: HistItem = { role, text, mode, blocked: isBlocked, reason, ts: new Date().toLocaleTimeString(), persist };
    historyItems.push(item);
    const { bubble, body } = renderBubble(item);
    if (chatHistoryContainer) {
      chatHistoryContainer.appendChild(bubble);
      chatHistoryContainer.scrollTop = chatHistoryContainer.scrollHeight;
    }
    saveChatHistoryToStorage();
    return { item, body };
  }

  function saveChatHistoryToStorage() {
    try {
      // private prompts and replies stay in memory only
      localStorage.setItem(STORAGE_KEY, JSON.stringify(historyItems.filter((i) => i.persist).slice(-100)));
    } catch (_) {}
  }

  function loadStoredChatHistory() {
    try {
      localStorage.removeItem('icfirewall_chat_history_v1'); // old format stored raw HTML
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw || !chatHistoryContainer) return;
      const items = JSON.parse(raw);
      if (!Array.isArray(items) || !items.length) return;
      document.getElementById('chat-history-empty')?.remove();
      for (const i of items) {
        const item: HistItem = {
          role: i.role === 'user' ? 'user' : 'ai',
          text: String(i.text ?? ''), mode: String(i.mode ?? ''), blocked: !!i.blocked,
          reason: String(i.reason ?? ''), ts: String(i.ts ?? ''), persist: true,
        };
        historyItems.push(item);
        chatHistoryContainer.appendChild(renderBubble(item).bubble);
      }
    } catch (e) {
      console.error(e);
    }
  }

  clearHistoryBtn?.addEventListener('click', () => {
    localStorage.removeItem(STORAGE_KEY);
    historyItems = [];
    if (chatHistoryContainer) {
      chatHistoryContainer.innerHTML = `<div class="chat-history-empty" id="chat-history-empty"><p style="color:var(--faint); font-family:'DM Mono', monospace; font-size:12px; text-align:center; padding:24px 0;">History cleared.</p></div>`;
    }
  });

  async function getPublicKey(): Promise<Uint8Array> {
    if (!cachedPublicKey) cachedPublicKey = Uint8Array.from(await actor.getVetKeyPublicKey());
    return cachedPublicKey;
  }

  async function decryptPrivateResult(ticketId: bigint, sealedB64: string): Promise<string> {
    const tsk = TransportSecretKey.random(); // fresh transport key per request
    const [encKey, pk] = await Promise.all([actor.deriveResultKey(ticketId, tsk.publicKeyBytes()), getPublicKey()]);
    return decryptResult(pk, Uint8Array.from(encKey), ticketId, tsk, b64ToBytes(sealedB64));
  }

  function pollForAIResponse(ticketId: bigint, mode: string, isPrivate: boolean) {
    const { item, body } = appendMessageToHistory('ai', 'Awaiting response from daemon agent...', mode, false, isPrivate ? 'Private ticket (not scanned by the canister)' : 'Queued on canister bridge', !isPrivate);
    const key = ticketId.toString();
    if (activePollIntervals[key]) clearInterval(activePollIntervals[key]);

    const finish = (text: string, status: string, blocked = false) => {
      clearInterval(activePollIntervals[key]);
      delete activePollIntervals[key];
      item.text = text;
      item.blocked = blocked;
      body.textContent = text;

      const reasonEl = body.parentElement?.querySelector('.chat-msg-reason') as HTMLElement | null;
      if (reasonEl) {
        if (blocked) {
          reasonEl.textContent = `Reason: ${status}`;
        } else {
          reasonEl.remove();
        }
      }

      if (chatStatus) chatStatus.textContent = status;
      saveChatHistoryToStorage();
    };

    let attempts = 0;
    let inFlight = false;
    activePollIntervals[key] = setInterval(async () => {
      if (inFlight) return;
      inFlight = true;
      attempts++;
      try {
        const [statusOpt, responseOpt] = await Promise.all([actor.getTicketStatus(ticketId), actor.checkResponse(ticketId)]);
        const status: string = statusOpt.length ? statusOpt[0] : '';
        if (responseOpt.length > 0) {
          const text = isPrivate ? await decryptPrivateResult(ticketId, responseOpt[0]) : responseOpt[0];
          finish(text, 'Response received');
        } else if (status === 'failed') {
          finish('The daemon could not process this ticket after several attempts.', 'Failed', true);
        } else if (status === 'expired') {
          finish('This ticket expired before it was processed.', 'Expired', true);
        } else if (attempts > 120) {
          finish('Timeout waiting for the daemon (is it running?).', 'Polling timeout', true);
        } else if (chatStatus && status) {
          chatStatus.textContent = status === 'processing' ? 'Daemon is working...' : 'Queued for daemon';
        }
      } catch (err: any) {
        console.error('Polling error:', err);
        if (attempts > 120) finish('Polling failed: ' + (err?.message ?? err), 'Error', true);
      } finally {
        inFlight = false;
      }
    }, 1500);
  }

  chatForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = promptInput?.value?.trim();
    if (!text || !actor) return;
    if (!currentPID) {
      if (chatStatus) chatStatus.textContent = 'Log in with Internet Identity first';
      return;
    }
    const isPrivate = privateToggle?.checked || false;

    if (sendPromptBtn) sendPromptBtn.disabled = true;
    if (chatStatus) chatStatus.textContent = isPrivate ? 'Encrypting (vetKeys IBE)...' : 'Transmitting...';
    appendMessageToHistory('user', text, '', false, isPrivate ? 'Private mode' : '', !isPrivate);
    if (promptInput) promptInput.value = '';

    try {
      let result: any;
      if (isPrivate) {
        const ticketId: bigint = await actor.reservePrivateTicket();
        const ciphertext = encryptPrompt(await getPublicKey(), ticketId, text);
        result = await actor.submitPrivate(ticketId, ciphertext);
      } else {
        result = await actor.processPrompt(text);
      }

      if (result.allowed) {
        if (result.ticketId && result.ticketId.length > 0) {
          if (chatStatus) chatStatus.textContent = 'Queued for daemon';
          pollForAIResponse(BigInt(result.ticketId[0]), result.mode, isPrivate);
        } else {
          appendMessageToHistory('ai', result.response, result.mode, false, result.reason, !isPrivate);
          if (chatStatus) chatStatus.textContent = 'Processed';
        }
      } else {
        appendMessageToHistory('ai', result.response, result.mode, true, result.reason, !isPrivate);
        if (chatStatus) chatStatus.textContent = 'Blocked';
      }
      await refreshDashboard();
    } catch (err: any) {
      // fail closed: a private-mode error never falls back to sending plaintext
      if (chatStatus) chatStatus.textContent = 'Error';
      appendMessageToHistory('ai', 'Failed to process prompt: ' + (err?.message ?? err), 'ERROR', true, '', false);
    } finally {
      if (sendPromptBtn) sendPromptBtn.disabled = false;
    }
  });

  onOwnerPanels = async () => { await Promise.all([loadSecurityRules(), loadAdminList()]); };
  loadStoredChatHistory();
  await evaluatePermissions(); // re-run now that the owner panels can be populated
  await refreshDashboard();
  startLiveRefresh();
});
