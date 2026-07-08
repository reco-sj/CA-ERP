/* ============================================================================
   CA Task Tracker — by Reconense
   Vanilla JS (ES6+) · Firebase Realtime Database (REST) · SheetJS
   ----------------------------------------------------------------------------
   SECURITY MODEL (read README-SECURITY.md before deploying)
   - No plaintext passwords in source: salted SHA-256 hashes only (Web Crypto).
   - Client PII (mobile, email) is AES-256-GCM encrypted before it reaches the
     DB. Key material lives in the browser — documented obfuscation, not
     zero-knowledge; the real fix is the Firebase Auth upgrade in the README.
   - RBAC: 'admin' (everything) vs 'staff' (period status updates only); UI
     gating PLUS a requireAdmin() re-check on every privileged write.
   ----------------------------------------------------------------------------
   DATA MODEL
   ----------------------------------------------------------------------------
   /system/users/{username} : { passwordHash, role, displayName, createdAt }

   /masterTasks/{taskId} : {
       name, frequency: 'monthly'|'quarterly'|'yearly'|'once',
       defaultFees,                       // ₹ per filing/occurrence
       createdAt
   }

   /clients/{clientId} : {
       companyName, authorisedPerson, city, gstin, pan,
       mobile (encrypted), email (encrypted),
       tasks: { taskId: {
           fees,                          // per-client override of defaultFees
           periods: { "2026": { "Jan": "Completed", "Q2": "Pending", ... } }
       }},
       others:   { entryId: { note, fees } },    // one-off work lines
       payments: { payId:   { amount, ts, note } },
       createdAt, updatedAt
   }

   Periods per frequency: monthly → Jan..Dec · quarterly → Q1..Q4 (FY quarters:
   Q1 Apr–Jun … Q4 Jan–Mar) · yearly/once → a single "Year" period.
   Missing period ⇒ Pending. Legacy shapes (plain status string, {status,fees})
   are tolerated: their status is mapped onto the current period.

   Total payable (selected year) = Σ task fee × COMPLETED periods + Others.
   Payment status is derived from the payments ledger: Paid only when the sum
   of recorded payments covers the total.
============================================================================ */

'use strict';

/* ============================================================================
   1 · CONFIGURATION
============================================================================ */

const DB_URL = 'https://ca-erp-c9edf-default-rtdb.europe-west1.firebasedatabase.app';

const APP_SALT = 'RECONENSE-CA-ERP-v1';

/**
 * Bootstrap admin credential — stored as a salted hash only:
 * SHA-256("reco" + "::" + APP_SALT + "::" + <password>).
 * Seeded when /system/users is empty; change it from the Users menu after
 * first login.
 */
const BOOTSTRAP_ADMIN = {
  username: 'reco',
  passwordHash: 'b93d67d1e55016da221b241dfa23652a4c4048ba5b084ec5ec6c2a0d471cf896',
  role: 'admin',
  displayName: 'Reco (Admin)',
};

const PII_SECRET = 'reconense.pii.obfuscation.key.v1';
const PII_KDF_SALT = 'reconense-kdf-salt-2026';
const ENC_PREFIX = 'enc.v1:';

const CLIENT_COLUMNS = [
  { key: 'companyName',      label: 'Company Name' },
  { key: 'authorisedPerson', label: 'Authorised Person' },
  { key: 'mobile',           label: 'Mobile Number' },
  { key: 'city',             label: 'City' },
  { key: 'email',            label: 'Email' },
  { key: 'gstin',            label: 'GSTIN' },
  { key: 'pan',              label: 'PAN' },
];

const TASK_STATUSES = ['Pending', 'Completed', 'Not Applicable'];
const STATUS_SHORT = { 'Pending': 'Pending', 'Completed': 'Completed', 'Not Applicable': 'N/A' };

const FREQUENCIES = ['monthly', 'quarterly', 'yearly', 'once'];
const FREQ_LABEL = { monthly: 'Monthly', quarterly: 'Quarterly', yearly: 'Yearly', once: 'Once' };

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const QUARTERS = ['Q1', 'Q2', 'Q3', 'Q4'];
/** Indian FY quarters, used for tooltips and "current quarter" resolution. */
const QUARTER_HINT = { Q1: 'Apr–Jun', Q2: 'Jul–Sep', Q3: 'Oct–Dec', Q4: 'Jan–Mar' };

/* ============================================================================
   2 · APPLICATION STATE
============================================================================ */

const state = {
  session: null,
  users: {},
  masterTasks: {},
  clients: {},
  piiKey: null,
  expanded: new Set(),               // open client panels
  year: new Date().getFullYear(),    // selected working year
  payClient: null,                   // client id open in the payments modal
};

/* ============================================================================
   3 · SMALL UTILITIES
============================================================================ */

const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function safeKey(str) {
  return String(str).trim().toLowerCase().replace(/[.#$\[\]\/\s]+/g, '_');
}

function uid(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function inr(n) {
  const v = Number(n) || 0;
  return '₹' + v.toLocaleString('en-IN');
}

function toFee(v) {
  const n = parseFloat(String(v ?? '').replace(/[₹,\s]/g, ''));
  return Number.isFinite(n) && n >= 0 ? Math.round(n * 100) / 100 : 0;
}

let toastTimer = null;
function toast(msg, isError = false) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.toggle('error', isError);
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
}

/* ============================================================================
   4 · CRYPTO — hashing (auth) and AES-GCM (PII at rest)
============================================================================ */

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function credentialHash(username, password) {
  return sha256Hex(`${username.trim().toLowerCase()}::${APP_SALT}::${password}`);
}

async function derivePiiKey() {
  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(PII_SECRET), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new TextEncoder().encode(PII_KDF_SALT), iterations: 150000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptField(plaintext) {
  if (!plaintext) return '';
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, state.piiKey, new TextEncoder().encode(String(plaintext))
  );
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  return `${ENC_PREFIX}${b64(iv)}:${b64(cipher)}`;
}

async function decryptField(stored) {
  if (!stored) return '';
  if (!String(stored).startsWith(ENC_PREFIX)) return String(stored);
  try {
    const [ivB64, dataB64] = String(stored).slice(ENC_PREFIX.length).split(':');
    const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(ivB64) }, state.piiKey, fromB64(dataB64)
    );
    return new TextDecoder().decode(plain);
  } catch {
    return '[unreadable]';
  }
}

/* ============================================================================
   5 · FIREBASE REALTIME DATABASE — thin REST wrapper
============================================================================ */

function dbUrl(path) {
  // Hook for Firebase Auth: append `?auth=${idToken}` here once enabled.
  return `${DB_URL}/${path}.json`;
}

async function dbRequest(method, path, body) {
  const res = await fetch(dbUrl(path), {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Database ${method} ${path} failed (${res.status}): ${text}`);
  }
  return res.json();
}

const dbGet    = (path)       => dbRequest('GET', path);
const dbPut    = (path, data) => dbRequest('PUT', path, data);
const dbPatch  = (path, data) => dbRequest('PATCH', path, data);
const dbDelete = (path)       => dbRequest('DELETE', path);

/* ============================================================================
   6 · AUTHENTICATION & SESSION
============================================================================ */

async function seedBootstrapAdminIfNeeded() {
  const users = await dbGet('system/users');
  if (users && Object.keys(users).length > 0) return;
  await dbPut(`system/users/${safeKey(BOOTSTRAP_ADMIN.username)}`, {
    passwordHash: BOOTSTRAP_ADMIN.passwordHash,
    role: BOOTSTRAP_ADMIN.role,
    displayName: BOOTSTRAP_ADMIN.displayName,
    createdAt: Date.now(),
  });
}

async function login(username, password) {
  await seedBootstrapAdminIfNeeded();

  const record = await dbGet(`system/users/${safeKey(username)}`);
  if (!record || !record.passwordHash) throw new Error('Invalid username or password.');

  const hash = await credentialHash(username, password);
  let mismatch = hash.length !== record.passwordHash.length;
  for (let i = 0; i < hash.length; i++) mismatch = mismatch || hash[i] !== record.passwordHash[i];
  if (mismatch) throw new Error('Invalid username or password.');

  const role = record.role === 'admin' ? 'admin' : 'staff';
  state.session = { username: safeKey(username), role, displayName: record.displayName || username };
  sessionStorage.setItem('reconense.session', JSON.stringify(state.session));
}

function restoreSession() {
  try {
    const raw = sessionStorage.getItem('reconense.session');
    if (!raw) return false;
    const s = JSON.parse(raw);
    if (!s || !s.username || !s.role) return false;
    state.session = s;
    return true;
  } catch { return false; }
}

function logout() {
  sessionStorage.removeItem('reconense.session');
  state.session = null;
  location.reload();
}

const isAdmin = () => state.session?.role === 'admin';

function requireAdmin() {
  if (!isAdmin()) {
    toast('Only an Admin can perform this action.', true);
    throw new Error('RBAC: admin required');
  }
}

/* ============================================================================
   7 · PERIODS — the heart of the frequency model
============================================================================ */

/** Period keys for a frequency: 12 months, 4 FY quarters, or a single year. */
function periodsFor(frequency) {
  if (frequency === 'monthly')   return MONTHS;
  if (frequency === 'quarterly') return QUARTERS;
  return ['Year'];
}

/** FY quarter containing a given month index (0 = Jan). Q1 = Apr–Jun. */
function fyQuarterOfMonth(m) {
  if (m >= 3 && m <= 5)  return 'Q1';
  if (m >= 6 && m <= 8)  return 'Q2';
  if (m >= 9 && m <= 11) return 'Q3';
  return 'Q4'; // Jan–Mar
}

/** The period that "today" falls in, if the selected year is the current one. */
function currentPeriodFor(frequency, year) {
  const now = new Date();
  if (year !== now.getFullYear()) return null;
  if (frequency === 'monthly')   return MONTHS[now.getMonth()];
  if (frequency === 'quarterly') return fyQuarterOfMonth(now.getMonth());
  return 'Year';
}

const validFrequency = (f) => (FREQUENCIES.includes(f) ? f : 'yearly');

/* ============================================================================
   8 · DATA LOADING & DERIVED VALUES
============================================================================ */

async function loadAllData() {
  const [tasks, clients, users] = await Promise.all([
    dbGet('masterTasks'),
    dbGet('clients'),
    isAdmin() ? dbGet('system/users') : Promise.resolve(null),
  ]);
  state.masterTasks = tasks || {};
  state.users = users || {};

  const decrypted = {};
  for (const [id, c] of Object.entries(clients || {})) {
    decrypted[id] = {
      ...c,
      mobile: await decryptField(c.mobile),
      email:  await decryptField(c.email),
      gstin:  c.gstin || '',
      pan:    c.pan || '',
      tasks:  c.tasks || {},
      others: normalizeOthers(c.others),
      payments: c.payments || {},
    };
  }
  state.clients = decrypted;
}

function normalizeOthers(raw) {
  const out = {};
  if (raw && (typeof raw.note === 'string' || typeof raw.fees === 'number' || typeof raw.fees === 'string')) {
    out['o_legacy'] = { note: String(raw.note || ''), fees: toFee(raw.fees) };
  } else if (raw && typeof raw === 'object') {
    for (const [eid, e] of Object.entries(raw)) {
      if (e && typeof e === 'object') out[eid] = { note: String(e.note || ''), fees: toFee(e.fees) };
    }
  }
  if (Object.keys(out).length === 0) out[uid('oth')] = { note: '', fees: 0 };
  return out;
}

function othersEntries(client) {
  return Object.entries(client.others || {}).sort((a, b) => a[0].localeCompare(b[0]));
}

function sortedTasks() {
  return Object.entries(state.masterTasks)
    .sort((a, b) => a[1].name.localeCompare(b[1].name));
}

/**
 * Normalised task node for a client:
 * { fees, periods: {year: {period: status}} } — tolerating both legacy shapes
 * (plain status string; v2 {status, fees}), whose status is mapped onto the
 * CURRENT period of the current year.
 */
function taskNode(client, taskId) {
  const t = state.masterTasks[taskId] || {};
  const def = toFee(t.defaultFees);
  const raw = client.tasks?.[taskId];

  if (raw == null) return { fees: def, periods: {} };

  if (typeof raw === 'string') { // legacy v1
    return { fees: def, periods: legacyPeriods(raw, t.frequency) };
  }
  if (raw.status !== undefined && raw.periods === undefined) { // legacy v2
    return {
      fees: raw.fees === undefined ? def : toFee(raw.fees),
      periods: legacyPeriods(raw.status, t.frequency),
    };
  }
  return {
    fees: raw.fees === undefined ? def : toFee(raw.fees),
    periods: raw.periods || {},
  };
}

function legacyPeriods(status, frequency) {
  if (!TASK_STATUSES.includes(status)) return {};
  const year = new Date().getFullYear();
  const period = currentPeriodFor(validFrequency(frequency), year) || 'Year';
  return { [year]: { [period]: status } };
}

/** Status of one period of a task for a client (missing ⇒ Pending). */
function periodStatus(client, taskId, year, period) {
  const s = taskNode(client, taskId).periods?.[year]?.[period];
  return TASK_STATUSES.includes(s) ? s : 'Pending';
}

/** Per-filing fee for a task/client (client override or task default). */
function taskFee(client, taskId) {
  return taskNode(client, taskId).fees;
}

/** {completed, pending, na, applicable} period counts for a task in a year. */
function periodCounts(client, taskId, year) {
  const freq = validFrequency(state.masterTasks[taskId]?.frequency);
  let completed = 0, pending = 0, na = 0;
  for (const p of periodsFor(freq)) {
    const s = periodStatus(client, taskId, year, p);
    if (s === 'Completed') completed++;
    else if (s === 'Not Applicable') na++;
    else pending++;
  }
  return { completed, pending, na, applicable: completed + pending };
}

/**
 * Total payable by a client for a year:
 * fee × number of COMPLETED filings for every task, plus all Others fees.
 * The total grows as work gets marked Completed.
 */
function totalFees(client, year = state.year) {
  let sum = othersEntries(client).reduce((s, [, e]) => s + (e.fees || 0), 0);
  for (const [taskId] of sortedTasks()) {
    sum += taskFee(client, taskId) * periodCounts(client, taskId, year).completed;
  }
  return Math.round(sum * 100) / 100;
}

/* ---- Payments ledger ------------------------------------------------------ */

function paymentEntries(client) {
  return Object.entries(client.payments || {}).sort((a, b) => (a[1].ts || 0) - (b[1].ts || 0));
}

function paymentsSum(client) {
  return paymentEntries(client).reduce((s, [, p]) => s + toFee(p.amount), 0);
}

/** 'Paid' | 'Partial' | 'Unpaid' | 'No dues' — derived, never set by hand. */
function paymentStatus(client, year = state.year) {
  const total = totalFees(client, year);
  const paid = paymentsSum(client);
  if (total <= 0) return paid > 0 ? 'Paid' : 'No dues';
  if (paid >= total) return 'Paid';
  if (paid > 0) return 'Partial';
  return 'Unpaid';
}

function balanceDue(client, year = state.year) {
  return Math.max(0, Math.round((totalFees(client, year) - paymentsSum(client)) * 100) / 100);
}

/* ============================================================================
   9 · NAVIGATION & SHELL
============================================================================ */

function showView(name) {
  $$('.view').forEach((v) => { v.hidden = v.id !== `view-${name}`; });
  $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
}

function populateYearSelect() {
  const sel = $('#year-select');
  const cy = new Date().getFullYear();
  const years = [cy + 1, cy, cy - 1, cy - 2, cy - 3];
  sel.innerHTML = years.map((y) =>
    `<option value="${y}" ${y === state.year ? 'selected' : ''}>${y}</option>`).join('');
}

function enterApp() {
  $('#login-screen').hidden = true;
  $('#app-shell').hidden = false;
  document.body.classList.toggle('role-staff', !isAdmin());
  $('#user-name').textContent = state.session.displayName;
  const roleEl = $('#user-role');
  roleEl.textContent = state.session.role;
  roleEl.classList.toggle('staff', !isAdmin());
  populateYearSelect();
  renderAll();
  showView('dashboard');
}

function renderAll() {
  $('#clients-year-label').textContent = `year ${state.year}`;
  renderMetrics();
  renderDashboardTable();
  renderClientTable();
  renderTaskList();
  renderTaskFilterOptions();
  if (isAdmin()) renderUserTable();
}

/* ============================================================================
   10 · DASHBOARD — one card per task + fees outstanding
============================================================================ */

/**
 * Card counts for a task. For the current year: clients pending/completed in
 * the CURRENT period (this month / this quarter / this year) — the number a
 * CA acts on. For other years: pending = clients with any pending filing that
 * year; completed = clients whose every applicable filing is completed.
 */
function taskCardCounts(taskId) {
  const freq = validFrequency(state.masterTasks[taskId]?.frequency);
  const cur = currentPeriodFor(freq, state.year);
  const clients = Object.values(state.clients);
  let pending = 0, completed = 0;

  for (const c of clients) {
    if (cur) {
      const s = periodStatus(c, taskId, state.year, cur);
      if (s === 'Pending') pending++;
      else if (s === 'Completed') completed++;
    } else {
      const pc = periodCounts(c, taskId, state.year);
      if (pc.pending > 0) pending++;
      else if (pc.applicable > 0 && pc.completed === pc.applicable) completed++;
    }
  }

  let scope;
  if (!cur) scope = `full year ${state.year}`;
  else if (freq === 'monthly')   scope = `${cur} ${state.year}`;
  else if (freq === 'quarterly') scope = `${cur} (${QUARTER_HINT[cur]}) ${state.year}`;
  else scope = `${state.year}`;

  return { pending, completed, scope, freq };
}

function renderMetrics() {
  const clients = Object.values(state.clients);
  $('#m-total').textContent = clients.length;

  // One live card per master task, with pending + completed counts.
  $('#task-cards').innerHTML = sortedTasks().map(([taskId, t]) => {
    const { pending, completed, scope, freq } = taskCardCounts(taskId);
    return `
      <article class="metric-card metric-task ${pending > 0 ? 'metric-warn' : ''}">
        <span class="metric-label">${esc(t.name)}
          <span class="freq-badge">${esc(FREQ_LABEL[freq])}</span></span>
        <span class="metric-duo">
          <span class="duo pending"><b>${pending}</b> pending</span>
          <span class="duo completed"><b>${completed}</b> completed</span>
        </span>
        <span class="metric-sub">${esc(scope)}</span>
      </article>`;
  }).join('');

  // Fees outstanding = Σ balance due across clients (completed work − payments).
  const outstanding = clients.reduce((s, c) => s + balanceDue(c), 0);
  const owing = clients.filter((c) => balanceDue(c) > 0).length;
  $('#m-fees').textContent = inr(outstanding);
  $('#m-fees-sub').textContent = owing ? `${owing} client(s) owe for ${state.year}` : `all settled for ${state.year}`;
}

function renderTaskFilterOptions() {
  const sel = $('#dash-filter-task');
  const current = sel.value;
  sel.innerHTML = '<option value="">Any task</option>' + sortedTasks()
    .map(([id, t]) => `<option value="${esc(id)}">${esc(t.name)}</option>`).join('');
  sel.value = current;
}

/** Does a task have at least one period with this status in the year? */
function taskHasStatus(client, taskId, status) {
  const freq = validFrequency(state.masterTasks[taskId]?.frequency);
  return periodsFor(freq).some((p) => periodStatus(client, taskId, state.year, p) === status);
}

function filteredDashboardClients() {
  const q = $('#dash-search').value.trim().toLowerCase();
  const fTask = $('#dash-filter-task').value;
  const fStatus = $('#dash-filter-status').value;

  return Object.entries(state.clients).filter(([, c]) => {
    if (q) {
      const hay = `${c.companyName} ${c.authorisedPerson} ${c.city} ${c.mobile} ${c.email} ${c.gstin} ${c.pan}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (fTask && fStatus) return taskHasStatus(c, fTask, fStatus);
    if (fTask) return true;
    if (fStatus) return sortedTasks().some(([id]) => taskHasStatus(c, id, fStatus));
    return true;
  });
}

function renderDashboardTable() {
  const rows = filteredDashboardClients();
  const tbody = $('#dash-tbody');
  $('#dash-empty').hidden = rows.length > 0;

  tbody.innerHTML = rows.map(([id, c]) => `
    <tr>
      <td class="cell-strong">${esc(c.companyName)}
        ${c.gstin ? `<br><span class="cell-muted">GSTIN: ${esc(c.gstin)}</span>` : ''}
        ${c.pan ? `<br><span class="cell-muted">PAN: ${esc(c.pan)}</span>` : ''}</td>
      <td>${esc(c.authorisedPerson)}</td>
      <td>${esc(c.mobile)}${c.email ? `<br><span class="cell-muted">${esc(c.email)}</span>` : ''}</td>
      <td>${esc(c.city)}</td>
      <td>${renderProgressChips(c)}</td>
      <td class="admin-only cell-strong">${inr(totalFees(c))}</td>
      <td class="admin-only">${renderPaymentPill(c)}</td>
    </tr>
  `).join('');
}

/* ============================================================================
   11 · SHARED RENDERERS — chips, pills, period buttons
============================================================================ */

const statusClass = (s) =>
  s === 'Completed' ? 'st-completed' : s === 'Not Applicable' ? 'st-na' : 'st-pending';

/**
 * Read-only dashboard chips: "GST Filing: 5/12" (completed/applicable) for
 * repeating tasks, or the plain status for yearly/once tasks. Statuses are
 * changed in the Clients section only.
 */
function renderProgressChips(client) {
  const tasks = sortedTasks();
  if (!tasks.length) return '<span class="cell-muted">No master tasks defined</span>';

  return `<div class="task-chips">` + tasks.map(([taskId, t]) => {
    const freq = validFrequency(t.frequency);
    const pc = periodCounts(client, taskId, state.year);
    let label, cls;
    if (pc.applicable === 0) {
      label = 'N/A'; cls = 'st-na';
    } else if (freq === 'yearly' || freq === 'once') {
      const s = periodStatus(client, taskId, state.year, 'Year');
      label = STATUS_SHORT[s]; cls = statusClass(s);
    } else {
      label = `${pc.completed}/${pc.applicable}`;
      cls = pc.completed === pc.applicable ? 'st-completed' : 'st-pending';
    }
    return `
      <span class="task-chip ${cls}"
            title="${esc(t.name)} (${esc(FREQ_LABEL[freq])}, ${state.year}): ${pc.completed} completed, ${pc.pending} pending, ${pc.na} N/A — update in Clients">
        <span class="chip-dot" aria-hidden="true"></span>${esc(t.name)}: ${esc(label)}
      </span>`;
  }).join('') + `</div>`;
}

/** Derived payment pill: Paid / Partial / Unpaid / No dues. */
function renderPaymentPill(client) {
  const st = paymentStatus(client);
  const cls = { 'Paid': 'pay-paid', 'Partial': 'pay-partial', 'Unpaid': 'pay-unpaid', 'No dues': 'pay-none' }[st];
  const paid = paymentsSum(client);
  const total = totalFees(client);
  const tip = `Received ${inr(paid)} of ${inr(total)} (${state.year})`;
  return `<span class="status-pill ${cls}" title="${esc(tip)}">${esc(st)}</span>`;
}

/**
 * Clickable period grid for one task row: Jan…Dec / Q1…Q4 / Year.
 * Click cycles Pending → Completed → N/A. Both roles may update.
 */
function renderPeriodGrid(clientId, client, taskId) {
  const freq = validFrequency(state.masterTasks[taskId]?.frequency);
  const cur = currentPeriodFor(freq, state.year);
  return `<div class="period-grid">` + periodsFor(freq).map((p) => {
    const s = periodStatus(client, taskId, state.year, p);
    const hint = freq === 'quarterly' ? ` (${QUARTER_HINT[p]})` : '';
    return `
      <button type="button" class="period-btn ${statusClass(s)} ${p === cur ? 'period-current' : ''}"
              data-action="cycle-period" data-client="${esc(clientId)}"
              data-task="${esc(taskId)}" data-period="${esc(p)}"
              title="${esc(p)}${hint} ${state.year}: ${esc(s)} — click to change">
        ${esc(p === 'Year' ? String(state.year) : p)}
      </button>`;
  }).join('') + `</div>`;
}

/* ============================================================================
   12 · CLIENTS VIEW — expandable rows with the period & fees panel
============================================================================ */

/** Overall "filings completed" summary for the clients table. */
function progressSummary(client) {
  let completed = 0, applicable = 0, pending = 0;
  for (const [taskId] of sortedTasks()) {
    const pc = periodCounts(client, taskId, state.year);
    completed += pc.completed;
    applicable += pc.applicable;
    pending += pc.pending;
  }
  return { completed, applicable, pending };
}

function renderClientTable() {
  const q = $('#client-search').value.trim().toLowerCase();
  const rows = Object.entries(state.clients).filter(([, c]) => {
    if (!q) return true;
    return `${c.companyName} ${c.authorisedPerson} ${c.city} ${c.mobile} ${c.email} ${c.gstin} ${c.pan}`
      .toLowerCase().includes(q);
  });

  $('#client-empty').hidden = rows.length > 0;
  $('#client-tbody').innerHTML = rows.map(([id, c]) => {
    const open = state.expanded.has(id);
    const p = progressSummary(c);
    return `
    <tr class="${open ? 'row-open' : ''}">
      <td>
        <button class="expand-btn ${open ? 'open' : ''}" data-action="toggle-expand"
                data-client="${esc(id)}" aria-expanded="${open}"
                title="${open ? 'Hide' : 'Show'} tasks &amp; fees">›</button>
      </td>
      <td class="cell-strong">${esc(c.companyName)}
        ${c.gstin ? `<br><span class="cell-muted">GSTIN: ${esc(c.gstin)}</span>` : ''}
        ${c.pan ? `<br><span class="cell-muted">PAN: ${esc(c.pan)}</span>` : ''}</td>
      <td>${esc(c.authorisedPerson)}
        ${c.email ? `<br><span class="cell-muted">${esc(c.email)}</span>` : ''}</td>
      <td>${esc(c.mobile)}</td>
      <td>${esc(c.city)}</td>
      <td>
        <span class="prog">
          <span class="prog-done">${p.completed}</span>/<span>${p.applicable}</span> filings completed
          ${p.pending ? `· <span class="prog-pending">${p.pending} pending</span>` : ''}
        </span>
      </td>
      <td class="admin-only cell-strong">${inr(totalFees(c))}</td>
      <td class="admin-only">
        <div class="pay-cell">
          ${renderPaymentPill(c)}
          <button class="btn-icon" data-action="open-payments" data-client="${esc(id)}"
                  title="Record / view payments">₹</button>
        </div>
      </td>
      <td class="admin-only">
        <button class="btn-icon" data-action="edit-client" data-client="${esc(id)}" title="Edit">✎</button>
        <button class="btn-icon danger" data-action="delete-client" data-client="${esc(id)}" title="Delete">🗑</button>
      </td>
    </tr>
    ${open ? renderTaskPanelRow(id, c) : ''}`;
  }).join('');
}

function renderTaskPanelRow(clientId, client) {
  const admin = isAdmin();
  const tasks = sortedTasks();

  const taskRows = tasks.map(([taskId, t]) => {
    const freq = validFrequency(t.frequency);
    const fee = taskFee(client, taskId);
    const pc = periodCounts(client, taskId, state.year);
    return `
      <tr>
        <td class="panel-task-name">${esc(t.name)}
          <span class="freq-badge">${esc(FREQ_LABEL[freq])}</span></td>
        <td>${renderPeriodGrid(clientId, client, taskId)}</td>
        <td class="admin-only">
          <span class="fee-wrap">₹
            <input type="number" class="fee-input" min="0" step="1" value="${fee}"
                   data-action="set-task-fees" data-client="${esc(clientId)}" data-task="${esc(taskId)}"
                   aria-label="Fee per filing for ${esc(t.name)}" />
          </span>
          <span class="fee-calc">× ${pc.completed} = <b>${inr(fee * pc.completed)}</b></span>
        </td>
      </tr>`;
  }).join('');

  const entries = othersEntries(client);
  const othersRows = entries.map(([entryId, entry], idx) => `
    <tr class="others-row">
      <td class="panel-task-name">
        ${idx === 0
          ? `Others <span class="cell-muted others-hint">one-off work for this client</span>`
          : `<span class="cell-muted">Others ${idx + 1}</span>`}
      </td>
      <td>
        <div class="others-line">
          ${admin
            ? `<input type="text" class="others-note" maxlength="300"
                 placeholder="Describe the work, e.g. ROC annual return, notice reply…"
                 value="${esc(entry.note)}"
                 data-action="set-others-note" data-client="${esc(clientId)}" data-entry="${esc(entryId)}" />`
            : `<span class="cell-muted">${esc(entry.note) || '—'}</span>`}
          ${admin && entries.length > 1
            ? `<button type="button" class="btn-icon danger" title="Remove this Others line"
                 data-action="remove-others" data-client="${esc(clientId)}" data-entry="${esc(entryId)}">−</button>`
            : ''}
          ${admin && idx === entries.length - 1
            ? `<button type="button" class="btn-icon add-others-btn" title="Add another Others line"
                 data-action="add-others" data-client="${esc(clientId)}">＋</button>`
            : ''}
        </div>
      </td>
      <td class="admin-only">
        <span class="fee-wrap">₹
          <input type="number" class="fee-input" min="0" step="1" value="${entry.fees}"
                 data-action="set-others-fees" data-client="${esc(clientId)}" data-entry="${esc(entryId)}"
                 aria-label="Fees for other work" />
        </span>
      </td>
    </tr>`).join('');

  const totalRow = admin ? `
    <tr class="panel-total">
      <td>Total payable ${state.year}
        <span class="cell-muted others-hint">completed filings + others</span></td>
      <td class="pay-total-mid">
        Received: <b>${inr(paymentsSum(client))}</b> · Balance: <b>${inr(balanceDue(client))}</b>
      </td>
      <td>${inr(totalFees(client))}</td>
    </tr>` : '';

  return `
    <tr class="detail-row">
      <td colspan="9">
        <div class="task-panel">
          <div class="panel-legend">
            <span class="panel-year">Year: <b>${state.year}</b> (change in the header)</span>
            <span class="legend-item"><span class="chip-dot st-pending-dot"></span> Pending</span>
            <span class="legend-item"><span class="chip-dot st-completed-dot"></span> Completed</span>
            <span class="legend-item"><span class="chip-dot st-na-dot"></span> Not Applicable</span>
            <span class="cell-muted">— click a month/quarter/year box to cycle its status</span>
          </div>
          <table class="panel-table">
            <thead>
              <tr><th>Task</th><th>Filing periods — ${state.year}</th><th class="admin-only">Fee per filing (₹)</th></tr>
            </thead>
            <tbody>
              ${tasks.length ? taskRows : `<tr><td colspan="3" class="cell-muted">No master tasks defined yet.</td></tr>`}
              ${othersRows}
            </tbody>
            <tfoot>${totalRow}</tfoot>
          </table>
        </div>
      </td>
    </tr>`;
}

/* ============================================================================
   13 · CLIENT ADD / EDIT / DELETE (modal)
============================================================================ */

function openClientModal(clientId = null) {
  requireAdmin();
  const modal = $('#client-modal');
  const c = clientId ? state.clients[clientId] : null;
  $('#client-modal-title').textContent = c ? 'Edit client' : 'Add client';
  $('#client-id').value = clientId || '';
  $('#c-company').value = c?.companyName ?? '';
  $('#c-person').value  = c?.authorisedPerson ?? '';
  $('#c-mobile').value  = c?.mobile ?? '';
  $('#c-city').value    = c?.city ?? '';
  $('#c-gstin').value   = c?.gstin ?? '';
  $('#c-pan').value     = c?.pan ?? '';
  $('#c-email').value   = c?.email ?? '';
  $('#client-error').hidden = true;
  modal.hidden = false;
  $('#c-company').focus();
}

function closeClientModal() { $('#client-modal').hidden = true; }

/** New clients: every master task present with its default fee, no periods
    marked yet (missing period ⇒ Pending). */
function freshTaskMap() {
  const map = {};
  for (const [id, t] of sortedTasks()) map[id] = { fees: toFee(t.defaultFees) };
  return map;
}

async function saveClientFromModal(e) {
  e.preventDefault();
  requireAdmin();
  const btn = $('#client-save');
  btn.disabled = true;

  try {
    const editingId = $('#client-id').value;
    const clientId = editingId || uid('cl');
    const existing = editingId ? state.clients[editingId] : null;

    const plain = {
      companyName:      $('#c-company').value.trim(),
      authorisedPerson: $('#c-person').value.trim(),
      mobile:           $('#c-mobile').value.trim(),
      city:             $('#c-city').value.trim(),
      gstin:            $('#c-gstin').value.trim().toUpperCase(),
      pan:              $('#c-pan').value.trim().toUpperCase(),
      email:            $('#c-email').value.trim(),
    };

    const record = {
      companyName: plain.companyName,
      authorisedPerson: plain.authorisedPerson,
      city: plain.city,
      gstin: plain.gstin,
      pan: plain.pan,
      mobile: await encryptField(plain.mobile),
      email:  await encryptField(plain.email),
      tasks: existing ? (existing.tasks || {}) : freshTaskMap(),
      others: existing ? existing.others : {},
      payments: existing ? (existing.payments || {}) : {},
      updatedAt: Date.now(),
      createdAt: existing?.createdAt || Date.now(),
    };

    await dbPut(`clients/${clientId}`, record);
    state.clients[clientId] = {
      ...record,
      mobile: plain.mobile,
      email: plain.email,
      others: normalizeOthers(record.others),
    };
    closeClientModal();
    renderAll();
    toast(existing ? 'Client updated.' : 'Client added.');
  } catch (err) {
    console.error(err);
    const errEl = $('#client-error');
    errEl.textContent = 'Could not save the client. Check your connection and try again.';
    errEl.hidden = false;
  } finally {
    btn.disabled = false;
  }
}

async function deleteClient(clientId) {
  requireAdmin();
  const c = state.clients[clientId];
  if (!c) return;
  if (!confirm(`Delete "${c.companyName}" with all task statuses and payment records? This cannot be undone.`)) return;
  try {
    await dbDelete(`clients/${clientId}`);
    delete state.clients[clientId];
    state.expanded.delete(clientId);
    renderAll();
    toast('Client deleted.');
  } catch (err) {
    console.error(err);
    toast('Delete failed — check your connection.', true);
  }
}

/* ============================================================================
   14 · MASTER TASK LIST (admin) — name + frequency + default fees
============================================================================ */

function renderTaskList() {
  const tasks = sortedTasks();
  $('#task-empty').hidden = tasks.length > 0;
  $('#task-list').innerHTML = tasks.map(([id, t]) => `
    <li>
      <span class="task-name">${esc(t.name)}
        <span class="freq-badge">${esc(FREQ_LABEL[validFrequency(t.frequency)])}</span></span>
      <span class="task-fee">
        default ₹
        <input type="number" class="fee-input" min="0" step="1" value="${toFee(t.defaultFees)}"
               data-action="set-default-fees" data-task="${esc(id)}"
               aria-label="Default fees for ${esc(t.name)}" />
        /filing
      </span>
      <button class="btn-icon danger" data-action="delete-task" data-task="${esc(id)}" title="Remove task">🗑</button>
    </li>
  `).join('');
}

async function addMasterTask(e) {
  e.preventDefault();
  requireAdmin();
  const input = $('#task-name');
  const name = input.value.trim();
  const frequency = validFrequency($('#task-frequency').value);
  const defaultFees = toFee($('#task-fees').value);
  const errEl = $('#task-error');
  errEl.hidden = true;

  if (!name) return;
  if (name.toLowerCase() === 'others') {
    errEl.textContent = '"Others" is built into every client automatically — no need to add it here.';
    errEl.hidden = false;
    return;
  }
  const duplicate = Object.values(state.masterTasks)
    .some((t) => t.name.toLowerCase() === name.toLowerCase());
  if (duplicate) {
    errEl.textContent = 'A task with this name already exists.';
    errEl.hidden = false;
    return;
  }

  try {
    const id = uid('task');
    const record = { name, frequency, defaultFees, createdAt: Date.now() };
    await dbPut(`masterTasks/${id}`, record);
    state.masterTasks[id] = record;
    input.value = '';
    $('#task-fees').value = '0';
    renderAll();
    toast(`"${name}" added — ${FREQ_LABEL[frequency]}, ${inr(defaultFees)} per filing.`);
  } catch (err) {
    console.error(err);
    errEl.textContent = 'Could not save the task. Check your connection.';
    errEl.hidden = false;
  }
}

async function deleteMasterTask(taskId) {
  requireAdmin();
  const t = state.masterTasks[taskId];
  if (!t) return;
  if (!confirm(`Remove "${t.name}" from the master list? All client statuses and fees for this task will also be removed.`)) return;
  try {
    await dbDelete(`masterTasks/${taskId}`);
    const patches = [];
    for (const [clientId, c] of Object.entries(state.clients)) {
      if (c.tasks && taskId in c.tasks) {
        patches.push(dbDelete(`clients/${clientId}/tasks/${taskId}`));
        delete c.tasks[taskId];
      }
    }
    await Promise.all(patches);
    delete state.masterTasks[taskId];
    renderAll();
    toast('Task removed.');
  } catch (err) {
    console.error(err);
    toast('Could not remove the task.', true);
  }
}

/* ============================================================================
   15 · PAYMENTS MODAL (admin) — partial payments ledger
============================================================================ */

function openPaymentsModal(clientId) {
  requireAdmin();
  state.payClient = clientId;
  renderPaymentsModal();
  $('#payments-modal').hidden = false;
  $('#pay-amount').focus();
}

function closePaymentsModal() {
  $('#payments-modal').hidden = true;
  state.payClient = null;
}

function renderPaymentsModal() {
  const client = state.clients[state.payClient];
  if (!client) return;

  const total = totalFees(client);
  const paid = paymentsSum(client);
  const balance = balanceDue(client);
  const st = paymentStatus(client);

  $('#payments-modal-title').textContent = `Payments — ${client.companyName}`;
  $('#pay-summary').innerHTML = `
    <div class="pay-stat"><span>Total payable (${state.year})</span><b>${inr(total)}</b></div>
    <div class="pay-stat"><span>Received so far</span><b class="ok-text">${inr(paid)}</b></div>
    <div class="pay-stat"><span>Balance due</span><b class="${balance > 0 ? 'due-text' : 'ok-text'}">${inr(balance)}</b></div>
    <div class="pay-stat"><span>Status</span>${renderPaymentPill(client)}</div>
    ${st !== 'Paid' && total > 0
      ? `<p class="pay-note-line">The client is marked <b>Paid</b> automatically once recorded payments cover the total.</p>`
      : ''}`;

  const entries = paymentEntries(client).reverse(); // newest first
  $('#pay-history-empty').hidden = entries.length > 0;
  $('#pay-history').innerHTML = entries.map(([payId, p]) => {
    const d = p.ts ? new Date(p.ts).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
    return `
      <li>
        <span class="pay-amt">${inr(p.amount)}</span>
        <span class="pay-meta">${esc(d)}${p.note ? ` · ${esc(p.note)}` : ''}</span>
        <button class="btn-icon danger" data-action="delete-payment"
                data-client="${esc(state.payClient)}" data-pay="${esc(payId)}"
                title="Delete this payment entry">🗑</button>
      </li>`;
  }).join('');
}

async function addPayment(e) {
  e.preventDefault();
  requireAdmin();
  const errEl = $('#pay-error');
  errEl.hidden = true;

  const client = state.clients[state.payClient];
  if (!client) return;
  const amount = toFee($('#pay-amount').value);
  const note = $('#pay-note').value.trim().slice(0, 200);
  if (amount <= 0) {
    errEl.textContent = 'Enter an amount greater than zero.';
    errEl.hidden = false;
    return;
  }

  try {
    const payId = uid('pay');
    const entry = { amount, ts: Date.now(), note };
    await dbPut(`clients/${state.payClient}/payments/${payId}`, entry);
    client.payments[payId] = entry;
    $('#payment-form').reset();
    renderPaymentsModal();
    renderAll();
    const st = paymentStatus(client);
    toast(st === 'Paid'
      ? `${inr(amount)} recorded — fees fully paid. 🎉`
      : `${inr(amount)} recorded — balance ${inr(balanceDue(client))}.`);
  } catch (err) {
    console.error(err);
    errEl.textContent = 'Could not record the payment. Check your connection.';
    errEl.hidden = false;
  }
}

async function deletePayment(clientId, payId) {
  requireAdmin();
  const client = state.clients[clientId];
  const p = client?.payments?.[payId];
  if (!p) return;
  if (!confirm(`Delete the ${inr(p.amount)} payment entry? Use this only to correct mistakes.`)) return;
  try {
    await dbDelete(`clients/${clientId}/payments/${payId}`);
    delete client.payments[payId];
    renderPaymentsModal();
    renderAll();
    toast('Payment entry deleted.');
  } catch (err) {
    console.error(err);
    toast('Could not delete the payment entry.', true);
  }
}

/* ============================================================================
   16 · USERS (admin)
============================================================================ */

function renderUserTable() {
  const entries = Object.entries(state.users).sort((a, b) => a[0].localeCompare(b[0]));

  $('#user-tbody').innerHTML = entries.map(([username, u]) => {
    const isSelf = username === state.session.username;
    return `
    <tr>
      <td class="cell-strong">${esc(username)}${isSelf ? ' <span class="cell-muted">(you)</span>' : ''}</td>
      <td>${esc(u.displayName || '—')}</td>
      <td><span class="role-badge ${u.role === 'staff' ? 'staff' : ''}" style="position:static">${esc(u.role)}</span></td>
      <td>
        <button class="btn-icon" data-action="reset-password" data-user="${esc(username)}" title="Reset password">🔑</button>
        ${isSelf ? '' : `<button class="btn-icon danger" data-action="delete-user" data-user="${esc(username)}" title="Delete user">🗑</button>`}
      </td>
    </tr>`;
  }).join('');
}

async function addUser(e) {
  e.preventDefault();
  requireAdmin();
  const errEl = $('#user-error');
  errEl.hidden = true;

  const username = safeKey($('#u-username').value.trim());
  const displayName = $('#u-display').value.trim();
  const password = $('#u-password').value;
  const role = $('#u-role').value === 'admin' ? 'admin' : 'staff';

  if (!/^[a-z0-9_\-.]{3,30}$/.test(username)) {
    errEl.textContent = 'Username must be 3–30 characters: letters, numbers, dot, dash or underscore.';
    errEl.hidden = false;
    return;
  }
  if (password.length < 8) {
    errEl.textContent = 'Password must be at least 8 characters.';
    errEl.hidden = false;
    return;
  }
  if (state.users[username]) {
    errEl.textContent = `A user named "${username}" already exists.`;
    errEl.hidden = false;
    return;
  }

  try {
    const record = {
      passwordHash: await credentialHash(username, password),
      role,
      displayName,
      createdAt: Date.now(),
    };
    await dbPut(`system/users/${username}`, record);
    state.users[username] = record;
    $('#user-form').reset();
    renderUserTable();
    toast(`User "${username}" created as ${role}.`);
  } catch (err) {
    console.error(err);
    errEl.textContent = 'Could not create the user. Check your connection and Firebase rules.';
    errEl.hidden = false;
  }
}

async function resetUserPassword(username) {
  requireAdmin();
  const u = state.users[username];
  if (!u) return;
  const pwd = prompt(`New password for "${username}" (minimum 8 characters):`);
  if (pwd === null) return;
  if (pwd.length < 8) { toast('Password must be at least 8 characters.', true); return; }
  try {
    const passwordHash = await credentialHash(username, pwd);
    await dbPatch(`system/users/${username}`, { passwordHash });
    state.users[username].passwordHash = passwordHash;
    toast(`Password reset for "${username}".`);
  } catch (err) {
    console.error(err);
    toast('Password reset failed.', true);
  }
}

async function deleteUser(username) {
  requireAdmin();
  const u = state.users[username];
  if (!u) return;
  if (username === state.session.username) { toast('You cannot delete your own account.', true); return; }
  const adminCount = Object.values(state.users).filter((x) => x.role === 'admin').length;
  if (u.role === 'admin' && adminCount <= 1) {
    toast('Cannot delete the last remaining admin.', true);
    return;
  }
  if (!confirm(`Delete user "${username}"? They will no longer be able to sign in.`)) return;
  try {
    await dbDelete(`system/users/${username}`);
    delete state.users[username];
    renderUserTable();
    toast('User deleted.');
  } catch (err) {
    console.error(err);
    toast('Could not delete the user.', true);
  }
}

/* ============================================================================
   17 · EXCEL — dynamic template + bulk upload (SheetJS)
============================================================================ */

function templateHeaders() {
  return [
    ...CLIENT_COLUMNS.map((c) => c.label),
    ...sortedTasks().map(([, t]) => t.name),
    'Others Description',
    'Others Fees',
  ];
}

function downloadTemplate() {
  requireAdmin();
  const headers = templateHeaders();
  const sample = {
    'Company Name': 'M/s Sample Traders Pvt Ltd',
    'Authorised Person': 'Rakesh Sharma',
    'Mobile Number': '9829000000',
    'City': 'Jaipur',
    'Email': 'accounts@sampletraders.in',
    'GSTIN': '08ABCDE1234F1Z5',
    'PAN': 'ABCDE1234F',
    'Others Description': 'ROC annual return',
    'Others Fees': 2500,
  };
  for (const [, t] of sortedTasks()) sample[t.name] = 'Pending';

  const ws = XLSX.utils.json_to_sheet([sample], { header: headers });
  ws['!cols'] = headers.map((h) => ({ wch: Math.max(16, h.length + 4) }));
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Clients');
  XLSX.writeFile(wb, 'CA_Task_Tracker_Template.xlsx');
  toast('Template downloaded — task statuses apply to the current period.');
}

const normHeader = (h) => String(h ?? '').trim().toLowerCase().replace(/[^a-z0-9]+/g, ' ');

async function handleBulkFile(file) {
  requireAdmin();
  const resultEl = $('#bulk-result');
  resultEl.hidden = false;
  resultEl.className = 'bulk-result ok';
  resultEl.textContent = 'Reading file…';

  try {
    const data = await file.arrayBuffer();
    const wb = XLSX.read(data, { type: 'array' });
    const ws = wb.Sheets[wb.SheetNames[0]];
    const rows = XLSX.utils.sheet_to_json(ws, { defval: '' });
    if (!rows.length) throw new Error('The first sheet contains no data rows.');

    const headerMap = {};
    for (const col of CLIENT_COLUMNS) headerMap[normHeader(col.label)] = { type: 'field', key: col.key };
    headerMap['mobile'] = { type: 'field', key: 'mobile' };
    headerMap['mobile no'] = { type: 'field', key: 'mobile' };
    headerMap['gst'] = { type: 'field', key: 'gstin' };
    headerMap['gst number'] = { type: 'field', key: 'gstin' };
    headerMap['gst no'] = { type: 'field', key: 'gstin' };
    headerMap['pan number'] = { type: 'field', key: 'pan' };
    headerMap['pan no'] = { type: 'field', key: 'pan' };
    headerMap['company pan'] = { type: 'field', key: 'pan' };
    headerMap['others description'] = { type: 'othersNote' };
    headerMap['others'] = { type: 'othersNote' };
    headerMap['others fees'] = { type: 'othersFees' };
    for (const [taskId, t] of sortedTasks()) headerMap[normHeader(t.name)] = { type: 'task', key: taskId };

    const existingNames = new Set(
      Object.values(state.clients).map((c) => c.companyName.trim().toLowerCase()));

    const importYear = new Date().getFullYear();
    let added = 0, skipped = 0;
    const problems = [];

    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const tasksMap = freshTaskMap();
      let othersNote = '', othersFees = 0;
      const plain = { companyName: '', authorisedPerson: '', mobile: '', city: '', email: '', gstin: '', pan: '' };

      for (const [rawHeader, rawValue] of Object.entries(row)) {
        const map = headerMap[normHeader(rawHeader)];
        if (!map) continue;
        const value = String(rawValue).trim();

        if (map.type === 'field')      plain[map.key] = value;
        if (map.type === 'othersNote') othersNote = value.slice(0, 300);
        if (map.type === 'othersFees') othersFees = toFee(value);
        if (map.type === 'task') {
          // Status columns apply to the CURRENT period of the current year.
          const canonical = TASK_STATUSES.find((s) => s.toLowerCase() === value.toLowerCase());
          if (canonical && canonical !== 'Pending') {
            const freq = validFrequency(state.masterTasks[map.key]?.frequency);
            const period = currentPeriodFor(freq, importYear) || 'Year';
            tasksMap[map.key].periods = { [importYear]: { [period]: canonical } };
          }
        }
      }

      if (!plain.companyName) {
        problems.push(`Row ${i + 2}: missing Company Name — skipped.`);
        skipped++; continue;
      }
      if (existingNames.has(plain.companyName.toLowerCase())) {
        problems.push(`Row ${i + 2}: "${plain.companyName}" already exists — skipped.`);
        skipped++; continue;
      }

      const clientId = uid('cl');
      const othersMap = (othersNote || othersFees > 0)
        ? { [uid('oth')]: { note: othersNote, fees: othersFees } }
        : {};
      const stored = {
        companyName: plain.companyName,
        authorisedPerson: plain.authorisedPerson,
        city: plain.city,
        gstin: plain.gstin.toUpperCase(),
        pan: plain.pan.toUpperCase(),
        mobile: await encryptField(plain.mobile),
        email:  await encryptField(plain.email),
        tasks: tasksMap,
        others: othersMap,
        payments: {},
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
      await dbPut(`clients/${clientId}`, stored);
      state.clients[clientId] = {
        ...stored,
        mobile: plain.mobile,
        email: plain.email,
        others: normalizeOthers(othersMap),
      };
      existingNames.add(plain.companyName.toLowerCase());
      added++;
    }

    renderAll();
    resultEl.className = 'bulk-result ' + (added ? 'ok' : 'err');
    resultEl.innerHTML =
      `<strong>${added}</strong> client(s) imported, <strong>${skipped}</strong> skipped.` +
      (problems.length ? `<br>${problems.map(esc).join('<br>')}` : '');
    if (added) toast(`Imported ${added} client(s).`);
  } catch (err) {
    console.error(err);
    resultEl.className = 'bulk-result err';
    resultEl.textContent = `Import failed: ${err.message}`;
  } finally {
    $('#bulk-file').value = '';
  }
}

/* ============================================================================
   18 · DELEGATED EVENTS
============================================================================ */

/** Persist a task node change: PUT the full normalised node. */
async function writeTaskNode(clientId, taskId, node) {
  await dbPut(`clients/${clientId}/tasks/${taskId}`, node);
  const c = state.clients[clientId];
  c.tasks = c.tasks || {};
  c.tasks[taskId] = node;
}

const nextStatus = (s) =>
  s === 'Pending' ? 'Completed' : s === 'Completed' ? 'Not Applicable' : 'Pending';

document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-action]');
  if (!btn || btn.tagName === 'SELECT' || btn.tagName === 'INPUT') return;
  const a = btn.dataset.action;

  try {
    if (a === 'toggle-expand') {
      const id = btn.dataset.client;
      state.expanded.has(id) ? state.expanded.delete(id) : state.expanded.add(id);
      renderClientTable();
    }
    if (a === 'cycle-period') {
      // Both roles may update period statuses.
      const { client, task, period } = btn.dataset;
      const year = state.year;
      const cur = periodStatus(state.clients[client], task, year, period);
      const next = nextStatus(cur);
      const node = taskNode(state.clients[client], task);
      node.periods = node.periods || {};
      node.periods[year] = node.periods[year] || {};
      node.periods[year][period] = next;
      await writeTaskNode(client, task, node);
      renderAll();
    }
    if (a === 'add-others') {
      requireAdmin();
      const clientId = btn.dataset.client;
      const entryId = uid('oth');
      const blank = { note: '', fees: 0 };
      await dbPut(`clients/${clientId}/others/${entryId}`, blank);
      state.clients[clientId].others[entryId] = blank;
      renderClientTable();
      toast('New "Others" line added.');
    }
    if (a === 'remove-others') {
      requireAdmin();
      const { client, entry } = btn.dataset;
      await dbDelete(`clients/${client}/others/${entry}`);
      delete state.clients[client].others[entry];
      state.clients[client].others = normalizeOthers(state.clients[client].others);
      renderAll();
      toast('"Others" line removed.');
    }
    if (a === 'open-payments')  openPaymentsModal(btn.dataset.client);
    if (a === 'delete-payment') deletePayment(btn.dataset.client, btn.dataset.pay);
    if (a === 'edit-client')    openClientModal(btn.dataset.client);
    if (a === 'delete-client')  deleteClient(btn.dataset.client);
    if (a === 'delete-task')    deleteMasterTask(btn.dataset.task);
    if (a === 'reset-password') resetUserPassword(btn.dataset.user);
    if (a === 'delete-user')    deleteUser(btn.dataset.user);
  } catch (err) {
    console.error(err);
    if (!String(err.message).startsWith('RBAC')) toast('Action failed — check your connection.', true);
  }
});

document.addEventListener('change', async (e) => {
  const el = e.target;
  if (!(el instanceof HTMLSelectElement) && !(el instanceof HTMLInputElement)) return;
  const a = el.dataset.action;
  if (!a) return;

  try {
    if (a === 'set-task-fees') {
      requireAdmin();
      const { client, task } = el.dataset;
      const node = taskNode(state.clients[client], task);
      node.fees = toFee(el.value);
      await writeTaskNode(client, task, node);
      renderAll();
      toast(`Fee saved: ${inr(node.fees)} per filing.`);
    }
    if (a === 'set-others-note') {
      requireAdmin();
      const { client, entry } = el.dataset;
      const note = el.value.trim().slice(0, 300);
      const cur = state.clients[client].others[entry] || { note: '', fees: 0 };
      cur.note = note;
      await dbPut(`clients/${client}/others/${entry}`, cur);
      state.clients[client].others[entry] = cur;
      toast('Others description saved.');
    }
    if (a === 'set-others-fees') {
      requireAdmin();
      const { client, entry } = el.dataset;
      const fees = toFee(el.value);
      const cur = state.clients[client].others[entry] || { note: '', fees: 0 };
      cur.fees = fees;
      await dbPut(`clients/${client}/others/${entry}`, cur);
      state.clients[client].others[entry] = cur;
      renderAll();
      toast(`Others fee saved: ${inr(fees)}.`);
    }
    if (a === 'set-default-fees') {
      requireAdmin();
      const { task } = el.dataset;
      const defaultFees = toFee(el.value);
      await dbPatch(`masterTasks/${task}`, { defaultFees });
      state.masterTasks[task].defaultFees = defaultFees;
      renderAll();
      toast(`Default fee for "${state.masterTasks[task].name}" is now ${inr(defaultFees)} per filing.`);
    }
  } catch (err) {
    console.error(err);
    if (!String(err.message).startsWith('RBAC')) toast('Update failed — check your connection.', true);
    renderAll();
  }
});

/* ============================================================================
   19 · EVENT WIRING & STARTUP
============================================================================ */

function wireEvents() {
  // --- Login ---
  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#login-btn');
    const errEl = $('#login-error');
    errEl.hidden = true;
    btn.disabled = true;
    btn.textContent = 'Signing in…';
    try {
      await login($('#login-username').value, $('#login-password').value);
      await loadAllData();
      enterApp();
    } catch (err) {
      console.error(err);
      errEl.textContent = err.message.includes('Invalid')
        ? 'Invalid username or password.'
        : 'Could not reach the database. Check your connection and Firebase rules.';
      errEl.hidden = false;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
  });

  $('#logout-btn').addEventListener('click', logout);

  // --- Year selection (header) ---
  $('#year-select').addEventListener('change', (e) => {
    state.year = parseInt(e.target.value, 10) || new Date().getFullYear();
    renderAll();
    toast(`Now showing ${state.year}.`);
  });

  // --- Navigation ---
  $$('.nav-item').forEach((btn) =>
    btn.addEventListener('click', () => showView(btn.dataset.view)));

  // --- Dashboard filters ---
  $('#dash-search').addEventListener('input', renderDashboardTable);
  $('#dash-filter-task').addEventListener('change', renderDashboardTable);
  $('#dash-filter-status').addEventListener('change', renderDashboardTable);

  // --- Clients ---
  $('#client-search').addEventListener('input', renderClientTable);
  $('#open-add-client').addEventListener('click', () => openClientModal());
  $('#client-form').addEventListener('submit', saveClientFromModal);
  $('#client-cancel').addEventListener('click', closeClientModal);
  $('#client-modal-close').addEventListener('click', closeClientModal);
  $('#client-modal').addEventListener('click', (e) => {
    if (e.target === $('#client-modal')) closeClientModal();
  });

  // --- Payments modal ---
  $('#payment-form').addEventListener('submit', addPayment);
  $('#payments-modal-close').addEventListener('click', closePaymentsModal);
  $('#payments-modal').addEventListener('click', (e) => {
    if (e.target === $('#payments-modal')) closePaymentsModal();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (!$('#client-modal').hidden) closeClientModal();
    if (!$('#payments-modal').hidden) closePaymentsModal();
  });

  // --- Master tasks ---
  $('#task-form').addEventListener('submit', addMasterTask);

  // --- Users ---
  $('#user-form').addEventListener('submit', addUser);

  // --- Bulk upload ---
  $('#download-template').addEventListener('click', downloadTemplate);
  const dz = $('#dropzone');
  const fileInput = $('#bulk-file');
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) handleBulkFile(fileInput.files[0]);
  });
  ['dragover', 'dragenter'].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('dragover'); }));
  ['dragleave', 'drop'].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('dragover'); }));
  dz.addEventListener('drop', (e) => {
    const file = e.dataTransfer.files?.[0];
    if (file) handleBulkFile(file);
  });
}

function startAutoRefresh() {
  setInterval(async () => {
    if (!state.session) return;
    if (!$('#payments-modal').hidden || !$('#client-modal').hidden) return; // don't refresh under a modal
    if (document.activeElement && document.activeElement.matches('input, select, textarea')) return;
    try {
      await loadAllData();
      renderAll();
    } catch { /* transient network issue */ }
  }, 60000);
}

async function init() {
  wireEvents();
  state.piiKey = await derivePiiKey();

  if (restoreSession()) {
    try {
      await loadAllData();
      enterApp();
    } catch (err) {
      console.error(err);
      logout();
    }
  }
  startAutoRefresh();
}

init();
