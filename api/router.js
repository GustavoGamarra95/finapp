import { createClient } from '@libsql/client';
import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const CATEGORIES = ['Comida', 'Transporte', 'Servicios', 'Vivienda', 'Salud', 'Ocio', 'Otro'];

const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI || '';
const GOOGLE_SCOPES = 'openid email https://www.googleapis.com/auth/calendar.events';

const db = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:./finapp.db',
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// ============ Utilidades ============
const uid      = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
const todayStr = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
const ymOf      = d => d.slice(0, 7);
const currentYm = () => todayStr().slice(0, 7);
function prevYm() {
  const [y, m] = currentYm().split('-').map(Number);
  const dt = new Date(y, m - 2, 1);
  return `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}`;
}
const daysBetween = (a, b) => Math.round((new Date(b + 'T00:00:00') - new Date(a + 'T00:00:00')) / 86400000);
const b64u    = s => Buffer.from(s).toString('base64url');
const b64uDec = s => Buffer.from(s, 'base64url').toString();

class HttpErr extends Error { constructor(status, message) { super(message); this.statusCode = status; } }

// ============ JWT HS256 mínimo ============
// ponytail: HMAC hand-rolled, ~15 líneas vs +1 dep (jsonwebtoken).
function jwtSign(payload) {
  const h = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = b64u(JSON.stringify(payload));
  const sig = createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${sig}`;
}
function jwtVerify(token) {
  if (!token) return null;
  const [h, p, sig] = token.split('.');
  if (!h || !p || !sig) return null;
  const expected = createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64url');
  const a = Buffer.from(sig, 'base64url'), b = Buffer.from(expected, 'base64url');
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(b64uDec(p));
    if (payload.exp && payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch { return null; }
}
function requireAuth(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  const payload = jwtVerify(token);
  if (!payload || !payload.sub) throw new HttpErr(401, 'unauthorized');
  return payload.sub;
}

// ============ Bootstrap (idempotente, corre en cold start) ============
let bootstrapped = false;
async function ensureBootstrap() {
  if (bootstrapped) return;
  await db.batch([
    `CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      email    TEXT NOT NULL,
      created  INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS expenses (
      id       TEXT PRIMARY KEY,
      username TEXT NOT NULL REFERENCES users(username),
      date     TEXT NOT NULL,
      descr    TEXT NOT NULL,
      category TEXT NOT NULL,
      amount   INTEGER NOT NULL CHECK (amount > 0)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_expenses_user_date ON expenses(username, date)`,
    `CREATE TABLE IF NOT EXISTS debts (
      id           TEXT PRIMARY KEY,
      username     TEXT NOT NULL REFERENCES users(username),
      creditor     TEXT NOT NULL,
      amount       INTEGER NOT NULL CHECK (amount > 0),
      due          TEXT NOT NULL,
      installments TEXT,
      cuota_amount INTEGER
    )`,
    `CREATE INDEX IF NOT EXISTS idx_debts_user ON debts(username)`,
    `CREATE TABLE IF NOT EXISTS payments (
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      debt_id TEXT NOT NULL REFERENCES debts(id) ON DELETE CASCADE,
      date    TEXT NOT NULL,
      amount  INTEGER NOT NULL CHECK (amount > 0),
      cuota_n INTEGER
    )`,
    `CREATE INDEX IF NOT EXISTS idx_payments_debt ON payments(debt_id)`,
    `CREATE TABLE IF NOT EXISTS budgets (
      username TEXT PRIMARY KEY REFERENCES users(username),
      overall  INTEGER NOT NULL DEFAULT 0,
      cats     TEXT NOT NULL DEFAULT '{}'
    )`,
    `CREATE TABLE IF NOT EXISTS google_tokens (
      username      TEXT PRIMARY KEY REFERENCES users(username),
      email         TEXT NOT NULL,
      access_token  TEXT NOT NULL,
      refresh_token TEXT,
      expires_at    INTEGER NOT NULL,
      calendar_id   TEXT NOT NULL DEFAULT 'primary'
    )`,
    `CREATE TABLE IF NOT EXISTS debt_events (
      debt_id  TEXT NOT NULL REFERENCES debts(id) ON DELETE CASCADE,
      cuota_n  INTEGER NOT NULL,
      event_id TEXT NOT NULL,
      PRIMARY KEY (debt_id, cuota_n)
    )`,
  ], 'write');
  // ponytail: migraciones idempotentes para instalaciones legacy.
  try { await db.execute('ALTER TABLE payments ADD COLUMN cuota_n INTEGER'); } catch {}
  try { await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_debt_cuota ON payments(debt_id, cuota_n) WHERE cuota_n IS NOT NULL'); } catch {}
  try { await db.execute('ALTER TABLE debts ADD COLUMN cuota_amount INTEGER'); } catch {}
  bootstrapped = true;
}

// ============ Reglas de negocio ============
function debtStatus(remaining, due) {
  if (remaining === 0) return { level: 'paid', label: 'Pagada' };
  const days = daysBetween(todayStr(), due);
  if (days < 0)   return { level: 'overdue', days, label: `Vencida hace ${-days}d` };
  if (days === 0) return { level: 'urgent',  days, label: 'Vence hoy' };
  if (days <= 7)  return { level: 'soon',    days, label: `Vence en ${days}d` };
  return { level: 'ok', days, label: `Vence en ${days}d` };
}
function budgetLevel(used, limit) {
  if (limit === 0) return { level: 'none', pct: 0, label: 'sin objetivo definido' };
  const pct = Math.min(100, (used / limit) * 100);
  if (used >= limit)       return { level: 'exceeded', pct, label: 'Superaste el objetivo' };
  if (used >= limit * 0.8) return { level: 'warn',     pct, label: 'Cerca del límite' };
  return { level: 'ok', pct, label: `${pct.toFixed(0)}% usado` };
}
function validateExpense(b) {
  if (!b || typeof b !== 'object') throw new HttpErr(400, 'invalid body');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(b.date || '')) throw new HttpErr(400, 'date requerido (YYYY-MM-DD)');
  const desc = String(b.desc || '').trim().slice(0, 80);
  if (!desc) throw new HttpErr(400, 'desc requerido');
  const category = CATEGORIES.includes(b.category) ? b.category : 'Otro';
  const amount = Math.floor(Number(b.amount));
  if (!(amount > 0)) throw new HttpErr(400, 'amount debe ser positivo');
  return { date: b.date, desc, category, amount };
}
function validateDebt(b) {
  if (!b || typeof b !== 'object') throw new HttpErr(400, 'invalid body');
  const creditor = String(b.creditor || '').trim().slice(0, 60);
  if (!creditor) throw new HttpErr(400, 'creditor requerido');
  const amount = Math.floor(Number(b.amount));
  if (!(amount > 0)) throw new HttpErr(400, 'amount debe ser positivo');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(b.due || '')) throw new HttpErr(400, 'due requerido (YYYY-MM-DD)');
  const installments = b.installments ? String(b.installments).trim().slice(0, 12) || null : null;
  const cuota_amount = b.cuota_amount == null || b.cuota_amount === '' ? null : Math.floor(Number(b.cuota_amount));
  if (cuota_amount !== null && !(cuota_amount > 0)) throw new HttpErr(400, 'cuota_amount inválido');
  return { creditor, amount, due: b.due, installments, cuota_amount };
}
function validatePayment(b, remaining) {
  if (!b || typeof b !== 'object') throw new HttpErr(400, 'invalid body');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(b.date || '')) throw new HttpErr(400, 'date requerido');
  const amount = Math.floor(Number(b.amount));
  if (!(amount > 0)) throw new HttpErr(400, 'amount debe ser positivo');
  if (amount > remaining) throw new HttpErr(400, 'monto excede lo pendiente');
  const cuota_n = b.cuota_n == null || b.cuota_n === '' ? null : Math.floor(Number(b.cuota_n));
  if (cuota_n !== null && !(cuota_n > 0)) throw new HttpErr(400, 'cuota_n inválido');
  return { date: b.date, amount, cuota_n };
}

// ============ View builder ============
async function buildView(username, filters = {}) {
  const curYm = currentYm();
  const prevY = prevYm();
  const q     = String(filters.q || '').trim().toLowerCase();
  const cat   = filters.cat || '';
  const from  = filters.from || '';
  const to    = filters.to || '';

  const [expRes, debtsRes, paysRes, budgetRes, gRes] = await Promise.all([
    db.execute({ sql: 'SELECT id, date, descr AS "desc", category, amount FROM expenses WHERE username = ?', args: [username] }),
    db.execute({ sql: 'SELECT id, creditor, amount, due, installments, cuota_amount FROM debts WHERE username = ?', args: [username] }),
    db.execute({ sql: 'SELECT p.id, p.debt_id, p.date, p.amount, p.cuota_n FROM payments p JOIN debts d ON d.id = p.debt_id WHERE d.username = ? ORDER BY p.date DESC, p.id DESC', args: [username] }),
    db.execute({ sql: 'SELECT overall, cats FROM budgets WHERE username = ?', args: [username] }),
    db.execute({ sql: 'SELECT email FROM google_tokens WHERE username = ?', args: [username] }),
  ]);
  const allExpenses = expRes.rows.map(r => ({ id: r.id, date: r.date, desc: r.desc, category: r.category, amount: Number(r.amount) }));

  let filtered = allExpenses;
  if (q)    filtered = filtered.filter(e => e.desc.toLowerCase().includes(q) || e.category.toLowerCase().includes(q));
  if (cat)  filtered = filtered.filter(e => e.category === cat);
  if (from) filtered = filtered.filter(e => e.date >= from);
  if (to)   filtered = filtered.filter(e => e.date <= to);
  filtered.sort((a, b) => b.date.localeCompare(a.date) || b.id.localeCompare(a.id));

  const grouped = {};
  for (const e of filtered) {
    const m = ymOf(e.date);
    (grouped[m] ||= { month: m, sum: 0, items: [] });
    grouped[m].items.push(e);
    grouped[m].sum += e.amount;
  }
  const groups = Object.values(grouped).sort((a, b) => b.month.localeCompare(a.month));

  const monthSum = allExpenses.filter(e => e.date.startsWith(curYm)).reduce((s, e) => s + e.amount, 0);
  const prevSum  = allExpenses.filter(e => e.date.startsWith(prevY)).reduce((s, e) => s + e.amount, 0);
  const now = new Date();
  const day = now.getDate();
  const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
  const avg = day > 0 ? monthSum / day : 0;
  const projection = avg * daysInMonth;

  const delta = prevSum > 0
    ? (() => {
        const pct = ((monthSum - prevSum) / prevSum) * 100;
        return { pct, prevSum, label: `${pct >= 0 ? '+' : ''}${pct.toFixed(1)}% que el mes anterior` };
      })()
    : { pct: null, prevSum: 0, label: monthSum > 0 ? 'Sin gastos en el mes anterior' : 'Aún sin datos' };

  const paysByDebt = {};
  for (const p of paysRes.rows) (paysByDebt[p.debt_id] ||= []).push({ id: Number(p.id), date: p.date, amount: Number(p.amount), cuota_n: p.cuota_n == null ? null : Number(p.cuota_n) });
  const debts = debtsRes.rows.map(d => {
    const amount = Number(d.amount);
    const pays = paysByDebt[d.id] || [];
    const paid = pays.reduce((s, p) => s + p.amount, 0);
    const remaining = Math.max(0, amount - paid);
    return {
      id: d.id, creditor: d.creditor, amount, due: d.due, installments: d.installments,
      cuota_amount: d.cuota_amount == null ? null : Number(d.cuota_amount),
      payments: pays, paid, remaining,
      pctPaid: amount > 0 ? (paid / amount) * 100 : 100,
      status: debtStatus(remaining, d.due),
    };
  }).sort((a, b) => {
    if ((a.remaining === 0) !== (b.remaining === 0)) return a.remaining === 0 ? 1 : -1;
    return a.due.localeCompare(b.due);
  });
  const activeDebts = debts.filter(d => d.remaining > 0);
  const debtTotal = activeDebts.reduce((s, d) => s + d.remaining, 0);
  const upcoming = activeDebts.slice().sort((a, b) => a.due.localeCompare(b.due)).slice(0, 5);

  const bRow = budgetRes.rows[0] || { overall: 0, cats: '{}' };
  const overall = Number(bRow.overall) || 0;
  const bCats = JSON.parse(bRow.cats || '{}');
  const overallStatus = budgetLevel(monthSum, overall);
  const byCat = {};
  for (const e of allExpenses.filter(e => e.date.startsWith(curYm))) {
    byCat[e.category] = (byCat[e.category] || 0) + e.amount;
  }
  const budgetCategories = CATEGORIES.map(c => {
    const limit = bCats[c] || 0;
    const used  = byCat[c] || 0;
    const s = budgetLevel(used, limit);
    return { cat: c, limit, used, pct: s.pct, level: s.level, label: s.label };
  });
  const categoryChart = Object.entries(byCat).sort((a, b) => b[1] - a[1]).map(([cat, amount]) => ({ cat, amount }));

  const trend = [];
  for (let i = 5; i >= 0; i--) {
    const dt = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const monthYm = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}`;
    const value = allExpenses.filter(e => e.date.startsWith(monthYm)).reduce((s, e) => s + e.amount, 0);
    trend.push({ ym: monthYm, label: dt.toLocaleDateString('es-PY', { month: 'short' }), value });
  }

  return {
    session:    { username },
    today:      todayStr(),
    ym:         curYm,
    categories: CATEGORIES,
    filters:    { q, cat, from, to },
    dashboard: {
      monthSum, delta, avg, projection, daysInMonth,
      debtTotal, debtCount: activeDebts.length,
      budget: { overall, used: monthSum, pctUsed: overallStatus.pct, status: overallStatus },
      categoryChart, trend, upcoming,
    },
    expenses: { groups, flat: filtered, filteredCount: filtered.length, totalCount: allExpenses.length },
    debts,
    budgets: { overall, categories: budgetCategories },
    google: { connected: gRes.rows.length > 0, email: gRes.rows[0]?.email || null, configured: !!GOOGLE_CLIENT_ID },
  };
}

// ============ Google OAuth + Calendar ============
function parseCookies(req) {
  const out = {};
  for (const p of (req.headers.cookie || '').split(';')) {
    const [k, ...v] = p.trim().split('=');
    if (k) out[k] = decodeURIComponent(v.join('='));
  }
  return out;
}
function decodeIdToken(idToken) {
  // ponytail: token viene por HTTPS directo desde Google, se confía en payload sin verificar firma.
  const [, payload] = idToken.split('.');
  if (!payload) return {};
  try { return JSON.parse(b64uDec(payload)); } catch { return {}; }
}
async function exchangeCode(code) {
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI, grant_type: 'authorization_code',
    }),
  });
  if (!r.ok) throw new HttpErr(400, `google token exchange failed: ${await r.text()}`);
  return r.json();
}
async function refreshAccessToken(refreshToken) {
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      refresh_token: refreshToken, client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET, grant_type: 'refresh_token',
    }),
  });
  if (!r.ok) return null;
  return r.json();
}
async function getValidAccessToken(username) {
  const r = await db.execute({ sql: 'SELECT access_token, refresh_token, expires_at, calendar_id FROM google_tokens WHERE username = ?', args: [username] });
  if (r.rows.length === 0) return null;
  const row = r.rows[0];
  const now = Math.floor(Date.now() / 1000);
  if (Number(row.expires_at) - 60 > now) return { access_token: row.access_token, calendar_id: row.calendar_id };
  if (!row.refresh_token) return null;
  const refreshed = await refreshAccessToken(row.refresh_token);
  if (!refreshed || !refreshed.access_token) return null;
  const newExp = now + Number(refreshed.expires_in || 3600);
  await db.execute({
    sql: 'UPDATE google_tokens SET access_token = ?, expires_at = ? WHERE username = ?',
    args: [refreshed.access_token, newExp, username],
  });
  return { access_token: refreshed.access_token, calendar_id: row.calendar_id };
}
const parseInstallments = (s) => {
  const n = parseInt(String(s || '').trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : 1;
};
const addMonthsIso = (dateStr, add) => {
  const [y, m, d] = dateStr.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1 + add, d));
  return `${dt.getUTCFullYear()}-${String(dt.getUTCMonth() + 1).padStart(2, '0')}-${String(dt.getUTCDate()).padStart(2, '0')}`;
};
const nextDayIso = (dateStr) => {
  const [y, m, d] = dateStr.split('-').map(Number);
  const nd = new Date(Date.UTC(y, m - 1, d + 1));
  return `${nd.getUTCFullYear()}-${String(nd.getUTCMonth() + 1).padStart(2, '0')}-${String(nd.getUTCDate()).padStart(2, '0')}`;
};
function cuotaAmountFor(debt, n, N) {
  const per = debt.cuota_amount && debt.cuota_amount > 0 ? debt.cuota_amount : Math.round(debt.amount / N);
  return n < N ? per : Math.max(0, debt.amount - per * (N - 1));
}
function paidCuotasSet(debt) {
  const N = parseInstallments(debt.installments);
  const tagged = new Set(Object.keys(debt.taggedByCuota || {}).map(Number).filter(n => n >= 1 && n <= N));
  let taggedSum = 0;
  for (const n of tagged) taggedSum += Number(debt.taggedByCuota[n]);
  let pool = Math.max(0, debt.paid - taggedSum);
  const paid = new Set(tagged);
  for (let n = 1; n <= N; n++) {
    if (paid.has(n)) continue;
    const cost = cuotaAmountFor(debt, n, N);
    if (pool >= cost) { paid.add(n); pool -= cost; }
  }
  return paid;
}
function cuotaEventBody(debt, n, N, isPaid) {
  const cuotaAmount = cuotaAmountFor(debt, n, N);
  const cuotaDue = addMonthsIso(debt.due, n - 1);
  const label = N > 1 ? `Cuota ${n}/${N}` : 'Deuda';
  return {
    summary: `${isPaid ? '✅ ' : '💰 '}${label} ${debt.creditor} — Gs ${cuotaAmount.toLocaleString('es-PY')}`,
    description: `Total: Gs ${debt.amount.toLocaleString('es-PY')}\nPagado: Gs ${debt.paid.toLocaleString('es-PY')}\nPendiente: Gs ${debt.remaining.toLocaleString('es-PY')}${N > 1 ? `\nCuota: ${n} de ${N}${isPaid ? ' · pagada' : ''}` : ''}`,
    start: { date: cuotaDue },
    end:   { date: nextDayIso(cuotaDue) },
    reminders: { useDefault: false, overrides: isPaid ? [] : [
      { method: 'popup', minutes: 24 * 60 },
      { method: 'popup', minutes: 60 },
    ] },
    transparency: isPaid ? 'transparent' : 'opaque',
  };
}
async function calendarFetch(access, calendarId, path, opts = {}) {
  return fetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events${path}`, {
    ...opts,
    headers: { authorization: `Bearer ${access}`, 'content-type': 'application/json', ...(opts.headers || {}) },
  });
}
async function syncDebtEvent(username, debt) {
  const tok = await getValidAccessToken(username);
  if (!tok) return;
  const N = parseInstallments(debt.installments);
  const paidSet = paidCuotasSet(debt);
  const existing = await db.execute({ sql: 'SELECT cuota_n, event_id FROM debt_events WHERE debt_id = ?', args: [debt.id] });
  const byN = new Map(existing.rows.map(r => [Number(r.cuota_n), r.event_id]));

  for (let n = 1; n <= N; n++) {
    const body = JSON.stringify(cuotaEventBody(debt, n, N, paidSet.has(n)));
    try {
      if (byN.has(n)) {
        const eid = byN.get(n);
        const r = await calendarFetch(tok.access_token, tok.calendar_id, `/${encodeURIComponent(eid)}`, { method: 'PUT', body });
        if (r.status === 404) {
          await db.execute({ sql: 'DELETE FROM debt_events WHERE debt_id = ? AND cuota_n = ?', args: [debt.id, n] });
          const r2 = await calendarFetch(tok.access_token, tok.calendar_id, '', { method: 'POST', body });
          if (r2.ok) {
            const ev = await r2.json();
            await db.execute({ sql: 'INSERT INTO debt_events (debt_id, cuota_n, event_id) VALUES (?, ?, ?)', args: [debt.id, n, ev.id] });
          } else {
            console.error('calendar POST failed cuota', n, r2.status, (await r2.text()).slice(0, 200));
          }
        } else if (!r.ok) {
          console.error('calendar PUT failed cuota', n, r.status, (await r.text()).slice(0, 200));
        }
      } else {
        const r = await calendarFetch(tok.access_token, tok.calendar_id, '', { method: 'POST', body });
        if (r.ok) {
          const ev = await r.json();
          await db.execute({ sql: 'INSERT INTO debt_events (debt_id, cuota_n, event_id) VALUES (?, ?, ?)', args: [debt.id, n, ev.id] });
        } else {
          console.error('calendar POST failed cuota', n, r.status, (await r.text()).slice(0, 200));
        }
      }
    } catch (e) {
      console.error('calendar sync failed cuota', n, e.message);
    }
  }

  // Cuotas de más (usuario redujo N): borrar en Calendar y DB.
  for (const [n, eid] of byN) {
    if (n <= N) continue;
    try {
      await calendarFetch(tok.access_token, tok.calendar_id, `/${encodeURIComponent(eid)}`, { method: 'DELETE' });
    } catch (e) { console.error('calendar delete extra cuota', n, e.message); }
    await db.execute({ sql: 'DELETE FROM debt_events WHERE debt_id = ? AND cuota_n = ?', args: [debt.id, n] });
  }
}
async function removeDebtEvent(username, debtId) {
  const tok = await getValidAccessToken(username);
  if (!tok) return;
  const r = await db.execute({ sql: 'SELECT event_id FROM debt_events WHERE debt_id = ?', args: [debtId] });
  for (const row of r.rows) {
    try {
      await calendarFetch(tok.access_token, tok.calendar_id, `/${encodeURIComponent(row.event_id)}`, { method: 'DELETE' });
    } catch (e) { console.error('calendar delete failed:', e.message); }
  }
  await db.execute({ sql: 'DELETE FROM debt_events WHERE debt_id = ?', args: [debtId] });
}
async function fetchDebtForSync(debtId, username) {
  const [dR, pR] = await Promise.all([
    db.execute({ sql: 'SELECT id, creditor, amount, due, installments, cuota_amount FROM debts WHERE id = ? AND username = ?', args: [debtId, username] }),
    db.execute({ sql: 'SELECT amount, cuota_n FROM payments WHERE debt_id = ?', args: [debtId] }),
  ]);
  if (dR.rows.length === 0) return null;
  const d = dR.rows[0];
  const amount = Number(d.amount);
  let paid = 0;
  const taggedByCuota = {};
  for (const p of pR.rows) {
    paid += Number(p.amount);
    if (p.cuota_n != null) taggedByCuota[Number(p.cuota_n)] = Number(p.amount);
  }
  return { id: d.id, creditor: d.creditor, amount, due: d.due, installments: d.installments, cuota_amount: d.cuota_amount == null ? null : Number(d.cuota_amount), paid, remaining: Math.max(0, amount - paid), taggedByCuota };
}

// ============ Handler Vercel ============
export default async function handler(req, res) {
  try {
    await ensureBootstrap();
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    const m = req.method;
    const q = Object.fromEntries(url.searchParams);
    const body = req.body || {};

    // Google OAuth público
    if (m === 'GET' && p === '/api/auth/google/start') {
      if (!GOOGLE_CLIENT_ID) throw new HttpErr(500, 'Google OAuth no configurado');
      const state = randomBytes(16).toString('hex');
      const auth = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      auth.searchParams.set('client_id', GOOGLE_CLIENT_ID);
      auth.searchParams.set('redirect_uri', GOOGLE_REDIRECT_URI);
      auth.searchParams.set('response_type', 'code');
      auth.searchParams.set('scope', GOOGLE_SCOPES);
      auth.searchParams.set('access_type', 'offline');
      auth.searchParams.set('prompt', 'consent');
      auth.searchParams.set('state', state);
      res.setHeader('Set-Cookie', `oauth_state=${state}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`);
      res.writeHead(302, { Location: auth.toString() });
      return res.end();
    }
    if (m === 'GET' && p === '/api/auth/google/callback') {
      const cookies = parseCookies(req);
      const stateCookie = cookies.oauth_state || '';
      const state = q.state || '';
      if (!state || state !== stateCookie) throw new HttpErr(400, 'state inválido');
      if (!q.code) throw new HttpErr(400, 'code faltante');
      const tokens = await exchangeCode(q.code);
      const idPayload = decodeIdToken(tokens.id_token || '');
      const email = (idPayload.email || '').toLowerCase();
      if (!email || !idPayload.email_verified) throw new HttpErr(403, 'email no verificado');
      const username = email;
      const now = Math.floor(Date.now() / 1000);
      await db.execute({
        sql: `INSERT INTO users (username, email, created) VALUES (?, ?, ?)
              ON CONFLICT(username) DO UPDATE SET email = excluded.email`,
        args: [username, email, now],
      });
      const expiresAt = now + Number(tokens.expires_in || 3600);
      await db.execute({
        sql: `INSERT INTO google_tokens (username, email, access_token, refresh_token, expires_at, calendar_id)
              VALUES (?, ?, ?, ?, ?, 'primary')
              ON CONFLICT(username) DO UPDATE SET email = excluded.email, access_token = excluded.access_token,
                refresh_token = COALESCE(excluded.refresh_token, google_tokens.refresh_token),
                expires_at = excluded.expires_at`,
        args: [username, email, tokens.access_token, tokens.refresh_token || null, expiresAt],
      });
      const jwtExp = Math.floor(Date.now() / 1000) + 30 * 86400;
      const token = jwtSign({ sub: username, exp: jwtExp });
      // Sync inicial de deudas activas
      const debtsR = await db.execute({ sql: 'SELECT id FROM debts WHERE username = ?', args: [username] });
      for (const row of debtsR.rows) {
        const d = await fetchDebtForSync(row.id, username);
        if (d) await syncDebtEvent(username, d);
      }
      res.setHeader('Set-Cookie', 'oauth_state=; Path=/; Max-Age=0');
      res.writeHead(302, { Location: `/?token=${encodeURIComponent(token)}&user=${encodeURIComponent(username)}` });
      return res.end();
    }

    // Auth requerido
    const user = requireAuth(req);
    const sendView = async () => res.status(200).json(await buildView(user, q));

    if (m === 'GET' && p === '/api/view') return sendView();

    if (m === 'POST' && p === '/api/expenses') {
      const e = validateExpense(body);
      await db.execute({
        sql: 'INSERT INTO expenses (id, username, date, descr, category, amount) VALUES (?, ?, ?, ?, ?, ?)',
        args: [uid(), user, e.date, e.desc, e.category, e.amount],
      });
      return sendView();
    }
    let mm = p.match(/^\/api\/expenses\/([^/]+)$/);
    if (mm && m === 'PUT') {
      const e = validateExpense(body);
      const r = await db.execute({
        sql: 'UPDATE expenses SET date = ?, descr = ?, category = ?, amount = ? WHERE id = ? AND username = ?',
        args: [e.date, e.desc, e.category, e.amount, mm[1], user],
      });
      if (r.rowsAffected === 0) throw new HttpErr(404, 'gasto no encontrado');
      return sendView();
    }
    if (mm && m === 'DELETE') {
      await db.execute({ sql: 'DELETE FROM expenses WHERE id = ? AND username = ?', args: [mm[1], user] });
      return sendView();
    }

    if (m === 'POST' && p === '/api/debts') {
      const d = validateDebt(body);
      const newId = uid();
      await db.execute({
        sql: 'INSERT INTO debts (id, username, creditor, amount, due, installments, cuota_amount) VALUES (?, ?, ?, ?, ?, ?, ?)',
        args: [newId, user, d.creditor, d.amount, d.due, d.installments, d.cuota_amount],
      });
      const dSync = await fetchDebtForSync(newId, user);
      if (dSync) await syncDebtEvent(user, dSync);
      return sendView();
    }
    mm = p.match(/^\/api\/debts\/([^/]+)$/);
    if (mm && m === 'PUT') {
      const d = validateDebt(body);
      const own = await db.execute({ sql: 'SELECT amount FROM debts WHERE id = ? AND username = ?', args: [mm[1], user] });
      if (own.rows.length === 0) throw new HttpErr(404, 'deuda no encontrada');
      const paidR = await db.execute({ sql: 'SELECT COALESCE(SUM(amount),0) AS s FROM payments WHERE debt_id = ?', args: [mm[1]] });
      const paid = Number(paidR.rows[0].s);
      if (d.amount < paid) throw new HttpErr(400, `el nuevo monto (${d.amount}) es menor a lo ya pagado (${paid})`);
      await db.execute({
        sql: 'UPDATE debts SET creditor = ?, amount = ?, due = ?, installments = ?, cuota_amount = ? WHERE id = ? AND username = ?',
        args: [d.creditor, d.amount, d.due, d.installments, d.cuota_amount, mm[1], user],
      });
      const dSync = await fetchDebtForSync(mm[1], user);
      if (dSync) await syncDebtEvent(user, dSync);
      return sendView();
    }
    if (mm && m === 'DELETE') {
      await removeDebtEvent(user, mm[1]);
      await db.execute({ sql: 'DELETE FROM debts WHERE id = ? AND username = ?', args: [mm[1], user] });
      return sendView();
    }

    mm = p.match(/^\/api\/debts\/([^/]+)\/payments$/);
    if (mm && m === 'POST') {
      const debt = await db.execute({ sql: 'SELECT amount FROM debts WHERE id = ? AND username = ?', args: [mm[1], user] });
      if (debt.rows.length === 0) throw new HttpErr(404, 'deuda no encontrada');
      const paidR = await db.execute({ sql: 'SELECT COALESCE(SUM(amount),0) AS s FROM payments WHERE debt_id = ?', args: [mm[1]] });
      const remaining = Math.max(0, Number(debt.rows[0].amount) - Number(paidR.rows[0].s));
      const pay = validatePayment(body, remaining);
      try {
        await db.execute({
          sql: 'INSERT INTO payments (debt_id, date, amount, cuota_n) VALUES (?, ?, ?, ?)',
          args: [mm[1], pay.date, pay.amount, pay.cuota_n],
        });
      } catch (e) {
        if (/UNIQUE|constraint/i.test(String(e.message))) throw new HttpErr(409, `esa cuota ya tiene un pago registrado`);
        throw e;
      }
      const dSync = await fetchDebtForSync(mm[1], user);
      if (dSync) await syncDebtEvent(user, dSync);
      return sendView();
    }

    mm = p.match(/^\/api\/debts\/([^/]+)\/payments\/([^/]+)$/);
    if (mm && m === 'PUT') {
      const [, did, pid] = mm;
      const debtR = await db.execute({ sql: 'SELECT amount FROM debts WHERE id = ? AND username = ?', args: [did, user] });
      if (debtR.rows.length === 0) throw new HttpErr(404, 'deuda no encontrada');
      const exR = await db.execute({ sql: 'SELECT 1 FROM payments WHERE id = ? AND debt_id = ?', args: [Number(pid), did] });
      if (exR.rows.length === 0) throw new HttpErr(404, 'pago no encontrado');
      const othR = await db.execute({ sql: 'SELECT COALESCE(SUM(amount),0) AS s FROM payments WHERE debt_id = ? AND id != ?', args: [did, Number(pid)] });
      const room = Math.max(0, Number(debtR.rows[0].amount) - Number(othR.rows[0].s));
      const pay = validatePayment(body, room);
      await db.execute({
        sql: 'UPDATE payments SET date = ?, amount = ? WHERE id = ? AND debt_id = ?',
        args: [pay.date, pay.amount, Number(pid), did],
      });
      const dSync = await fetchDebtForSync(did, user);
      if (dSync) await syncDebtEvent(user, dSync);
      return sendView();
    }
    if (mm && m === 'DELETE') {
      const [, did, pid] = mm;
      await db.execute({
        sql: 'DELETE FROM payments WHERE id = ? AND debt_id IN (SELECT id FROM debts WHERE id = ? AND username = ?)',
        args: [Number(pid), did, user],
      });
      const dSync = await fetchDebtForSync(did, user);
      if (dSync) await syncDebtEvent(user, dSync);
      return sendView();
    }

    if (m === 'PUT' && p === '/api/budgets') {
      const overall = Math.max(0, Math.floor(Number(body.overall || 0)));
      const cats = {};
      for (const [k, v] of Object.entries(body.categories || {})) {
        const n = Math.floor(Number(v));
        if (n > 0 && CATEGORIES.includes(k)) cats[k] = n;
      }
      await db.execute({
        sql: `INSERT INTO budgets (username, overall, cats) VALUES (?, ?, ?)
              ON CONFLICT(username) DO UPDATE SET overall = excluded.overall, cats = excluded.cats`,
        args: [user, overall, JSON.stringify(cats)],
      });
      return sendView();
    }

    if (m === 'GET' && p === '/api/export') {
      const [expR, debtR, payR, bR] = await Promise.all([
        db.execute({ sql: 'SELECT id, date, descr AS "desc", category, amount FROM expenses WHERE username = ? ORDER BY date, id', args: [user] }),
        db.execute({ sql: 'SELECT id, creditor, amount, due, installments, cuota_amount FROM debts WHERE username = ? ORDER BY due, id', args: [user] }),
        db.execute({ sql: 'SELECT p.debt_id, p.date, p.amount FROM payments p JOIN debts d ON d.id = p.debt_id WHERE d.username = ? ORDER BY p.date, p.id', args: [user] }),
        db.execute({ sql: 'SELECT overall, cats FROM budgets WHERE username = ?', args: [user] }),
      ]);
      const paysByDebt = {};
      for (const p of payR.rows) (paysByDebt[p.debt_id] ||= []).push({ date: p.date, amount: Number(p.amount) });
      const expenses = expR.rows.map(r => ({ id: r.id, date: r.date, desc: r.desc, category: r.category, amount: Number(r.amount) }));
      const debts = debtR.rows.map(d => ({ id: d.id, creditor: d.creditor, amount: Number(d.amount), due: d.due, installments: d.installments, cuota_amount: d.cuota_amount == null ? null : Number(d.cuota_amount), payments: paysByDebt[d.id] || [] }));
      const b = bR.rows[0] || { overall: 0, cats: '{}' };
      return res.status(200).json({ version: 2, expenses, debts, budgets: { overall: Number(b.overall), categories: JSON.parse(b.cats || '{}') } });
    }

    if (m === 'POST' && p === '/api/import') {
      if (!Array.isArray(body.expenses)) throw new HttpErr(400, 'shape inválida');
      const stmts = [
        { sql: 'DELETE FROM payments WHERE debt_id IN (SELECT id FROM debts WHERE username = ?)', args: [user] },
        { sql: 'DELETE FROM debts WHERE username = ?', args: [user] },
        { sql: 'DELETE FROM expenses WHERE username = ?', args: [user] },
      ];
      for (const e of body.expenses) {
        try {
          const v = validateExpense(e);
          stmts.push({
            sql: 'INSERT INTO expenses (id, username, date, descr, category, amount) VALUES (?, ?, ?, ?, ?, ?)',
            args: [String(e.id || uid()), user, v.date, v.desc, v.category, v.amount],
          });
        } catch {}
      }
      for (const d of body.debts || []) {
        try {
          const v = validateDebt(d);
          const did = String(d.id || uid());
          stmts.push({
            sql: 'INSERT INTO debts (id, username, creditor, amount, due, installments, cuota_amount) VALUES (?, ?, ?, ?, ?, ?, ?)',
            args: [did, user, v.creditor, v.amount, v.due, v.installments, v.cuota_amount],
          });
          for (const p of d.payments || []) {
            if (p && /^\d{4}-\d{2}-\d{2}$/.test(p.date) && Number(p.amount) > 0) {
              stmts.push({
                sql: 'INSERT INTO payments (debt_id, date, amount) VALUES (?, ?, ?)',
                args: [did, p.date, Math.floor(Number(p.amount))],
              });
            }
          }
        } catch {}
      }
      const bBody = body.budgets || { overall: 0, categories: {} };
      const cats = {};
      for (const [k, v] of Object.entries(bBody.categories || {})) {
        const n = Math.floor(Number(v));
        if (n > 0 && CATEGORIES.includes(k)) cats[k] = n;
      }
      stmts.push({
        sql: `INSERT INTO budgets (username, overall, cats) VALUES (?, ?, ?)
              ON CONFLICT(username) DO UPDATE SET overall = excluded.overall, cats = excluded.cats`,
        args: [user, Math.max(0, Math.floor(Number(bBody.overall || 0))), JSON.stringify(cats)],
      });
      await db.batch(stmts, 'write');
      return sendView();
    }

    if (m === 'DELETE' && p === '/api/auth/google') {
      const tok = await getValidAccessToken(user);
      if (tok) {
        try { await fetch(`https://oauth2.googleapis.com/revoke?token=${tok.access_token}`, { method: 'POST' }); } catch {}
      }
      await db.batch([
        { sql: 'DELETE FROM debt_events WHERE debt_id IN (SELECT id FROM debts WHERE username = ?)', args: [user] },
        { sql: 'DELETE FROM google_tokens WHERE username = ?', args: [user] },
      ], 'write');
      return sendView();
    }

    if (m === 'POST' && p === '/api/auth/google/resync') {
      const debtsR = await db.execute({ sql: 'SELECT id FROM debts WHERE username = ?', args: [user] });
      for (const row of debtsR.rows) {
        const d = await fetchDebtForSync(row.id, user);
        if (d) await syncDebtEvent(user, d);
      }
      return sendView();
    }

    if (m === 'DELETE' && p === '/api/all') {
      // Borrar eventos en Google Calendar antes de nukear las deudas.
      const debtsR = await db.execute({ sql: 'SELECT id FROM debts WHERE username = ?', args: [user] });
      for (const row of debtsR.rows) await removeDebtEvent(user, row.id);
      await db.batch([
        { sql: 'DELETE FROM payments WHERE debt_id IN (SELECT id FROM debts WHERE username = ?)', args: [user] },
        { sql: 'DELETE FROM debts WHERE username = ?', args: [user] },
        { sql: 'DELETE FROM expenses WHERE username = ?', args: [user] },
        { sql: 'DELETE FROM budgets WHERE username = ?', args: [user] },
      ], 'write');
      return sendView();
    }

    return res.status(404).json({ error: 'not found' });
  } catch (e) {
    if (e.statusCode) return res.status(e.statusCode).json({ error: e.message });
    console.error(e);
    return res.status(500).json({ error: 'internal error' });
  }
}
