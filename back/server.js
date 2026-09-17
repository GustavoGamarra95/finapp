import Fastify from 'fastify';
import fjwt from '@fastify/jwt';
import Database from 'better-sqlite3';
import { scryptSync, randomBytes, timingSafeEqual } from 'node:crypto';

const DB_PATH    = process.env.DB_PATH    || './finapp.db';
const PORT       = Number(process.env.PORT) || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';

const CATEGORIES = ['Comida', 'Transporte', 'Servicios', 'Vivienda', 'Salud', 'Ocio', 'Otro'];

// ============ DB ============
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username  TEXT PRIMARY KEY,
    pass_hash TEXT NOT NULL,
    pass_salt TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS expenses (
    id       TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES users(username),
    date     TEXT NOT NULL,
    descr    TEXT NOT NULL,
    category TEXT NOT NULL,
    amount   INTEGER NOT NULL CHECK (amount > 0)
  );
  CREATE INDEX IF NOT EXISTS idx_expenses_user_date ON expenses(username, date);
  CREATE TABLE IF NOT EXISTS debts (
    id           TEXT PRIMARY KEY,
    username     TEXT NOT NULL REFERENCES users(username),
    creditor     TEXT NOT NULL,
    amount       INTEGER NOT NULL CHECK (amount > 0),
    due          TEXT NOT NULL,
    installments TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_debts_user ON debts(username);
  CREATE TABLE IF NOT EXISTS payments (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    debt_id TEXT NOT NULL REFERENCES debts(id) ON DELETE CASCADE,
    date    TEXT NOT NULL,
    amount  INTEGER NOT NULL CHECK (amount > 0)
  );
  CREATE INDEX IF NOT EXISTS idx_payments_debt ON payments(debt_id);
  CREATE TABLE IF NOT EXISTS budgets (
    username TEXT PRIMARY KEY REFERENCES users(username),
    overall  INTEGER NOT NULL DEFAULT 0,
    cats     TEXT NOT NULL DEFAULT '{}'
  );
`);

// ============ Utilidades ============
function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }
function todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
const ymOf     = (d) => d.slice(0, 7);
const currentYm = () => todayStr().slice(0, 7);
function prevYm() {
  const [y, m] = currentYm().split('-').map(Number);
  const dt = new Date(y, m - 2, 1);
  return `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}`;
}
const daysBetween = (a, b) => Math.round((new Date(b + 'T00:00:00') - new Date(a + 'T00:00:00')) / 86400000);

// ponytail: migración one-shot del blob viejo (tabla `state`) → tablas normalizadas.
try {
  const legacy = db.prepare(`SELECT username, data FROM state`).all();
  if (legacy.length) {
    db.transaction((rows) => {
      for (const { username, data } of rows) {
        const s = JSON.parse(data);
        for (const e of s.expenses || []) {
          if (!e || !e.date || !e.amount) continue;
          db.prepare(`INSERT OR IGNORE INTO expenses (id, username, date, descr, category, amount) VALUES (?, ?, ?, ?, ?, ?)`)
            .run(String(e.id || uid()), username, e.date, e.desc || '', CATEGORIES.includes(e.category) ? e.category : 'Otro', Math.floor(e.amount));
        }
        for (const d of s.debts || []) {
          if (!d || !d.creditor || !d.amount || !d.due) continue;
          const did = String(d.id || uid());
          db.prepare(`INSERT OR IGNORE INTO debts (id, username, creditor, amount, due, installments) VALUES (?, ?, ?, ?, ?, ?)`)
            .run(did, username, d.creditor, Math.floor(d.amount), d.due, d.installments || null);
          for (const p of d.payments || []) {
            if (!p || !p.amount) continue;
            db.prepare(`INSERT INTO payments (debt_id, date, amount) VALUES (?, ?, ?)`)
              .run(did, p.date, Math.floor(p.amount));
          }
        }
        const b = s.budgets || {};
        db.prepare(`INSERT OR REPLACE INTO budgets (username, overall, cats) VALUES (?, ?, ?)`)
          .run(username, Math.max(0, Math.floor(b.overall || 0)), JSON.stringify(b.categories || {}));
      }
    })(legacy);
    db.exec(`DROP TABLE state`);
  }
} catch { /* tabla legacy no existe: primer arranque limpio */ }

// ============ Auth ============
const hash = (pass, salt) => scryptSync(pass, salt, 64).toString('hex');

if (!db.prepare('SELECT 1 FROM users WHERE username = ?').get(ADMIN_USER)) {
  const salt = randomBytes(16).toString('hex');
  db.prepare('INSERT INTO users (username, pass_hash, pass_salt) VALUES (?, ?, ?)')
    .run(ADMIN_USER, hash(ADMIN_PASS, salt), salt);
}

function verify(username, password) {
  const row = db.prepare('SELECT pass_hash, pass_salt FROM users WHERE username = ?').get(username);
  if (!row) return false;
  const a = Buffer.from(row.pass_hash, 'hex');
  const b = Buffer.from(hash(password, row.pass_salt), 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

// ============ Reglas de negocio ============
function debtStatus(remaining, due) {
  if (remaining === 0) return { level: 'paid', label: 'Pagada' };
  const days = daysBetween(todayStr(), due);
  if (days < 0)   return { level: 'overdue', days, label: `Vencida hace ${-days}d` };
  if (days === 0) return { level: 'urgent',  days, label: 'Vence hoy' };
  if (days <= 7)  return { level: 'soon',    days, label: `Vence en ${days}d` };
  return              { level: 'ok',       days, label: `Vence en ${days}d` };
}
function budgetLevel(used, limit) {
  if (limit === 0) return { level: 'none', pct: 0, label: 'sin objetivo definido' };
  const pct = Math.min(100, (used / limit) * 100);
  if (used >= limit)       return { level: 'exceeded', pct, label: 'Superaste el objetivo' };
  if (used >= limit * 0.8) return { level: 'warn',     pct, label: 'Cerca del límite' };
  return { level: 'ok', pct, label: `${pct.toFixed(0)}% usado` };
}

class HttpErr extends Error { constructor(status, message) { super(message); this.statusCode = status; } }

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
  return { creditor, amount, due: b.due, installments };
}
function validatePayment(b, remaining) {
  if (!b || typeof b !== 'object') throw new HttpErr(400, 'invalid body');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(b.date || '')) throw new HttpErr(400, 'date requerido');
  const amount = Math.floor(Number(b.amount));
  if (!(amount > 0)) throw new HttpErr(400, 'amount debe ser positivo');
  if (amount > remaining) throw new HttpErr(400, 'monto excede lo pendiente');
  return { date: b.date, amount };
}

// ============ View builder (todo lo que el front necesita para pintar) ============
function buildView(username, filters = {}) {
  const curYm = currentYm();
  const prevY = prevYm();
  const q     = String(filters.q || '').trim().toLowerCase();
  const cat   = filters.cat || '';
  const from  = filters.from || '';
  const to    = filters.to || '';

  const allExpenses = db.prepare(`
    SELECT id, date, descr AS "desc", category, amount FROM expenses WHERE username = ?
  `).all(username);

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

  // KPIs siempre en base al mes actual, no al filtro.
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

  const debtsRaw = db.prepare(`SELECT id, creditor, amount, due, installments FROM debts WHERE username = ?`).all(username);
  const debts = debtsRaw.map(d => {
    const pays = db.prepare(`SELECT id, date, amount FROM payments WHERE debt_id = ? ORDER BY date DESC, id DESC`).all(d.id);
    const paid = pays.reduce((s, p) => s + p.amount, 0);
    const remaining = Math.max(0, d.amount - paid);
    return {
      ...d,
      payments: pays,
      paid,
      remaining,
      pctPaid: d.amount > 0 ? (paid / d.amount) * 100 : 100,
      status: debtStatus(remaining, d.due),
    };
  }).sort((a, b) => {
    if ((a.remaining === 0) !== (b.remaining === 0)) return a.remaining === 0 ? 1 : -1;
    return a.due.localeCompare(b.due);
  });
  const activeDebts = debts.filter(d => d.remaining > 0);
  const debtTotal = activeDebts.reduce((s, d) => s + d.remaining, 0);
  const upcoming = activeDebts.slice().sort((a, b) => a.due.localeCompare(b.due)).slice(0, 5);

  const bRow  = db.prepare(`SELECT overall, cats FROM budgets WHERE username = ?`).get(username) || { overall: 0, cats: '{}' };
  const bCats = JSON.parse(bRow.cats);
  const overallStatus = budgetLevel(monthSum, bRow.overall || 0);
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
      budget: { overall: bRow.overall, used: monthSum, pctUsed: overallStatus.pct, status: overallStatus },
      categoryChart, trend, upcoming,
    },
    expenses: { groups, flat: filtered, filteredCount: filtered.length, totalCount: allExpenses.length },
    debts,
    budgets: { overall: bRow.overall, categories: budgetCategories },
  };
}

// ============ HTTP ============
const app = Fastify({ logger: true });
await app.register(fjwt, { secret: JWT_SECRET });

app.setErrorHandler((err, req, reply) => {
  if (err.statusCode) return reply.code(err.statusCode).send({ error: err.message });
  req.log.error(err);
  reply.code(500).send({ error: 'internal error' });
});

const auth = async (req, reply) => {
  try { await req.jwtVerify(); }
  catch { reply.code(401).send({ error: 'unauthorized' }); }
};

// ponytail: helper para endpoints de mutación que responden con la view fresca.
const withView = (handler) => async (req, reply) => {
  await handler(req, reply);
  if (!reply.sent) reply.send(buildView(req.user.sub, req.query));
};

app.post('/api/login', async (req, reply) => {
  const { username, password } = req.body || {};
  if (!username || !password || !verify(username, password)) {
    return reply.code(401).send({ error: 'credenciales inválidas' });
  }
  const token = app.jwt.sign({ sub: username }, { expiresIn: '30d' });
  return { token, username };
});

app.get('/api/view', { preHandler: auth }, async (req) => buildView(req.user.sub, req.query));

app.post('/api/expenses', { preHandler: auth }, withView(async (req) => {
  const e = validateExpense(req.body);
  db.prepare(`INSERT INTO expenses (id, username, date, descr, category, amount) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(uid(), req.user.sub, e.date, e.desc, e.category, e.amount);
}));

app.put('/api/expenses/:id', { preHandler: auth }, withView(async (req) => {
  const e = validateExpense(req.body);
  const info = db.prepare(`
    UPDATE expenses SET date = ?, descr = ?, category = ?, amount = ? WHERE id = ? AND username = ?
  `).run(e.date, e.desc, e.category, e.amount, req.params.id, req.user.sub);
  if (info.changes === 0) throw new HttpErr(404, 'gasto no encontrado');
}));

app.delete('/api/expenses/:id', { preHandler: auth }, withView(async (req) => {
  db.prepare(`DELETE FROM expenses WHERE id = ? AND username = ?`).run(req.params.id, req.user.sub);
}));

app.post('/api/debts', { preHandler: auth }, withView(async (req) => {
  const d = validateDebt(req.body);
  db.prepare(`INSERT INTO debts (id, username, creditor, amount, due, installments) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(uid(), req.user.sub, d.creditor, d.amount, d.due, d.installments);
}));

app.put('/api/debts/:id', { preHandler: auth }, withView(async (req) => {
  const d = validateDebt(req.body);
  const owner = db.prepare(`SELECT 1 FROM debts WHERE id = ? AND username = ?`).get(req.params.id, req.user.sub);
  if (!owner) throw new HttpErr(404, 'deuda no encontrada');
  const paid = db.prepare(`SELECT COALESCE(SUM(amount), 0) AS s FROM payments WHERE debt_id = ?`).get(req.params.id).s;
  if (d.amount < paid) throw new HttpErr(400, `el nuevo monto (${d.amount}) es menor a lo ya pagado (${paid})`);
  db.prepare(`
    UPDATE debts SET creditor = ?, amount = ?, due = ?, installments = ? WHERE id = ? AND username = ?
  `).run(d.creditor, d.amount, d.due, d.installments, req.params.id, req.user.sub);
}));

app.delete('/api/debts/:id', { preHandler: auth }, withView(async (req) => {
  db.prepare(`DELETE FROM debts WHERE id = ? AND username = ?`).run(req.params.id, req.user.sub);
}));

app.post('/api/debts/:id/payments', { preHandler: auth }, withView(async (req) => {
  const debt = db.prepare(`SELECT amount FROM debts WHERE id = ? AND username = ?`).get(req.params.id, req.user.sub);
  if (!debt) throw new HttpErr(404, 'deuda no encontrada');
  const paid = db.prepare(`SELECT COALESCE(SUM(amount), 0) AS s FROM payments WHERE debt_id = ?`).get(req.params.id).s;
  const remaining = Math.max(0, debt.amount - paid);
  const p = validatePayment(req.body, remaining);
  db.prepare(`INSERT INTO payments (debt_id, date, amount) VALUES (?, ?, ?)`).run(req.params.id, p.date, p.amount);
}));

app.put('/api/debts/:did/payments/:pid', { preHandler: auth }, withView(async (req) => {
  const debt = db.prepare(`SELECT amount FROM debts WHERE id = ? AND username = ?`).get(req.params.did, req.user.sub);
  if (!debt) throw new HttpErr(404, 'deuda no encontrada');
  const exists = db.prepare(`SELECT 1 FROM payments WHERE id = ? AND debt_id = ?`).get(req.params.pid, req.params.did);
  if (!exists) throw new HttpErr(404, 'pago no encontrado');
  const others = db.prepare(`SELECT COALESCE(SUM(amount), 0) AS s FROM payments WHERE debt_id = ? AND id != ?`)
    .get(req.params.did, req.params.pid).s;
  const room = Math.max(0, debt.amount - others);
  const p = validatePayment(req.body, room);
  db.prepare(`UPDATE payments SET date = ?, amount = ? WHERE id = ? AND debt_id = ?`)
    .run(p.date, p.amount, req.params.pid, req.params.did);
}));

app.delete('/api/debts/:did/payments/:pid', { preHandler: auth }, withView(async (req) => {
  db.prepare(`
    DELETE FROM payments WHERE id = ? AND debt_id IN (SELECT id FROM debts WHERE id = ? AND username = ?)
  `).run(req.params.pid, req.params.did, req.user.sub);
}));

app.put('/api/budgets', { preHandler: auth }, withView(async (req) => {
  const body = req.body || {};
  const overall = Math.max(0, Math.floor(Number(body.overall || 0)));
  const cats = {};
  for (const [k, v] of Object.entries(body.categories || {})) {
    const n = Math.floor(Number(v));
    if (n > 0 && CATEGORIES.includes(k)) cats[k] = n;
  }
  db.prepare(`INSERT INTO budgets (username, overall, cats) VALUES (?, ?, ?)
    ON CONFLICT(username) DO UPDATE SET overall = excluded.overall, cats = excluded.cats`)
    .run(req.user.sub, overall, JSON.stringify(cats));
}));

app.get('/api/export', { preHandler: auth }, async (req) => {
  const username = req.user.sub;
  const expenses = db.prepare(`SELECT id, date, descr AS "desc", category, amount FROM expenses WHERE username = ? ORDER BY date, id`).all(username);
  const debtsRaw = db.prepare(`SELECT id, creditor, amount, due, installments FROM debts WHERE username = ? ORDER BY due, id`).all(username);
  const debts = debtsRaw.map(d => ({
    ...d,
    payments: db.prepare(`SELECT date, amount FROM payments WHERE debt_id = ? ORDER BY date, id`).all(d.id),
  }));
  const b = db.prepare(`SELECT overall, cats FROM budgets WHERE username = ?`).get(username) || { overall: 0, cats: '{}' };
  return { version: 2, expenses, debts, budgets: { overall: b.overall, categories: JSON.parse(b.cats) } };
});

app.post('/api/import', { preHandler: auth }, withView(async (req) => {
  const body = req.body || {};
  if (!Array.isArray(body.expenses)) throw new HttpErr(400, 'shape inválida');
  const username = req.user.sub;
  db.transaction(() => {
    db.prepare(`DELETE FROM payments WHERE debt_id IN (SELECT id FROM debts WHERE username = ?)`).run(username);
    db.prepare(`DELETE FROM debts    WHERE username = ?`).run(username);
    db.prepare(`DELETE FROM expenses WHERE username = ?`).run(username);
    for (const e of body.expenses) {
      try {
        const v = validateExpense(e);
        db.prepare(`INSERT INTO expenses (id, username, date, descr, category, amount) VALUES (?, ?, ?, ?, ?, ?)`)
          .run(String(e.id || uid()), username, v.date, v.desc, v.category, v.amount);
      } catch { /* skip fila inválida */ }
    }
    for (const d of body.debts || []) {
      try {
        const v = validateDebt(d);
        const did = String(d.id || uid());
        db.prepare(`INSERT INTO debts (id, username, creditor, amount, due, installments) VALUES (?, ?, ?, ?, ?, ?)`)
          .run(did, username, v.creditor, v.amount, v.due, v.installments);
        for (const p of d.payments || []) {
          if (p && /^\d{4}-\d{2}-\d{2}$/.test(p.date) && Number(p.amount) > 0) {
            db.prepare(`INSERT INTO payments (debt_id, date, amount) VALUES (?, ?, ?)`).run(did, p.date, Math.floor(Number(p.amount)));
          }
        }
      } catch { /* skip */ }
    }
    const b = body.budgets || { overall: 0, categories: {} };
    const cats = {};
    for (const [k, v] of Object.entries(b.categories || {})) {
      const n = Math.floor(Number(v));
      if (n > 0 && CATEGORIES.includes(k)) cats[k] = n;
    }
    db.prepare(`INSERT INTO budgets (username, overall, cats) VALUES (?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET overall = excluded.overall, cats = excluded.cats`)
      .run(username, Math.max(0, Math.floor(Number(b.overall || 0))), JSON.stringify(cats));
  })();
}));

app.delete('/api/all', { preHandler: auth }, withView(async (req) => {
  const username = req.user.sub;
  db.transaction(() => {
    db.prepare(`DELETE FROM payments WHERE debt_id IN (SELECT id FROM debts WHERE username = ?)`).run(username);
    db.prepare(`DELETE FROM debts    WHERE username = ?`).run(username);
    db.prepare(`DELETE FROM expenses WHERE username = ?`).run(username);
    db.prepare(`DELETE FROM budgets  WHERE username = ?`).run(username);
  })();
}));

// ============ Self-check ============
(function selfcheck() {
  console.assert(debtStatus(0, todayStr()).level === 'paid', 'debtStatus paid');
  console.assert(budgetLevel(80, 100).level === 'warn', 'budgetLevel warn');
  console.assert(budgetLevel(110, 100).level === 'exceeded', 'budgetLevel exceeded');
  console.assert(budgetLevel(50, 100).level === 'ok', 'budgetLevel ok');
  console.assert(budgetLevel(10, 0).level === 'none', 'budgetLevel none');
})();

try {
  await app.listen({ host: '0.0.0.0', port: PORT });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
