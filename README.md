# Finanzas

PWA de gastos, deudas y presupuestos. Backend en Vercel Functions, DB en Turso (libSQL),
front estático. Login user/pass o con Google, con sync automático de deudas a Google Calendar.

## Stack

- **Front**: SPA en `public/` (Tailwind + Chart.js por CDN, service worker offline-first).
- **API**: `api/router.js` (single-file, Node runtime en Vercel). Toda la lógica y validación
  vive acá; el front sólo pinta.
- **DB**: Turso (libSQL, `@libsql/client`). En dev local cae a `file:./finapp.db`.
- **Auth**: JWT HS256 hand-rolled con `node:crypto`. Login user/pass o Google OAuth
  (whitelisted por email).
- **Calendario**: Google Calendar API (`calendar.events`). Cada deuda es un evento all-day
  con recordatorios 24h y 1h antes del vencimiento.

## Estructura

```
finapp/
├── api/router.js         # todos los endpoints, un solo handler
├── public/               # index.html, sw.js, manifest.json, icon.svg
├── vercel.json           # rewrite /api/* → /api/router
├── package.json
└── .env.example
```

## Endpoints

Auth:
- `POST /api/login` — user/pass → `{ token, username }`.
- `GET  /api/auth/google/start` — redirige al consent de Google.
- `GET  /api/auth/google/callback` — canjea code, guarda tokens, redirige a `/?token=...`.
- `POST /api/auth/google/resync` — re-sincroniza todas las deudas al calendario.
- `DELETE /api/auth/google` — revoca tokens y borra eventos ya creados.

Datos (requieren `Authorization: Bearer <jwt>`):
- `GET /api/view` — payload único con dashboard + listas + estado de Google.
- `POST/PUT/DELETE /api/expenses[/:id]`.
- `POST/PUT/DELETE /api/debts[/:id]` — cada mutación sincroniza el evento en Calendar.
- `POST/PUT/DELETE /api/debts/:id/payments[/:pid]` — refresca el evento con el pendiente.
- `PUT /api/budgets`.
- `GET /api/export` / `POST /api/import` — backup JSON.
- `DELETE /api/all` — wipe (borra eventos de Calendar también).

## Deploy

Vercel + Turso:

```bash
# 1. DB
turso db create finapp
turso db show finapp --url        # → TURSO_DATABASE_URL
turso db tokens create finapp     # → TURSO_AUTH_TOKEN

# 2. Vars en Vercel (Production/Preview/Development)
#    JWT_SECRET, ADMIN_USER, ADMIN_PASS, TURSO_DATABASE_URL, TURSO_AUTH_TOKEN
#    Google (opcional): GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
#                       GOOGLE_REDIRECT_URI, GOOGLE_ALLOWED_EMAIL

# 3. Deploy
vercel deploy --prod
```

En el primer arranque el bootstrap crea tablas y siembra el usuario admin
(`ADMIN_USER` / `ADMIN_PASS`) si no existe.

## Google OAuth + Calendar (opcional)

1. https://console.cloud.google.com → New Project → Enable **Google Calendar API**.
2. **OAuth consent screen**: External, agregá tu email como test user, scopes `openid`,
   `email`, `.../auth/calendar.events`.
3. **Credentials → OAuth Client ID → Web application**:
   - Authorized redirect URI: `https://<tu-app>.vercel.app/api/auth/google/callback`.
4. Copiá Client ID y Client Secret a las env vars de Vercel.
5. `GOOGLE_ALLOWED_EMAIL` = tu Gmail (whitelist single-user).

Con OAuth en modo *Testing*, el refresh token expira en 7 días. Para uso personal alcanza
re-loguearse cuando pasa; publicar a producción requiere verificación de Google porque
`calendar.events` es scope sensible.

## Dev local

```bash
npm install
cp .env.example .env.local
# En .env.local usá TURSO_DATABASE_URL=file:./finapp.db (SQLite local, sin Turso).
npx vercel dev
```

## Regresión

Smoke test que corre el handler contra libSQL local:

```bash
node /tmp/finapp_smoke.mjs   # 19 asserts sobre login, CRUD, export/import, wipe
```
