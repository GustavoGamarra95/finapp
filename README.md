# Finanzas

App de gastos y deudas con backend en Node + SQLite y frontend estático servido por nginx.

## Estructura

```
finapp/
├── front/            # SPA + nginx (sirve estáticos y proxya /api → back)
│   ├── index.html
│   ├── sw.js
│   ├── manifest.json
│   ├── icon.svg
│   ├── nginx.conf
│   └── Dockerfile
├── back/             # API Fastify + SQLite
│   ├── server.js
│   ├── package.json
│   └── Dockerfile
├── compose.yml
└── .env.example
```

## Uso

```bash
cp .env.example .env     # editá ADMIN_PASS y JWT_SECRET
docker compose up -d --build
```

Abrí `http://localhost:8080`. Entrá con `ADMIN_USER` / `ADMIN_PASS`.

- **Gastos**: fecha, descripción, categoría, monto. Se agrupan por mes.
- **Deudas**: acreedor, monto, vencimiento, cuotas y pagos parciales.
- **Presupuestos**: objetivo mensual general y por categoría.
- **Export/Import JSON**: respaldo manual (además del volumen SQLite).

## Servicios

- **web** (`nginx:alpine`) — sirve la SPA en `/` y proxya `/api/*` a la API.
- **api** (`node:22-slim`) — Fastify + `better-sqlite3` + JWT. Sin puerto al host.

Datos en el volumen `finapp_data` (`/data/finapp.db`). Bajar con `docker compose down`
(el volumen sobrevive; agregá `-v` para borrarlo).

## Vars de entorno

Copiar `.env.example` a `.env`. `docker compose` lo lee solo.

- `ADMIN_USER` / `ADMIN_PASS` — usuario admin sembrado al primer arranque.
- `JWT_SECRET` — secreto HMAC para firmar los tokens. Generá uno con `openssl rand -hex 32`.

## API

```bash
# login
curl -s localhost:8080/api/login -H 'content-type: application/json' \
  -d '{"username":"admin","password":"admin"}'
# → {"token":"...","username":"admin"}

TOKEN=<pega el token>

# leer estado
curl -s localhost:8080/api/state -H "authorization: Bearer $TOKEN"

# guardar estado (blob JSON: {expenses, debts, budgets})
curl -s -X PUT localhost:8080/api/state -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"expenses":[],"debts":[],"budgets":{"overall":0,"categories":{}}}'
```

## Cuándo dejar de ser YAGNI

- Multi-usuario / signup → agregar endpoint y UI cuando aparezca la necesidad.
- Queries sobre los datos (agrupar en el server, reportes) → normalizar tablas.
- Modo offline con sync → sw.js + cola de mutaciones local + reconciliación.
