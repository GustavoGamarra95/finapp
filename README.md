# Finanzas

App de una sola página para llevar gastos y deudas.

- Datos en `localStorage` del navegador (privado, sin servidor, sin login).
- Export/Import JSON para respaldo.
- Deploy estático: `npx vercel --prod` desde esta carpeta.

## Cuando quieras sincronizar entre dispositivos

Agregar un backend (Vercel Functions + Vercel KV o Postgres) cuando aparezca
la necesidad real. Por ahora YAGNI: un solo dispositivo, un solo dueño.
