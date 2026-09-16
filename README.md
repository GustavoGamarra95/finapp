# Finanzas

SPA de una sola página (`index.html`) para llevar gastos y deudas. Sin build, sin backend, sin login.

## Uso

Abrí `index.html` en el navegador. Listo.

- **Gastos**: fecha, descripción, categoría, monto. Se agrupan por mes.
- **Deudas**: acreedor, monto, vencimiento. Marcar pagado/pendiente.
- **Resumen**: gasto del mes, deuda pendiente, gasto total (en ₲).
- **Export/Import JSON**: respaldo manual.

Los datos viven en `localStorage` del navegador. Un dispositivo, un dueño, cero servidor.

## Deploy

```bash
npx vercel --prod
```

Sirve `index.html` como estático. Nada más que configurar.

## Cuándo dejar de ser YAGNI

Cuando aparezca la necesidad real de sincronizar entre dispositivos: agregar
Vercel Functions + Vercel KV o Postgres. Hasta entonces, `localStorage` alcanza.
