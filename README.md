# Proyecto_SMX · PrimaZet

Web de PrimaZet con **base de datos real (SQLite)**: registro, inicio de sesión,
tickets de soporte y formulario de contacto guardados en el servidor.

## Estructura

```
Proyecto_SMX/
├── server.js        ← servidor (Node + Express) y API
├── package.json
├── public/
│   └── index.html   ← la web (se sirve desde el servidor)
└── primazet.db      ← la base de datos (se crea sola al arrancar)
```

## Cómo arrancarlo

Necesitas [Node.js](https://nodejs.org) 18 o superior.

```bash
npm install
npm start
```

Abre **http://localhost:3000**.

> ⚠️ Ya no vale abrir `index.html` con doble clic: la web necesita el servidor
> para guardar y comprobar las cuentas.

## Qué se guarda (tablas)

| Tabla              | Contenido |
|--------------------|-----------|
| `users`            | nombre, email (único), contraseña cifrada (scrypt), mayoría de edad y fecha de aceptación RGPD |
| `sessions`         | sesiones activas (solo el hash del token); caducan a los 7 días |
| `tickets`          | tickets de soporte de cada usuario |
| `contact_messages` | mensajes del formulario de contacto |

## API

| Método   | Ruta            | Descripción |
|----------|-----------------|-------------|
| POST     | `/api/register` | Crear cuenta |
| POST     | `/api/login`    | Iniciar sesión (cookie `pz_sid`) |
| POST     | `/api/logout`   | Cerrar sesión |
| GET      | `/api/me`       | Usuario de la sesión actual |
| GET/POST | `/api/tickets`  | Listar / abrir tickets (requiere sesión) |
| POST     | `/api/contact`  | Enviar mensaje de contacto |

## Ver los datos guardados

Abre `primazet.db` con [DB Browser for SQLite](https://sqlitebrowser.org), o por terminal:

```bash
sqlite3 primazet.db "SELECT id, name, email, created_at FROM users;"
```

## Seguridad incluida

- Contraseñas con **scrypt + sal** (nunca en texto plano).
- Sesión en cookie `HttpOnly` + `SameSite=Lax` (y `Secure` con HTTPS).
- Consultas preparadas (sin inyección SQL) y validación en el servidor.
- Límite de intentos en login, registro y contacto.

## Variables de entorno (opcionales)

| Variable      | Por defecto     | Para qué |
|---------------|-----------------|----------|
| `PORT`        | `3000`          | Puerto |
| `DB_PATH`     | `./primazet.db` | Ruta del archivo de la base de datos |
| `TRUST_PROXY` | —               | `true` si va detrás de un proxy con HTTPS (Render, Nginx…) |

## Publicarlo en internet

**GitHub Pages no sirve** (solo aloja archivos estáticos, no ejecuta `server.js`).
Opciones: Render, Railway, Fly.io o un VPS. Como SQLite es un archivo, hay que
activar un **disco persistente** y apuntar `DB_PATH` a él; si no, la base de datos
se borra en cada despliegue.

## Pendiente para producción

Verificación real del email y de la identidad, recuperación de contraseña y
copias de seguridad periódicas del archivo `.db`.
