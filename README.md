# Lab Device Inventory Tool

A web-based internal tool for managing lab hardware. Teams can track device ownership, availability, and leases; request devices from other users; and get notified when requests are approved or leases expire — all through a browser UI with role-based access control. Admins can manage users, reset passwords, and create or restore database backups without leaving the browser.

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Backend framework | FastAPI | 0.115.0 |
| ASGI server | Uvicorn (standard) | 0.30.6 |
| Database | PostgreSQL | — |
| DB driver | psycopg2-binary | 2.9.9 |
| Connection pooling | psycopg2 ThreadedConnectionPool | — |
| Authentication | PyJWT (HTTP-only cookie, HS256) | 2.9.0 |
| Password hashing | Werkzeug (`pbkdf2:sha256`) | 3.0.1 |
| Device password encryption | cryptography (Fernet symmetric) | 42.0.8 |
| Session / flash messages | itsdangerous + Starlette SessionMiddleware | 2.2.0 |
| Templating | Jinja2 | 3.1.4 |
| Form parsing | python-multipart | 0.0.9 |
| Environment config | python-dotenv | 1.0.1 |
| Background jobs | APScheduler (BackgroundScheduler) | 3.10.4 |
| Excel import / export | openpyxl | 3.1.5 |
| Frontend | HTML + CSS + vanilla JavaScript | — |
| Deployment | Heroku-compatible via Procfile | — |

---

## Project Structure

```
Lab_Inventory_tool-master/
│
├── backend/                          # All server-side Python code
│   ├── main.py                       # FastAPI app entry point; mounts routers, initialises connection pool, starts APScheduler
│   ├── dependencies.py               # Shared helpers: JWT auth, flash messages, Jinja2 render, _require_login
│   ├── requirements.txt              # Python package dependencies
│   ├── Procfile                      # Heroku process definition (uvicorn)
│   ├── .env                          # Local environment variables (not committed to VCS)
│   │
│   ├── routers/                      # FastAPI route handlers, one file per domain
│   │   ├── auth.py                   # Login, logout, home redirect
│   │   ├── devices.py                # Full device CRUD, autocomplete API, reserve/release/claim/use/request/renew-lease
│   │   ├── history.py                # Paginated device-edit audit log
│   │   ├── notifications.py          # Notification inbox, accept/decline device requests
│   │   ├── users.py                  # In-app user management (admin): list, add, delete, reset password; self-service change-password
│   │   ├── backup.py                 # Database backup management (admin): list, create, download, restore, delete
│   │   └── importexport.py           # Excel import/export (admin): GET /export downloads .xlsx, POST /import uploads .xlsx
│   │
│   ├── services/                     # Shared business-logic and I/O modules
│   │   ├── db.py                     # ThreadedConnectionPool, get/return connection, log_change, log_device_edit, create_notification, get_unread_count
│   │   ├── crypto.py                 # Fernet encrypt/decrypt for device passwords
│   │   └── backup.py                 # Backup logic: pg_dump (with Python fallback), restore, list, delete, auto-cleanup
│   │
│   ├── schemas/                      # Pydantic models (used for type reference)
│   │   └── device.py                 # DeviceCreate and DeviceEdit schemas
│   │
│   ├── backups/                      # Auto-created at runtime; stores .sql backup files (max 7 kept)
│   │
│   ├── init_db.py                    # One-time script: creates all tables and default admin user
│   ├── migrate_lease.py              # Migration script: adds lease columns to existing databases
│   ├── add_user.py                   # Interactive CLI script to add a new user
│   ├── add_password_column.py        # Migration script: adds password column to devices table
│   ├── create_history_table.py       # Migration script: creates device_edit_history table
│   ├── delete_user.py                # CLI script to delete a user and release their devices
│   ├── delete_device.py              # CLI script to delete a device by MAC address
│   └── inventory.db                  # SQLite remnant from early development (not used by the app)
│
├── frontend/                         # All static assets and HTML templates
│   ├── static/
│   │   ├── styles.css                # Global stylesheet for all pages
│   │   ├── autocomplete.js           # Autocomplete dropdown widget (used in Add/Edit forms)
│   │   └── datepicker.js             # Custom calendar date picker widget (used for lease date inputs)
│   └── templates/                    # Jinja2 HTML templates
│       ├── layout.html               # Base layout: header, nav (role-aware), flash messages, footer
│       ├── login.html                # Login form
│       ├── index.html                # Device inventory table with action buttons and search
│       ├── add_item.html             # Add new device form (with autocomplete)
│       ├── edit_item.html            # Edit existing device form (with autocomplete)
│       ├── history.html              # Paginated field-level audit log table
│       ├── notifications.html        # Notification inbox with accept/decline actions
│       ├── users.html                # User management table (admin)
│       ├── add_user.html             # Add new user form (admin)
│       ├── reset_password.html       # Admin: reset another user's password
│       ├── change_password.html      # Any user: change own password
│       └── backups.html              # Backup management page (admin)
│
├── LICENSE                           # CC BY-NC 4.0
└── README.md                         # This file
```

---

## Features

### Authentication

- **Login / Logout** — Username and password login; credentials verified with `pbkdf2:sha256` hashing. Usernames are stored and compared in lowercase. A signed JWT is issued on success and stored in an HTTP-only, `SameSite=lax` cookie (`access_token`).
- **Session expiry** — JWT and `SessionMiddleware` both expire after 15 minutes of inactivity. On expiry the user is redirected to `/login` with a flash message.
- **Protected routes** — All routes except `/login` and `/logout` require a valid JWT. Missing or expired tokens redirect to the login page.
- **Default credentials** — A default `admin` / `admin123` account is created by `init_db.py`. Change this immediately after first login.

---

### Role-Based Access Control

Two roles exist: `admin` and `user`. The role is embedded in the JWT and checked on every request.

| Capability | admin | user |
|---|---|---|
| View inventory | Yes | Yes |
| Add device | Yes (any owner) | Yes (owner forced to self) |
| Edit device — identity fields (MAC, model, owner, lease note) | Yes | No (read-only in form) |
| Edit device — operational fields (availability, IP, location, reporting manager, team) | Yes | Yes (effective controller only) |
| Edit device password | Yes (any device) | Yes (effective controller only) |
| Reveal device password | Yes (any device) | Yes (effective controller only) |
| Delete device | Yes | No |
| Claim unowned device | Yes | Yes |
| Use (mark claimed device as In Use) | Yes | Yes (owner only) |
| Release device | Yes | Yes (effective controller — owner or active leasee) |
| Request device lease | Yes | Yes (non-controller only) |
| Renew lease | Yes | Yes (current leasee only) |
| Accept / Decline lease requests | Yes | Yes (device owner only) |
| View audit history | Yes | Yes |
| View and act on notifications | Yes | Yes |
| Change own password | Yes | Yes |
| Manage users (list, add, delete, reset password) | Yes | No |
| Access backup management | Yes | No |

---

### Device Inventory (CRUD)

**Listing devices**

The inventory page (`/inventory`) shows all devices in a table with columns: MAC address, model, owner, availability, reporting manager, team, IP address, location, lease status (leasee + expiry date), and password. Every page load also runs the lease-expiry check (see Lease Management).

**Adding a device** (`/add`)

- MAC address is normalised: all non-hex characters are stripped and the result is formatted as `AA:BB:CC:DD:EE:FF`. Exactly 12 hex digits are required.
- IP address must be a valid IPv4 or IPv6 address. An empty IP address is **not** accepted — if a device has no IP yet, enter a placeholder (see Limitations).
- If the user role is `user`, the owner field is silently overridden to the logged-in username regardless of what was typed.
- Device passwords are Fernet-encrypted before storage.
- Duplicate MAC addresses are rejected.

**Editing a device** (`/edit/{id}`)

- Access is restricted to the **effective controller** (owner or active leasee) or an admin.
- **Admins** can edit all fields: MAC address, model, owner, availability, reporting manager, team, IP address, location, lease note, and password.
- **Regular users (effective controller)** can edit only: availability, reporting manager, team, IP address, location, and password. Identity fields (MAC, model, owner, lease note) are rendered as read-only in the form and silently ignored if submitted. The `owner` field is never changed by this form for non-admins.
- Every changed field is written to `device_edit_history` (audit log). Password changes are logged as `"****" → "****"` — the value is never logged in plain text.

**Deleting a device** (`/delete/{id}`)

Admin only. Deletion is logged to `change_logs` with a snapshot of the device row.

**Duplicate MAC prevention**

Inserting or editing to a MAC address that is already used by another device is rejected at the server level.

---

### Search and Filter

- **Full-text search** — The `?search=` query parameter runs a case-insensitive `ILIKE '%term%'` across: MAC address, model, owner, availability, reporting manager, team, IP address, location, lease note, leasee username, project, console, and power. Searching `iphone`, `iPhone`, or `IPHONE` all return the same results.
- **Availability filter** — The `?availability=` dropdown filters to `Available` or `In Use`.
- Both can be combined. A **Clear** button resets to the unfiltered view.

---

### Autocomplete on Add / Edit Forms

The **Owner**, **Reporting Manager**, **Device Model**, and **Team** fields on the Add Device and Edit Device forms support live autocomplete:

- Suggestions are fetched once per page load from `GET /api/autocomplete-options`, which returns JSON with four arrays: `owners` (all registered usernames), `reporting_managers`, `device_models`, and `teams` (distinct non-empty values from existing devices).
- Typing filters the list using substring matching; the matched portion is highlighted.
- Keyboard navigation: **↓ / ↑** to move through the list, **Enter** to select, **Escape** to dismiss.
- Clicking outside the dropdown or blurring the field also dismisses it.
- The autocomplete does **not** restrict input — any value can be typed freely.

---

### Ownership vs. Lease (Effective Controller Model)

The system separates **permanent ownership** from **temporary control**:

- **Owner** (`owner` field) — the permanent owner of a device. Ownership never changes due to lease actions. Only an admin can reassign the owner field.
- **Leasee** (`leasee_username` + `lease_expiry`) — a user who has been granted temporary control by the owner.
- **Effective controller** — dynamically determined on every request:
  - If a lease is **active** (`leasee_username` is set, `lease_expiry` is set, and `now < lease_expiry`) → the **leasee** is in control.
  - Otherwise → the **owner** is in control.

All permission checks (edit, release, password reveal, request blocking) use the effective controller, not the static owner field. The Lease column in the inventory table shows an "In control: \<username\>" label when a lease is active.

The owner remains the sole authority for accepting or declining incoming lease requests — a leasee cannot sub-lease a device to a third party.

---

### Device Lifecycle (Claim → Use → Release)

Devices follow a state machine based on `availability` (`Available` / `In Use`) and the `owner` field:

| State | availability | owner |
|---|---|---|
| Unowned / free | `Available` | empty |
| Claimed, not yet in use | `Available` | set |
| In use | `In Use` | set |

**Claim** — Any logged-in user can claim an unowned available device, setting them as owner (availability stays `Available`). Devices with any pending request are blocked from direct claim; those must go through the request workflow instead.

**Use** — The owner of a claimed-but-available device marks it as `In Use`.

**Reserve** — A one-step shortcut that sets both owner and `In Use` simultaneously. Shown in the UI when a device is free.

**Release** — The **effective controller** (owner or active leasee) of an `In Use` device releases it back to `Available` with no owner. All pending requests are cancelled, the active lease is cleared, and the leasee (if any) is notified. If the leasee releases their own lease, no self-notification is sent. The UI shows a confirmation warning whenever an active leasee exists.

---

### Device Request and Approval System

When a device is `In Use`, users who are not the effective controller can queue a time-limited lease request:

1. **Submit request** — Click **Request** on any `In Use` device you don't currently control. A calendar date picker appears constrained to tomorrow through 7 days from today. The request is created as `pending` and the owner is notified.
2. **Owner decides** — Accept / Decline buttons appear on the notification. The server re-checks ownership before acting.
3. **On Accept** — The requester becomes `leasee_username` with the approved `lease_expiry`. All other competing `pending` requests for the same device are automatically cancelled. If a previous leasee existed, they are notified.
4. **On Decline** — The request moves to `declined` and the requester is notified.
5. **Duplicate guard** — A user cannot have two `pending` requests of type `request` for the same device simultaneously. The **Request** button is replaced with a disabled **Requested** label while a pending request exists.

---

### Lease Management

Each device tracks `leasee_username`, `lease_expiry` (timestamp), and `lease_warning_sent` (boolean).

**Auto-expiry** — On every `GET /inventory` load, `check_and_expire_leases()` scans all devices with a non-null `lease_expiry`. Overdue leases (expiry < now) are cleared: `leasee_username` and `lease_expiry` are set to NULL, all pending requests on the device are cancelled, and notifications are sent to the former leasee, the device owner, and any pending requesters.

> **Limitation:** Lease expiry only fires on inventory page load. If no user visits `/inventory`, overdue leases will not be cleared until the next visit.

**2-day warning** — Devices expiring within 2 days that have not yet had a warning sent trigger a notification to the leasee and flip `lease_warning_sent` to TRUE (so the warning fires only once per lease).

**Lease renewal** — The current leasee can extend their lease. Clicking **Renew Lease** opens a calendar picker constrained to `expiry + 1 day` through `expiry + 7 days`. The renewal is a new `pending` request of type `renewal`; the owner approves or declines via notifications. On approval, only `lease_expiry` is updated and `lease_warning_sent` is reset. A user cannot submit two simultaneous pending renewals for the same device.

**UI indicators** — When a lease is active, the Lease column shows `leasee_username (expires: Mon D, YYYY)` with an "In control: \<username\>" sub-label. If a leasee record exists but the expiry has passed (before the expiry job clears it), the column shows `leasee_username (expired)`. The Action column shows a disabled **Renewal Pending** button while a renewal is outstanding.

---

### Password Management

- Device passwords are stored **Fernet-encrypted** in the `password` column using the `FERNET_KEY` environment variable. If `FERNET_KEY` is not set, the server raises a `RuntimeError` on the first encrypt/decrypt attempt.
- The inventory table shows `••••••••` for devices with a password, and `—` for devices with none.
- A **Show / Hide** toggle calls `GET /reveal-password/{id}` via AJAX. Only the **effective controller** (owner or active leasee) or an admin can reveal the password; others receive `{"error": "Access denied"}`.
- The Edit Device form pre-populates the decrypted password for authorised users. Saving always re-encrypts whatever is in the field. Clearing the field stores an empty string.
- Password changes are recorded in the audit log as `"****" → "****"`.

---

### User Management (Admin only)

Accessible via **Users** in the nav bar (admin only). Provides a complete in-app alternative to the CLI scripts.

**User list** (`/users`) — Table of all users (username, role) with Reset Password and Delete buttons.

**Add user** (`/users/add`) — Validation rules:
- Username is lowercased and trimmed; must not already exist.
- Password must be at least 6 characters.
- Password and confirm-password must match.
- Role must be `admin` or `user`.

**Delete user** (`/users/delete/{user_id}`) — Admin cannot delete their own account (button is replaced with "(you)"). On deletion:
- All devices owned by the deleted user are set to `owner = 'Unassigned'` and `availability = 'Available'`.
- All pending device requests by the deleted user are cancelled.
- A browser confirmation dialog is shown before proceeding.

**Reset password** (`/users/reset-password/{user_id}`) — Admin sets a new password for any user without needing the current one. Min 6 characters, confirm-password check.

---

### Account / Password Self-Service

**Change own password** (`/change-password`) — Available to every logged-in user via **Change Password** in the nav bar. Validation:
- Current password must be correct.
- New password must be at least 6 characters.
- New password and confirm must match.
- New password must differ from the current password.

On success the user is redirected to `/inventory`.

---

### Database Backup & Restore (Admin only)

Accessible via **Backups** in the nav bar (admin only).

**Backup creation** — Two methods are attempted in order:
1. **`pg_dump`** (preferred) — Uses the system `pg_dump` binary with `--inserts --clean --if-exists --no-owner --no-acl`. Produces a standard SQL dump.
2. **Python fallback** — If `pg_dump` is unavailable or fails (common on PaaS), a Python-based dump is generated using `psycopg2`. It introspects `information_schema`, topologically sorts tables by foreign-key dependency, and writes `DROP TABLE`, `CREATE TABLE`, and `INSERT` statements.

**Automatic weekly backup** — APScheduler starts on app startup and fires `create_backup()` every 7 days (first run: 1 minute after startup).

**Manual backup** — Click **Create Backup Now** on the Backups page.

**Backup storage** — Files are named `backup_YYYY-MM-DD_HH-MM-SS.sql` and stored in `backend/backups/`. After each backup, `cleanup_old_backups()` deletes all but the 7 most recent files.

**Download** — `GET /backups/download/{filename}` serves the file as a downloadable attachment.

**Restore** — A browser confirmation warning is shown before proceeding. The SQL file is split by `;` and each statement is executed against the live database with `session_replication_role = replica` to suppress FK triggers during the load.

> **Limitation:** Restore replaces all current data unconditionally. There is no partial restore and no undo. Always download a fresh backup before restoring an older one.

**Delete backup** — Removes the `.sql` file from disk. Requires a browser confirmation.

**Security** — All file operations call `_safe_filename()`, which enforces `[A-Za-z0-9_\-\.]+` and a `.sql` extension requirement to prevent path traversal.

---

### Notifications

Every system event creates rows in the `notifications` table for the relevant recipient(s).

| Trigger | Recipient(s) |
|---|---|
| Lease request submitted | Device owner |
| Lease request accepted | Requester |
| Lease request declined | Requester |
| Lease renewal submitted | Device owner |
| Lease renewal accepted | Requester |
| Lease renewal declined | Requester |
| Lease auto-expired | Leasee, device owner, pending requesters |
| 2-day lease expiry warning | Leasee |
| Owner releases device with active leasee | Leasee |
| Owner accepts new request when a leasee already exists | Displaced leasee |

**Unread badge** — The nav bar shows a numeric badge next to **Notifications** when there are unread notifications. The count is fetched from the connection pool on every page render.

**Notifications page** — All notifications for the current user, newest first. Columns: message, related device MAC, received date, requested lease end date, type badge (Request / Renewal), status badge (Pending / Accepted / Declined / Cancelled), and action buttons. All unread rows are automatically marked as read on page visit and are highlighted in pale yellow.

**Accept / Decline** — Buttons appear only on notifications with a linked `request_id` in `pending` status. The server re-checks that the acting user is the device owner before processing.

---

### Excel Import / Export (Admin only)

Admins can bulk-manage device inventory using `.xlsx` files via two endpoints. No UI page exists for these yet — they are used via `curl`, a REST client, or a future frontend form.

---

#### Export (`GET /export`)

Downloads the full `devices` table as an Excel file. Excluded columns that are system-managed (`id`, `password`, `leasee_username`, `lease_expiry`, `lease_warning_sent`) are never included.

**Example — curl:**

```bash
curl -b "access_token=<your_admin_jwt>" \
     http://localhost:8000/export \
     -o devices_export.xlsx
```

The downloaded file (`devices_export.xlsx`) will look like this:

| mac_address | device_model | owner | availability | reporting_manager | team | ip_address | location | lease |
|---|---|---|---|---|---|---|---|---|
| AA:BB:CC:11:22:33 | Raspberry Pi 4 | alice | In Use | bob | Platform | 192.168.1.10 | Lab Rack A | Long-term |
| DD:EE:FF:44:55:66 | Jetson Nano | | Available | | | 10.0.0.5 | Server Room | |

---

#### Import (`POST /import`)

Accepts a `.xlsx` file and bulk-inserts or updates device records.

- **New MAC address** → row is inserted as a new device.
- **Existing MAC address** → existing device record is overwritten with values from the file. The response lists every MAC that was overwritten so you know what changed.
- Rows with validation errors are skipped; the rest are still processed. All valid rows are committed in one transaction.

**Example — curl:**

```bash
curl -b "access_token=<your_admin_jwt>" \
     -X POST http://localhost:8000/import \
     -F "file=@devices_import.xlsx"
```

**Example response:**

```json
{
  "inserted": 2,
  "overwritten": ["AA:BB:CC:11:22:33"],
  "errors": [
    {"row": 4, "message": "Invalid availability: 'unknown'. Must be 'Available' or 'In Use'."},
    {"row": 7, "message": "MAC address must have exactly 12 hex digits, got: 'ZZ:ZZ'"}
  ]
}
```

---

#### Required Excel Columns

The file must be `.xlsx` format (not `.xls` or `.csv`). The first row must be a header row with column names exactly as shown below (case-sensitive).

| Column | Required | Data Type | Valid Values | Example |
|---|---|---|---|---|
| `mac_address` | **Yes** | Text | 12 hex digits in any separator format — normalised to `AA:BB:CC:DD:EE:FF` on import | `AA:BB:CC:11:22:33` or `aabbcc112233` |
| `device_model` | **Yes** | Text | Any non-empty string | `Raspberry Pi 4`, `Jetson Nano` |
| `availability` | **Yes** | Text | Exactly `Available` or `In Use` (case-sensitive) | `Available` |
| `owner` | No | Text | Any username registered in the system, or blank for unowned | `alice` |
| `reporting_manager` | No | Text | Any string or blank | `bob` |
| `team` | No | Text | Any string or blank | `Platform` |
| `ip_address` | No | Text | Valid IPv4 or IPv6 address, or blank | `192.168.1.10` |
| `location` | No | Text | Any string or blank | `Lab Rack A` |
| `lease` | No | Text | Any string or blank; free-text admin note | `Long-term`, `Project X` |

> Columns beyond those listed above are ignored.  
> System-managed columns (`id`, `password`, `leasee_username`, `lease_expiry`, `lease_warning_sent`) cannot be set via import and are silently ignored even if present.

---

#### Validation Rules

| Rule | Behaviour on failure |
|---|---|
| File is not `.xlsx` | HTTP 400: `"Only .xlsx files are supported."` — entire import rejected |
| File cannot be parsed as a valid Excel workbook | HTTP 400: `"Could not parse file."` — entire import rejected |
| Required column missing from header row | HTTP 400: `"Missing required columns: <name>"` — entire import rejected |
| `mac_address` is not 12 hex digits | Row skipped; error recorded in `errors` array |
| `availability` is not `Available` or `In Use` | Row skipped; error recorded in `errors` array |
| `device_model` is blank | Row skipped; error recorded in `errors` array |
| All cells in a row are empty | Row silently skipped (treated as padding) |
| MAC address already exists | Row processed as an update; MAC listed in `overwritten` |

---

#### Minimal Valid Example

A file with only the three required columns is valid:

| mac_address | device_model | availability |
|---|---|---|
| 00:11:22:33:44:55 | Arduino Uno | Available |
| AA:BB:CC:DD:EE:FF | Raspberry Pi 4 | In Use |

All optional columns will be set to `NULL` / empty for newly inserted rows. Existing rows updated this way will have those optional fields cleared.

---

### Audit Log (History)

**`device_edit_history`** — Field-level change log. Every device field update (via form, lease events, or system actions) inserts a row recording: MAC address, field name, old value, new value, `changed_by` (username or `system`), and timestamp.

**`change_logs`** — Higher-level event log. Records events such as: `Reserve`, `Release`, `Claim`, `Use`, `Delete`, `Lease Started`, `Lease Renewal Approved`, `Lease Renewal Declined`, `Decline Request`. Each row includes username, action label, device MAC, and a JSON detail blob.

The **History** page (`/history`) shows `device_edit_history` in reverse-chronological order, paginated at 10 rows per page with Previous / Next controls. The `change_logs` table is not exposed in the UI but is available for direct database query.

---

## Database Schema

### `devices`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | SERIAL | PRIMARY KEY | Auto-incrementing row ID |
| `mac_address` | TEXT | UNIQUE NOT NULL | Normalised MAC (`AA:BB:CC:DD:EE:FF`) |
| `device_model` | TEXT | NOT NULL | Hardware model name |
| `owner` | TEXT | | Current owner username (empty = unowned; `NOT NULL` dropped by `init_db.py` after creation) |
| `availability` | TEXT | NOT NULL CHECK (`Available` / `In Use`) | Current availability status |
| `reporting_manager` | TEXT | | Owner's reporting manager |
| `team` | TEXT | | Team the device belongs to |
| `ip_address` | TEXT | | Device IP address |
| `location` | TEXT | | Physical location |
| `lease` | TEXT | | Free-text lease note (admin-editable only) |
| `password` | TEXT | DEFAULT `''` | Fernet-encrypted device password |
| `leasee_username` | TEXT | | Username of the current leasee (NULL if none) |
| `lease_expiry` | TIMESTAMP | | When the current lease ends (NULL if no active lease) |
| `lease_warning_sent` | BOOLEAN | DEFAULT FALSE | Whether the 2-day expiry warning has been sent for the current lease |

### `users`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | SERIAL | PRIMARY KEY | Auto-incrementing row ID |
| `username` | TEXT | UNIQUE NOT NULL | Login username (stored and compared lowercase) |
| `password` | TEXT | NOT NULL | `pbkdf2:sha256` hashed password |
| `role` | TEXT | NOT NULL CHECK (`admin` / `user`) | User role |

### `device_edit_history`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | SERIAL | PRIMARY KEY | Auto-incrementing row ID |
| `mac_address` | TEXT | NOT NULL | Device that was edited |
| `field_name` | TEXT | NOT NULL | Name of the field that changed |
| `old_value` | TEXT | | Value before the change |
| `new_value` | TEXT | | Value after the change |
| `changed_by` | TEXT | NOT NULL | Username who made the change, or `system` |
| `changed_at` | TIMESTAMP | NOT NULL DEFAULT NOW() | Time of the change |

### `change_logs`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | SERIAL | PRIMARY KEY | Auto-incrementing row ID |
| `username` | TEXT | NOT NULL | User who triggered the action |
| `action` | TEXT | NOT NULL | Action label (e.g. `Reserve`, `Delete`, `Lease Started`) |
| `item_name` | TEXT | NOT NULL | MAC address of the affected device |
| `details` | TEXT | NOT NULL | JSON blob with action-specific context |
| `timestamp` | TEXT | NOT NULL | ISO 8601 timestamp string |

### `device_requests`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | SERIAL | PRIMARY KEY | Auto-incrementing row ID |
| `mac_address` | TEXT | NOT NULL | Device being requested |
| `requester_username` | TEXT | NOT NULL | User who submitted the request |
| `request_status` | TEXT | NOT NULL DEFAULT `pending` CHECK (`pending` / `accepted` / `declined` / `cancelled`) | Current status |
| `requested_at` | TIMESTAMP | NOT NULL DEFAULT NOW() | When the request was submitted |
| `resolved_at` | TIMESTAMP | | When the request was accepted/declined/cancelled |
| `requested_lease_date` | TIMESTAMP | | Desired lease end date provided by requester |
| `request_type` | TEXT | NOT NULL DEFAULT `request` CHECK (`request` / `renewal`) | New lease request or lease renewal |

### `notifications`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | SERIAL | PRIMARY KEY | Auto-incrementing row ID |
| `recipient_username` | TEXT | NOT NULL | User this notification is for |
| `message` | TEXT | NOT NULL | Human-readable notification text |
| `related_mac_address` | TEXT | | MAC address of the related device |
| `request_id` | INTEGER | REFERENCES `device_requests(id)` | Linked request row (NULL for system events) |
| `is_read` | BOOLEAN | NOT NULL DEFAULT FALSE | Whether the user has viewed it |
| `created_at` | TIMESTAMP | NOT NULL DEFAULT NOW() | When the notification was created |

---

## API Endpoints

All endpoints return HTML (Jinja2-rendered pages) except where noted. Auth is via an HTTP-only JWT cookie (`access_token`). Unauthenticated requests to protected routes redirect to `/login`.

### Authentication

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/` | No | Redirects to `/inventory` if logged in, else `/login` |
| `GET` | `/login` | No | Renders the login form |
| `POST` | `/login` | No | Validates credentials; sets JWT cookie; redirects to `/inventory` |
| `GET` | `/logout` | No | Clears the JWT cookie; redirects to `/login` |

### Device Inventory

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/inventory` | Yes | Lists all devices; triggers lease-expiry check; accepts `?search=` and `?availability=` |
| `GET` | `/add` | Yes | Renders the Add Device form |
| `POST` | `/add` | Yes | Creates a new device; validates MAC and IP; admin can set any owner, user is forced to self |
| `GET` | `/edit/{id}` | Yes | Renders Edit Device form (effective controller or admin only); pre-populates decrypted password |
| `POST` | `/edit/{id}` | Yes | Saves edits; admins edit all fields, effective controller edits operational fields only; logs all changes |
| `GET` | `/delete/{id}` | Yes | Deletes a device and logs the event (admin only) |
| `GET` | `/reveal-password/{id}` | Yes | **JSON** — returns `{"password": "..."}` (effective controller or admin); `{"error": "..."}` on failure |
| `GET` | `/api/autocomplete-options` | Yes | **JSON** — returns `{"owners": [...], "reporting_managers": [...], "device_models": [...], "teams": [...]}` |

### Device Actions

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/claim/{id}` | Yes | Claims an unowned available device; blocked if any pending request exists on the device |
| `POST` | `/use/{id}` | Yes | Marks an owned available device as `In Use` (owner only) |
| `POST` | `/reserve/{id}` | Yes | Sets owner + `In Use` in one step on a free device |
| `POST` | `/release/{id}` | Yes | Releases an `In Use` device; cancels all pending requests; ends any active lease (effective controller — owner or active leasee) |
| `POST` | `/request/{id}` | Yes | Submits a lease request with a desired end date (non-controller only; date: tomorrow through 7 days) |
| `POST` | `/renew-lease/{id}` | Yes | Submits a lease renewal (current leasee only; date: expiry+1 through expiry+7 days) |

### Notifications

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/notifications` | Yes | Renders notification inbox; marks all unread as read |
| `POST` | `/accept-request/{request_id}` | Yes | Accepts a pending device request or renewal (device owner only) |
| `POST` | `/decline-request/{request_id}` | Yes | Declines a pending device request or renewal (device owner only) |
| `POST` | `/notifications/mark-read` | Yes | Marks all of the current user's notifications as read |

### History

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/history` | Yes | Renders paginated `device_edit_history`; accepts `?page=` (10 rows per page) |

### User Management

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/users` | Admin | Lists all users with Reset Password and Delete actions |
| `GET` | `/users/add` | Admin | Renders Add User form |
| `POST` | `/users/add` | Admin | Creates a user; validates username uniqueness, min-6-char password, confirm-password, role |
| `GET` | `/users/delete/{user_id}` | Admin | Deletes user; releases their devices; cancels their pending requests; cannot delete own account |
| `GET` | `/users/reset-password/{user_id}` | Admin | Renders Reset Password form for a target user |
| `POST` | `/users/reset-password/{user_id}` | Admin | Saves a new password for any user; min 6 chars, confirm-password check |
| `GET` | `/change-password` | Yes | Renders Change Password form for the current user |
| `POST` | `/change-password` | Yes | Changes the current user's own password; validates current password, min 6 chars, must differ |

### Backup Management

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/backups` | Admin | Lists all backup files (filename, size, creation date) |
| `POST` | `/backups/create` | Admin | Creates a backup now; uses `pg_dump` if available, Python fallback otherwise |
| `GET` | `/backups/download/{filename}` | Admin | Serves the `.sql` file as a downloadable attachment |
| `POST` | `/backups/restore/{filename}` | Admin | Restores the database from the selected backup; requires `confirm=yes` form field |
| `GET` | `/backups/delete/{filename}` | Admin | Deletes a backup file from disk |

### Excel Import / Export

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/export` | Admin | Downloads all devices as `devices_export.xlsx`; excludes system-managed and password columns |
| `POST` | `/import` | Admin | Uploads a `.xlsx` file; inserts new rows and overwrites existing ones by MAC address; **JSON response** with `inserted`, `overwritten`, and `errors` counts |

---

## Setup and Running

### Prerequisites

- Python 3.9+
- PostgreSQL database

### 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure environment variables

Create `backend/.env`:

```env
DATABASE_URL=postgresql://<user>:<password>@<host>:<port>/<dbname>
SECRET_KEY=<any-random-string>
FERNET_KEY=<base64-fernet-key>
```

Generate a Fernet key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

All three variables are required. Missing `FERNET_KEY` raises a `RuntimeError` on first device-password access. A wrong `DATABASE_URL` causes a connection error on startup.

### 3. Initialise the database

```bash
cd backend
python init_db.py
```

Creates all six tables (`devices`, `users`, `change_logs`, `device_edit_history`, `device_requests`, `notifications`) and inserts a default admin user (`admin` / `admin123`). **Change the admin password immediately after first login** via the Change Password page or the admin Reset Password flow.

**Upgrading an existing database** — Run only the scripts for columns / tables that are missing:

```bash
python migrate_lease.py          # adds leasee_username, lease_expiry, lease_warning_sent, request_type columns
python add_password_column.py    # adds password column to devices
python create_history_table.py   # creates device_edit_history table
```

### 4. Run the server

```bash
cd backend
uvicorn main:app --reload
```

The app is available at `http://localhost:8000`.

On startup, the app:
1. Initialises a PostgreSQL connection pool (min 2 / max 10 connections).
2. Starts an APScheduler `BackgroundScheduler` with a weekly auto-backup job (first run: 1 minute after startup, then every 7 days).

### 5. Add users

Users can be added either via the web UI (**Users → Add User**, admin only) or the CLI:

```bash
cd backend
python add_user.py
```

### Deployment (Heroku)

The `backend/Procfile` is already configured:

```
web: uvicorn main:app --host 0.0.0.0 --port $PORT
```

Set `DATABASE_URL`, `SECRET_KEY`, and `FERNET_KEY` as Heroku config vars.

> **Note:** `pg_dump` is not available in the standard Heroku Python buildpack. Backups on Heroku will automatically use the Python fallback method.

---

## Known Limitations

| # | Area | Limitation |
|---|---|---|
| 1 | Lease expiry | Leases are only expired on inventory page load. If no user visits `/inventory`, overdue leases linger until the next visit. |
| 2 | Notifications | All notifications are in-app only. There is no email, SMS, or push notification support. |
| 3 | IP address on Add | Empty IP address fails validation — a placeholder must be entered if the device has no IP yet. The Edit Device form does not re-validate the IP field, so it can be cleared or left blank after editing. |
| 4 | Inventory pagination | The inventory page loads all matching devices at once. Very large inventories may result in slow page loads. |
| 5 | Backup restore is destructive | Restoring replaces all current data with no undo mechanism. Always download a fresh backup before restoring an older one. |
| 6 | Backup retention | Only the 7 most recent backup files are kept on disk. Older files are permanently deleted automatically. |
| 7 | Python backup fallback | The Python-based fallback does not replicate PostgreSQL-specific features (sequences post-insert, triggers, custom types). It covers the standard schema used by this application but is not a general-purpose dump tool. |
| 8 | Connection pool cap | The pool is limited to 10 connections. Under very heavy concurrent load, requests may block waiting for a free connection. |
| 9 | Short session lifetime | Sessions expire after 15 minutes with no "remember me" option. |
| 10 | No email password reset | Self-service password reset requires knowing the current password. If forgotten, an admin must use Reset Password. There is no email-based reset flow. |
| 11 | CLI `add_user.py` has no password-length rule | The script does not enforce the 6-character minimum that the web UI enforces. |
| 12 | No search on History page | The audit log page is paginated but has no search or filter controls. |
| 13 | `change_logs` not in UI | The higher-level event log is written to the database but is not exposed in any page; it must be queried directly. |

---

## Admin Utilities

These scripts run manually from the `backend/` directory. Most functionality is now also available through the web UI.

| Script | Purpose | Web UI equivalent |
|---|---|---|
| `init_db.py` | Create all tables and default admin user | None (run once at setup) |
| `migrate_lease.py` | Add lease/renewal columns to an existing database | None (run once per upgrade) |
| `add_password_column.py` | Add the `password` column to an existing devices table | None (run once per upgrade) |
| `create_history_table.py` | Create `device_edit_history` table on an existing database | None (run once per upgrade) |
| `add_user.py` | Interactively add a new user with any role | **Users → Add User** |
| `delete_user.py` | Delete a user and release all their devices | **Users → Delete** (also cancels pending requests) |
| `delete_device.py` | Delete a device by MAC address (or all devices with the master key) | **Inventory → Delete** button (admin) |

---

## License

This project is licensed under [CC BY-NC 4.0](LICENSE).  
Commercial use is not permitted. Attribution is required.
