# Lab Device Inventory Tool

A web-based internal tool for managing lab hardware. Teams can track device ownership, availability, and leases; request devices from other users; and get notified when requests are approved or leases expire — all through a browser UI with role-based access control.

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Backend framework | FastAPI | 0.115.0 |
| ASGI server | Uvicorn (standard) | 0.30.6 |
| Database | PostgreSQL | — |
| DB driver | psycopg2-binary | 2.9.9 |
| Authentication | PyJWT (HTTP-only cookie, HS256) | 2.9.0 |
| Password hashing | Werkzeug (`pbkdf2:sha256`) | 3.0.1 |
| Device password encryption | cryptography (Fernet symmetric) | 42.0.8 |
| Session / flash messages | itsdangerous + Starlette SessionMiddleware | 2.2.0 |
| Templating | Jinja2 | 3.1.4 |
| Form parsing | python-multipart | 0.0.9 |
| Environment config | python-dotenv | 1.0.1 |
| Frontend | HTML + CSS + vanilla JavaScript | — |
| Deployment | Heroku-compatible via Procfile | — |

---

## Project Structure

```
Lab_Inventory_tool-master/
│
├── backend/                          # All server-side Python code
│   ├── main.py                       # FastAPI app entry point; mounts routers and static files
│   ├── dependencies.py               # Shared helpers: JWT auth, flash messages, Jinja2 render, _require_login
│   ├── requirements.txt              # Python package dependencies
│   ├── Procfile                      # Heroku process definition (uvicorn)
│   ├── .env                          # Local environment variables (not committed to VCS)
│   │
│   ├── routers/                      # FastAPI route handlers, one file per domain
│   │   ├── auth.py                   # Login, logout, home redirect
│   │   ├── devices.py                # Full device CRUD, autocomplete API, reserve/release/claim/use/request/renew-lease
│   │   ├── history.py                # Paginated device-edit audit log
│   │   └── notifications.py          # Notification inbox, accept/decline device requests
│   │
│   ├── services/                     # Shared business-logic and I/O modules
│   │   ├── db.py                     # DB connection, log_change, log_device_edit, create_notification, get_unread_count
│   │   └── crypto.py                 # Fernet encrypt/decrypt for device passwords
│   │
│   ├── schemas/                      # Pydantic models (used for type reference)
│   │   └── device.py                 # DeviceCreate and DeviceEdit schemas
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
│       ├── layout.html               # Base layout: header, nav, flash messages, footer
│       ├── login.html                # Login form
│       ├── index.html                # Device inventory table with action buttons and search
│       ├── add_item.html             # Add new device form
│       ├── edit_item.html            # Edit existing device form
│       ├── history.html              # Paginated audit log table
│       └── notifications.html        # Notification inbox with accept/decline actions
│
├── LICENSE                           # CC BY-NC 4.0
└── README.md                         # This file
```

---

## Features

### Authentication
- **Login / Logout** — Username and password login; credentials verified with `pbkdf2:sha256` hashing. A signed JWT is issued on success and stored in an HTTP-only cookie (`access_token`).
- **Session expiry** — JWT and session middleware both expire after 15 minutes of inactivity.
- **Protected routes** — All routes except `/login` require a valid JWT; expired or missing tokens redirect to the login page.

### Role-Based Access Control
Two roles exist: `admin` and `user`.

| Capability | admin | user |
|---|---|---|
| View inventory | Yes | Yes |
| Add device (any owner) | Yes | Yes (owner forced to self) |
| Edit any device field (MAC, model, owner, lease note) | Yes | No |
| Edit own device fields (availability, IP, location, reporting manager, team) | Yes | Yes |
| Edit device password | Yes | Yes (own devices only) |
| Delete any device | Yes | No |
| Reveal device password | Yes (any device) | Yes (own devices only) |
| View audit history | Yes | Yes |
| Manage all notifications | Yes | Yes |

### Device Inventory (CRUD)
- **List devices** — Full inventory table showing MAC address, model, owner, availability, reporting manager, team, IP address, location, lease status, and password.
- **Add device** — Validates MAC address format (normalises to `AA:BB:CC:DD:EE:FF`) and IP address before inserting.
- **Edit device** — Admins can edit all fields including MAC, model, and owner; regular users can only edit availability, reporting manager, team, IP, and location. All changes are written to the audit log.
- **Delete device** — Admins only. Regular users cannot delete any device.
- **Duplicate MAC prevention** — Inserting or editing to an already-used MAC address is rejected.

### Search and Filter
- Full-text search across all device fields (MAC address, model, owner, availability, manager, team, IP, location, lease note, leasee username).
- Dropdown filter by availability status (`Available` / `In Use`).
- Both can be combined; a Clear button resets to the unfiltered view.

### Autocomplete on Forms
- The Add Device and Edit Device forms provide live autocomplete suggestions for the **Owner**, **Reporting Manager**, **Device Model**, and **Team** fields.
- Suggestions are drawn from existing data in the database (all registered usernames for Owner; distinct existing values for the other fields) via the `GET /api/autocomplete-options` JSON endpoint.
- Keyboard navigation (↑ / ↓ / Enter / Escape) and substring matching with highlighted matches are supported.

### Device Lifecycle (Claim → Use → Release)
- **Claim** — Any user can claim an unowned available device, provided there are no pending requests on it (devices with pending requests are locked from direct claim).
- **Use** — The owner of an available device marks it as `In Use`.
- **Release** — The owner releases the device, setting it back to `Available` with no owner. Cancels all pending requests and ends any active lease.

### Device Request and Approval System
- Any non-owner can submit a **request** to use an `In Use` device, specifying a desired lease end date (tomorrow through 7 days from today) using a custom calendar date picker.
- The device owner receives a **notification** with Accept / Decline buttons.
- On **Accept**: the requester is set as the leasee with the approved expiry date; competing pending requests are cancelled.
- On **Decline**: the requester is notified; the device state is unchanged.
- A user cannot submit a duplicate pending request for the same device.
- The inventory table shows a disabled "Requested" button while a pending request exists.

### Lease Management
- Each device tracks a current **leasee**, **lease expiry timestamp**, and a **warning-sent flag**.
- **Auto-expiry** — On every inventory page load, overdue leases are automatically cleared; the leasee, owner, and any pending requesters all receive notifications.
- **2-day warning** — Devices expiring within 2 days that have not yet had a warning sent trigger a notification to the leasee.
- **Lease renewal** — The current leasee can request an extension (1–7 days past the current expiry) using a calendar date picker pre-constrained to the valid renewal window. The owner can accept or decline via the notifications page.
- The inventory table shows the leasee username and formatted expiry date for each leased device.

### Password Management
- Device passwords are stored **Fernet-encrypted** in the database using a `FERNET_KEY` environment variable.
- Passwords are shown as `••••••••` in the inventory table.
- A **Show/Hide** button on each row makes a `GET /reveal-password/{id}` AJAX call; only the device owner or an admin can reveal the password.
- The edit form pre-populates the decrypted password for authorised users.

### Notifications
- In-app notification system: every system event (lease expiry, request received, request accepted/declined, lease warning) creates a notification row.
- The nav bar shows an **unread count badge** that updates on every page render.
- The notifications page lists all notifications with message, related device MAC, timestamp, request type, and current request status.
- Unread notifications are visually highlighted; all are marked read on page visit.

### Audit Log (History)
- **`device_edit_history`** records every field-level change: which field changed, old value, new value, who changed it, and when.
- **`change_logs`** records higher-level events (Reserve, Release, Claim, Use, Delete, Lease Started, etc.) as JSON detail blobs.
- The History page displays `device_edit_history` in reverse-chronological order, paginated at 10 rows per page.

---

## Database Schema

### `devices`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | SERIAL | PRIMARY KEY | Auto-incrementing row ID |
| `mac_address` | TEXT | UNIQUE NOT NULL | Normalised MAC (`AA:BB:CC:DD:EE:FF`) |
| `device_model` | TEXT | NOT NULL | Hardware model name |
| `owner` | TEXT | | Current owner username (empty = unowned) |
| `availability` | TEXT | CHECK (`Available` / `In Use`) | Current availability status |
| `reporting_manager` | TEXT | | Owner's reporting manager |
| `team` | TEXT | | Team the device belongs to |
| `ip_address` | TEXT | | Device IP address |
| `location` | TEXT | | Physical location |
| `lease` | TEXT | | Free-text lease note |
| `password` | TEXT | DEFAULT `''` | Fernet-encrypted device password |
| `leasee_username` | TEXT | | Username of the current leasee (NULL if none) |
| `lease_expiry` | TIMESTAMP | | When the current lease ends |
| `lease_warning_sent` | BOOLEAN | DEFAULT FALSE | Whether the 2-day expiry warning was sent |

### `users`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | SERIAL | PRIMARY KEY | Auto-incrementing row ID |
| `username` | TEXT | UNIQUE NOT NULL | Login username (stored lowercase) |
| `password` | TEXT | NOT NULL | `pbkdf2:sha256` hashed password |
| `role` | TEXT | CHECK (`admin` / `user`) | User role |

### `device_edit_history`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | SERIAL | PRIMARY KEY | Auto-incrementing row ID |
| `mac_address` | TEXT | NOT NULL | Device that was edited |
| `field_name` | TEXT | NOT NULL | Name of the field that changed |
| `old_value` | TEXT | | Value before the change |
| `new_value` | TEXT | | Value after the change |
| `changed_by` | TEXT | NOT NULL | Username who made the change (or `system`) |
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
| `request_status` | TEXT | DEFAULT `pending`, CHECK (`pending` / `accepted` / `declined` / `cancelled`) | Current status |
| `requested_at` | TIMESTAMP | NOT NULL DEFAULT NOW() | When the request was submitted |
| `resolved_at` | TIMESTAMP | | When the request was accepted/declined/cancelled |
| `requested_lease_date` | TIMESTAMP | | Desired lease end date provided by requester |
| `request_type` | TEXT | DEFAULT `request`, CHECK (`request` / `renewal`) | Whether this is a new request or a renewal |

### `notifications`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | SERIAL | PRIMARY KEY | Auto-incrementing row ID |
| `recipient_username` | TEXT | NOT NULL | User this notification is for |
| `message` | TEXT | NOT NULL | Human-readable notification text |
| `related_mac_address` | TEXT | | MAC address of the related device |
| `request_id` | INTEGER | REFERENCES `device_requests(id)` | Linked request row (NULL for system notifications) |
| `is_read` | BOOLEAN | NOT NULL DEFAULT FALSE | Whether the user has viewed it |
| `created_at` | TIMESTAMP | NOT NULL DEFAULT NOW() | When the notification was created |

---

## API Endpoints

All endpoints return HTML (Jinja2-rendered pages) except `/reveal-password/{id}` which returns JSON. Authentication is via an HTTP-only JWT cookie (`access_token`).

### Authentication

| Method | Path | Auth required | Description |
|---|---|---|---|
| `GET` | `/` | No | Redirects to `/inventory` if logged in, else `/login` |
| `GET` | `/login` | No | Renders the login form |
| `POST` | `/login` | No | Validates credentials; sets JWT cookie and redirects to `/inventory` |
| `GET` | `/logout` | No | Clears the JWT cookie and redirects to `/login` |

### Device Inventory

| Method | Path | Auth required | Description |
|---|---|---|---|
| `GET` | `/inventory` | Yes | Lists all devices; accepts `?search=` and `?availability=` query params |
| `GET` | `/add` | Yes | Renders the Add Device form |
| `POST` | `/add` | Yes | Creates a new device; validates MAC and IP formats |
| `GET` | `/edit/{id}` | Yes | Renders the Edit Device form (owner or admin only) |
| `POST` | `/edit/{id}` | Yes | Saves device edits; admins can edit all fields, users edit a subset |
| `GET` | `/delete/{id}` | Yes | Deletes a device (admin only) |
| `GET` | `/reveal-password/{id}` | Yes | Returns `{"password": "..."}` JSON (owner or admin only) |
| `GET` | `/api/autocomplete-options` | Yes | Returns `{"owners": [...], "reporting_managers": [...], "device_models": [...], "teams": [...]}` JSON for form autocomplete |

### Device Actions

| Method | Path | Auth required | Description |
|---|---|---|---|
| `POST` | `/claim/{id}` | Yes | Claims an unowned available device |
| `POST` | `/use/{id}` | Yes | Marks an owned available device as In Use |
| `POST` | `/reserve/{id}` | Yes | Reserves an available device (sets owner + In Use in one step) |
| `POST` | `/release/{id}` | Yes | Releases an In Use device back to Available (owner only) |
| `POST` | `/request/{id}` | Yes | Submits a lease request to the device owner |
| `POST` | `/renew-lease/{id}` | Yes | Submits a lease renewal request (leasee only) |

### Notifications

| Method | Path | Auth required | Description |
|---|---|---|---|
| `GET` | `/notifications` | Yes | Renders notification inbox; marks all as read |
| `POST` | `/accept-request/{request_id}` | Yes | Accepts a pending device request or renewal (owner only) |
| `POST` | `/decline-request/{request_id}` | Yes | Declines a pending device request or renewal (owner only) |
| `POST` | `/notifications/mark-read` | Yes | Marks all notifications as read for the current user |

### History

| Method | Path | Auth required | Description |
|---|---|---|---|
| `GET` | `/history` | Yes | Renders paginated field-level audit log; accepts `?page=` query param (10 rows per page) |

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

### 3. Initialise the database

```bash
cd backend
python init_db.py
```

This creates all tables and inserts a default admin user (`admin` / `admin123`). **Change the admin password immediately after first login.**

If upgrading an existing database, run the migration script:

```bash
python migrate_lease.py
```

### 4. Add users

```bash
python add_user.py
```

### 5. Run the server

```bash
cd backend
uvicorn main:app --reload
```

The app is available at `http://localhost:8000`.

### Deployment (Heroku)

The `backend/Procfile` is already configured:

```
web: uvicorn main:app --host 0.0.0.0 --port $PORT
```

Set `DATABASE_URL`, `SECRET_KEY`, and `FERNET_KEY` as Heroku config vars.

---

## Admin Utilities

These scripts are run manually from the `backend/` directory:

| Script | Purpose |
|---|---|
| `init_db.py` | Create all tables and default admin user |
| `migrate_lease.py` | Add lease columns to an existing database |
| `add_user.py` | Interactively add a new user with any role |
| `add_password_column.py` | Add the password column to an existing devices table |
| `create_history_table.py` | Create the device_edit_history table on an existing database |
| `delete_user.py` | Delete a user and release all their devices |
| `delete_device.py` | Delete a specific device by MAC address |

---

## License

This project is licensed under [CC BY-NC 4.0](LICENSE).  
Commercial use is not permitted. Attribution is required.
