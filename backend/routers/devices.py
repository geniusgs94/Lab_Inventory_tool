import ipaddress
import re
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from psycopg2.extras import RealDictCursor

from dependencies import flash, render, _require_login
from services.crypto import decrypt_password, encrypt_password
from services.db import create_notification, get_db_connection, log_change, log_device_edit, return_db_connection

router = APIRouter()


def format_mac_address(mac: str) -> str:
    mac = re.sub(r"[^a-fA-F0-9]", "", mac).upper()
    if len(mac) != 12:
        raise ValueError("MAC address must have exactly 12 hexadecimal digits.")
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2))


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def check_and_expire_leases():
    """Expire overdue leases and send 2-day warning notifications. Called on every inventory load."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute(
        "SELECT id, mac_address, leasee_username, lease_expiry, owner, lease_warning_sent "
        "FROM devices WHERE leasee_username IS NOT NULL AND lease_expiry IS NOT NULL"
    )
    leased_devices = cur.fetchall()

    now = datetime.now()

    expired_devices = [d for d in leased_devices if d["lease_expiry"] < now]
    warning_devices = [
        d for d in leased_devices
        if now < d["lease_expiry"] <= now + timedelta(days=2)
        and not d.get("lease_warning_sent")
    ]

    # --- Handle expired leases ---
    expired_info = []
    for device in expired_devices:
        mac = device["mac_address"]
        leasee = device["leasee_username"]
        owner = device["owner"] or ""

        # Collect pending requests before cancelling them
        cur.execute(
            "SELECT id, requester_username FROM device_requests "
            "WHERE mac_address = %s AND request_status = 'pending'",
            (mac,)
        )
        pending_requests = cur.fetchall()

        cur.execute(
            "UPDATE device_requests SET request_status = 'cancelled', resolved_at = NOW() "
            "WHERE mac_address = %s AND request_status = 'pending'",
            (mac,)
        )
        cur.execute(
            "UPDATE devices SET leasee_username = NULL, lease_expiry = NULL, "
            "lease_warning_sent = FALSE WHERE id = %s",
            (device["id"],)
        )
        expired_info.append({
            "mac": mac,
            "leasee": leasee,
            "owner": owner,
            "lease_expiry": device["lease_expiry"],
            "pending_requesters": [r["requester_username"] for r in pending_requests
                                   if r["requester_username"] != leasee],
        })

    # --- Mark 2-day warnings as sent ---
    warning_info = []
    for device in warning_devices:
        cur.execute(
            "UPDATE devices SET lease_warning_sent = TRUE WHERE id = %s",
            (device["id"],)
        )
        warning_info.append({
            "mac": device["mac_address"],
            "leasee": device["leasee_username"],
            "expiry": device["lease_expiry"],
        })

    conn.commit()
    return_db_connection(conn)

    # --- Fire notifications and audit logs (each uses its own connection) ---
    for info in expired_info:
        mac = info["mac"]
        leasee = info["leasee"]
        owner = info["owner"]
        expiry_str = info["lease_expiry"].strftime("%Y-%m-%d") if info["lease_expiry"] else ""

        log_device_edit(mac, "leasee_username", leasee, "", "system")
        log_device_edit(mac, "lease_expiry", expiry_str, "", "system")

        create_notification(
            recipient_username=leasee,
            message=f"Your lease for device {mac} has expired.",
            related_mac_address=mac,
        )
        if owner:
            create_notification(
                recipient_username=owner,
                message=f"Lease for your device {mac} by {leasee} has expired. Device is back with you.",
                related_mac_address=mac,
            )
        for requester in info["pending_requesters"]:
            create_notification(
                recipient_username=requester,
                message=f"Device {mac} is now available. You can request it again.",
                related_mac_address=mac,
            )

    for info in warning_info:
        expiry_str = info["expiry"].strftime("%Y-%m-%d") if info["expiry"] else ""
        create_notification(
            recipient_username=info["leasee"],
            message=f"Your lease for device {info['mac']} expires on {expiry_str}. Renew now.",
            related_mac_address=info["mac"],
        )


# ---------------------------------------------------------------------------
# Autocomplete options
# ---------------------------------------------------------------------------

@router.get("/api/autocomplete-options")
def autocomplete_options(request: Request):
    user = _require_login(request)
    if not user:
        return JSONResponse({"error": "Not logged in"}, status_code=401)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT username FROM users ORDER BY username")
    owners = [row["username"] for row in cur.fetchall()]

    cur.execute(
        "SELECT DISTINCT reporting_manager FROM devices "
        "WHERE reporting_manager IS NOT NULL AND reporting_manager != '' "
        "ORDER BY reporting_manager"
    )
    reporting_managers = [row["reporting_manager"] for row in cur.fetchall()]

    cur.execute(
        "SELECT DISTINCT device_model FROM devices "
        "WHERE device_model IS NOT NULL AND device_model != '' "
        "ORDER BY device_model"
    )
    device_models = [row["device_model"] for row in cur.fetchall()]

    cur.execute(
        "SELECT DISTINCT team FROM devices "
        "WHERE team IS NOT NULL AND team != '' "
        "ORDER BY team"
    )
    teams = [row["team"] for row in cur.fetchall()]

    return_db_connection(conn)

    return JSONResponse({
        "owners": owners,
        "reporting_managers": reporting_managers,
        "device_models": device_models,
        "teams": teams,
    })


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

@router.get("/inventory", name="inventory")
def inventory(
    request: Request,
    search: Optional[str] = None,
    availability: Optional[str] = None,
):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    check_and_expire_leases()

    query = "SELECT * FROM devices WHERE 1=1"
    params = []

    if search:
        like = f"%{search}%"
        query += """
            AND (
                mac_address LIKE %s OR
                device_model LIKE %s OR
                owner LIKE %s OR
                availability LIKE %s OR
                reporting_manager LIKE %s OR
                team LIKE %s OR
                ip_address LIKE %s OR
                location LIKE %s OR
                lease LIKE %s OR
                leasee_username LIKE %s
            )
        """
        params.extend([like] * 10)

    if availability:
        query += " AND availability = %s"
        params.append(availability)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(query, params)
    devices = cur.fetchall()

    cur.execute(
        "SELECT mac_address FROM device_requests "
        "WHERE requester_username = %s AND request_status = 'pending' AND request_type = 'request'",
        (user["username"],)
    )
    my_pending_macs = {row["mac_address"] for row in cur.fetchall()}

    cur.execute(
        "SELECT mac_address FROM device_requests "
        "WHERE requester_username = %s AND request_status = 'pending' AND request_type = 'renewal'",
        (user["username"],)
    )
    my_pending_renewal_macs = {row["mac_address"] for row in cur.fetchall()}

    cur.execute("SELECT DISTINCT mac_address FROM device_requests WHERE request_status = 'pending'")
    pending_macs = {row["mac_address"] for row in cur.fetchall()}

    return_db_connection(conn)

    return render("index.html", request, {
        "devices": devices,
        "my_pending_macs": my_pending_macs,
        "my_pending_renewal_macs": my_pending_renewal_macs,
        "pending_macs": pending_macs,
    })


# ---------------------------------------------------------------------------
# Add device
# ---------------------------------------------------------------------------

@router.get("/add", name="add_item")
def add_item_get(request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return render("add_item.html", request)


@router.post("/add")
def add_item_post(
    request: Request,
    mac_address: str = Form(...),
    device_model: str = Form(...),
    owner: str = Form(...),
    availability: str = Form(...),
    reporting_manager: str = Form(""),
    team: str = Form(""),
    ip_address: str = Form(""),
    location: str = Form(""),
    lease: str = Form(""),
    password: str = Form(""),
):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    try:
        mac = format_mac_address(mac_address)
    except ValueError as e:
        flash(request, str(e), "danger")
        return RedirectResponse(url="/add", status_code=303)

    if not validate_ip(ip_address):
        flash(request, "Invalid IP address format", "danger")
        return RedirectResponse(url="/add", status_code=303)

    actual_owner = user["username"] if user.get("role") == "user" else owner

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT 1 FROM devices WHERE mac_address = %s", (mac,))
    if cur.fetchone():
        return_db_connection(conn)
        flash(request, "MAC address already exists.", "danger")
        return RedirectResponse(url="/add", status_code=303)

    encrypted_password = encrypt_password(password)

    cur.execute(
        """
        INSERT INTO devices
            (mac_address, device_model, owner, availability, reporting_manager, team, ip_address, location, lease, password)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (mac, device_model, actual_owner, availability, reporting_manager, team, ip_address, location, lease, encrypted_password),
    )
    conn.commit()
    return_db_connection(conn)
    return RedirectResponse(url="/inventory", status_code=303)


# ---------------------------------------------------------------------------
# Edit device
# ---------------------------------------------------------------------------

@router.get("/edit/{id}", name="edit_item")
def edit_item_get(id: int, request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()
    return_db_connection(conn)

    if not device:
        flash(request, "Device not found", "danger")
        return RedirectResponse(url="/inventory", status_code=302)

    if not (user.get("role") == "admin" or device["owner"] == user["username"]):
        flash(request, "Access denied. Only the owner or an admin can edit this device.", "danger")
        return RedirectResponse(url="/inventory", status_code=302)

    device_dict = dict(device)
    device_dict["decrypted_password"] = decrypt_password(device_dict.get("password", "") or "")
    return render("edit_item.html", request, {"device": device_dict})


@router.post("/edit/{id}")
def edit_item_post(
    id: int,
    request: Request,
    availability: str = Form(...),
    reporting_manager: str = Form(""),
    team: str = Form(""),
    ip_address: str = Form(""),
    location: str = Form(""),
    password: str = Form(""),
    owner: str = Form(""),
    mac_address: str = Form(""),
    device_model: str = Form(""),
    lease: str = Form(""),
):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        return_db_connection(conn)
        flash(request, "Device not found", "danger")
        return RedirectResponse(url="/inventory", status_code=302)

    if not (user.get("role") == "admin" or device["owner"] == user["username"]):
        return_db_connection(conn)
        flash(request, "Access denied. Only the owner or an admin can edit this device.", "danger")
        return RedirectResponse(url="/inventory", status_code=403)

    is_admin = user.get("role") == "admin"

    # Admins can change mac_address, device_model, owner, lease; regular users cannot
    if is_admin:
        new_owner = owner.strip()
        new_device_model = device_model.strip()
        new_lease = lease.strip()
        try:
            new_mac = format_mac_address(mac_address) if mac_address.strip() else device["mac_address"]
        except ValueError as e:
            return_db_connection(conn)
            flash(request, str(e), "danger")
            return RedirectResponse(url=f"/edit/{id}", status_code=303)
        # Reject if the new MAC is already taken by a different device
        if new_mac != device["mac_address"]:
            cur.execute("SELECT 1 FROM devices WHERE mac_address = %s AND id != %s", (new_mac, id))
            if cur.fetchone():
                return_db_connection(conn)
                flash(request, "MAC address already exists on another device.", "danger")
                return RedirectResponse(url=f"/edit/{id}", status_code=303)
    else:
        new_mac = device["mac_address"]
        new_device_model = device["device_model"]
        new_owner = device["owner"]
        new_lease = device["lease"]

    editable_fields = {
        "availability": availability,
        "reporting_manager": reporting_manager,
        "team": team,
        "ip_address": ip_address,
        "location": location,
    }
    if is_admin:
        editable_fields["mac_address"] = new_mac
        editable_fields["device_model"] = new_device_model
        editable_fields["owner"] = new_owner
        editable_fields["lease"] = new_lease

    changes = [
        (field, str(device[field] or ""), str(new_val))
        for field, new_val in editable_fields.items()
        if str(device[field] or "") != str(new_val)
    ]

    old_password_plain = decrypt_password(device.get("password", "") or "")
    password_changed = old_password_plain != password
    encrypted_password = encrypt_password(password)

    cur.execute(
        """
        UPDATE devices
        SET mac_address = %s, device_model = %s, owner = %s, availability = %s,
            reporting_manager = %s, team = %s, ip_address = %s, location = %s, lease = %s,
            password = %s
        WHERE id = %s
        """,
        (
            new_mac,
            new_device_model,
            new_owner,
            availability,
            reporting_manager,
            team,
            ip_address,
            location,
            new_lease,
            encrypted_password,
            id,
        ),
    )
    conn.commit()
    return_db_connection(conn)

    for field, old_val, new_val in changes:
        log_device_edit(device["mac_address"], field, old_val, new_val, user["username"])

    if password_changed:
        log_device_edit(device["mac_address"], "password", "****", "****", user["username"])

    flash(request, "Device updated successfully.", "success")
    return RedirectResponse(url="/inventory", status_code=303)


# ---------------------------------------------------------------------------
# Reveal password
# ---------------------------------------------------------------------------

@router.get("/reveal-password/{id}", name="reveal_password")
def reveal_password(id: int, request: Request):
    user = _require_login(request)
    if not user:
        return JSONResponse({"error": "Not logged in"}, status_code=401)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()
    return_db_connection(conn)

    if not device:
        return JSONResponse({"error": "Device not found"}, status_code=404)

    if not (user.get("role") == "admin" or device["owner"] == user["username"]):
        return JSONResponse({"error": "Access denied"}, status_code=403)

    plain = decrypt_password(device.get("password", "") or "")
    return JSONResponse({"password": plain})


# ---------------------------------------------------------------------------
# Reserve / Release / Claim / Use / Request / Renew Lease
# ---------------------------------------------------------------------------

@router.post("/reserve/{id}", name="reserve_device")
def reserve_device(id: int, request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        return_db_connection(conn)
        flash(request, "Device not found.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    if device["availability"] == "Available":
        cur.execute(
            "UPDATE devices SET availability = %s, owner = %s WHERE id = %s",
            ("In Use", user["username"], id),
        )
        conn.commit()
        log_change(user["username"], "Reserve", device["mac_address"], {"new_owner": user["username"]})
        flash(request, "Device reserved successfully.", "success")
    else:
        flash(request, "Device is not available for reservation.", "danger")

    return_db_connection(conn)
    return RedirectResponse(url="/inventory", status_code=303)


@router.post("/release/{id}", name="release_device")
def release_device(id: int, request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        return_db_connection(conn)
        flash(request, "Device not found.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    owner = device["owner"] or ""
    if device["availability"] == "In Use" and owner.strip().lower() == user["username"].lower():
        mac = device["mac_address"]
        leasee = device.get("leasee_username") or ""
        lease_expiry = device.get("lease_expiry")

        cur.execute(
            "UPDATE device_requests SET request_status = 'cancelled', resolved_at = NOW() "
            "WHERE mac_address = %s AND request_status = 'pending'",
            (mac,)
        )
        cur.execute(
            "UPDATE devices SET availability = %s, owner = %s, "
            "leasee_username = NULL, lease_expiry = NULL, lease_warning_sent = FALSE WHERE id = %s",
            ("Available", "", id),
        )
        conn.commit()

        log_device_edit(mac, "availability", "In Use", "Available", user["username"])
        log_device_edit(mac, "owner", owner, "", user["username"])
        if leasee:
            log_device_edit(mac, "leasee_username", leasee, "", user["username"])
            log_device_edit(mac, "lease_expiry", str(lease_expiry or ""), "", user["username"])

        log_change(user["username"], "Release", mac, {"released_by": user["username"]})

        if leasee:
            create_notification(
                recipient_username=leasee,
                message=f"Your lease for device {mac} has been ended by the owner.",
                related_mac_address=mac,
            )

        flash(request, "Device released successfully.", "success")
    else:
        flash(request, "You are not allowed to release this device.", "danger")

    return_db_connection(conn)
    return RedirectResponse(url="/inventory", status_code=303)


@router.post("/request/{id}", name="request_device")
def request_device(
    id: int,
    request: Request,
    requested_lease_date: str = Form(...),
):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    try:
        lease_date = datetime.strptime(requested_lease_date, "%Y-%m-%d")
    except ValueError:
        flash(request, "Invalid lease date format.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    now = datetime.now()
    if lease_date.date() <= now.date():
        flash(request, "Lease end date must be in the future.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)
    if lease_date > now + timedelta(days=7):
        flash(request, "Lease end date cannot be more than 7 days from today.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        return_db_connection(conn)
        flash(request, "Device not found.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    owner = device["owner"] or ""
    if owner.strip().lower() == user["username"].lower():
        return_db_connection(conn)
        flash(request, "You already own this device.", "info")
        return RedirectResponse(url="/inventory", status_code=303)

    if device["availability"] != "In Use":
        return_db_connection(conn)
        flash(request, "You can only request a device that is currently In Use.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    cur.execute(
        "SELECT 1 FROM device_requests WHERE mac_address = %s AND requester_username = %s "
        "AND request_status = 'pending' AND request_type = 'request'",
        (device["mac_address"], user["username"])
    )
    if cur.fetchone():
        return_db_connection(conn)
        flash(request, "You already have a pending request for this device.", "info")
        return RedirectResponse(url="/inventory", status_code=303)

    cur.execute(
        "INSERT INTO device_requests "
        "(mac_address, requester_username, request_status, request_type, requested_lease_date, requested_at) "
        "VALUES (%s, %s, 'pending', 'request', %s, NOW()) RETURNING id",
        (device["mac_address"], user["username"], lease_date)
    )
    request_row = cur.fetchone()
    request_id = request_row["id"]
    conn.commit()
    return_db_connection(conn)

    create_notification(
        recipient_username=owner.strip(),
        message=(
            f"User {user['username']} has requested device {device['mac_address']} "
            f"(lease until {lease_date.strftime('%Y-%m-%d')})"
        ),
        related_mac_address=device["mac_address"],
        request_id=request_id,
    )

    flash(request, f"Request sent to owner ({owner.strip()}).", "success")
    return RedirectResponse(url="/inventory", status_code=303)


@router.post("/renew-lease/{id}", name="renew_lease")
def renew_lease(
    id: int,
    request: Request,
    requested_lease_date: str = Form(...),
):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    try:
        renewal_date = datetime.strptime(requested_lease_date, "%Y-%m-%d")
    except ValueError:
        flash(request, "Invalid date format.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        return_db_connection(conn)
        flash(request, "Device not found.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    leasee = device.get("leasee_username") or ""
    if leasee.strip().lower() != user["username"].lower():
        return_db_connection(conn)
        flash(request, "You are not the current leasee of this device.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    current_expiry = device.get("lease_expiry")
    if not current_expiry:
        return_db_connection(conn)
        flash(request, "No active lease found.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    if renewal_date <= current_expiry:
        return_db_connection(conn)
        flash(request, "Renewal date must be after the current lease expiry.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    max_renewal = current_expiry + timedelta(days=7)
    if renewal_date > max_renewal:
        return_db_connection(conn)
        flash(
            request,
            f"Renewal date cannot exceed 7 days from current expiry ({current_expiry.strftime('%Y-%m-%d')}).",
            "danger",
        )
        return RedirectResponse(url="/inventory", status_code=303)

    cur.execute(
        "SELECT 1 FROM device_requests WHERE mac_address = %s AND requester_username = %s "
        "AND request_status = 'pending' AND request_type = 'renewal'",
        (device["mac_address"], user["username"])
    )
    if cur.fetchone():
        return_db_connection(conn)
        flash(request, "You already have a pending renewal request for this device.", "info")
        return RedirectResponse(url="/inventory", status_code=303)

    cur.execute(
        "INSERT INTO device_requests "
        "(mac_address, requester_username, request_status, request_type, requested_lease_date, requested_at) "
        "VALUES (%s, %s, 'pending', 'renewal', %s, NOW()) RETURNING id",
        (device["mac_address"], user["username"], renewal_date)
    )
    request_row = cur.fetchone()
    request_id = request_row["id"]
    conn.commit()
    return_db_connection(conn)

    owner = device["owner"] or ""
    create_notification(
        recipient_username=owner.strip(),
        message=(
            f"User {user['username']} has requested a lease renewal for device "
            f"{device['mac_address']} until {renewal_date.strftime('%Y-%m-%d')}."
        ),
        related_mac_address=device["mac_address"],
        request_id=request_id,
    )

    flash(request, f"Renewal request sent to owner ({owner.strip()}).", "success")
    return RedirectResponse(url="/inventory", status_code=303)


@router.post("/claim/{id}", name="claim_device")
def claim_device(id: int, request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        return_db_connection(conn)
        flash(request, "Device not found.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    owner = device["owner"] or ""
    if device["availability"] != "Available" or owner.strip():
        return_db_connection(conn)
        flash(request, "Device is not available to claim.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    cur.execute(
        "SELECT 1 FROM device_requests WHERE mac_address = %s AND request_status = 'pending'",
        (device["mac_address"],)
    )
    if cur.fetchone():
        return_db_connection(conn)
        flash(request, "This device has a pending request and cannot be claimed.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    cur.execute("UPDATE devices SET owner = %s WHERE id = %s", (user["username"], id))
    conn.commit()
    log_device_edit(device["mac_address"], "owner", "", user["username"], user["username"])
    log_change(user["username"], "Claim", device["mac_address"], {"new_owner": user["username"]})
    return_db_connection(conn)
    flash(request, "Device claimed. Click 'Use' to mark it as In Use.", "success")
    return RedirectResponse(url="/inventory", status_code=303)


@router.post("/use/{id}", name="use_device")
def use_device(id: int, request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        return_db_connection(conn)
        flash(request, "Device not found.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    owner = device["owner"] or ""
    if owner.strip().lower() != user["username"].lower():
        return_db_connection(conn)
        flash(request, "You are not the owner of this device.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    if device["availability"] != "Available":
        return_db_connection(conn)
        flash(request, "Device is already marked as In Use.", "info")
        return RedirectResponse(url="/inventory", status_code=303)

    cur.execute("UPDATE devices SET availability = %s WHERE id = %s", ("In Use", id))
    conn.commit()
    log_device_edit(device["mac_address"], "availability", "Available", "In Use", user["username"])
    log_change(user["username"], "Use", device["mac_address"], {"used_by": user["username"]})
    return_db_connection(conn)
    flash(request, "Device is now marked as In Use.", "success")
    return RedirectResponse(url="/inventory", status_code=303)


# ---------------------------------------------------------------------------
# Delete device
# ---------------------------------------------------------------------------

@router.get("/delete/{id}", name="delete_item")
def delete_item(id: int, request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        return_db_connection(conn)
        flash(request, "Device not found", "danger")
        return RedirectResponse(url="/inventory", status_code=302)

    if user.get("role") != "admin":
        return_db_connection(conn)
        flash(request, "Only admins can delete devices.", "danger")
        return RedirectResponse(url="/inventory", status_code=302)

    cur.execute("DELETE FROM devices WHERE id = %s", (id,))
    conn.commit()
    log_change(user["username"], "Delete", device["mac_address"], dict(device))
    return_db_connection(conn)
    return RedirectResponse(url="/inventory", status_code=302)
