import ipaddress
import re
from typing import Optional

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from dependencies import flash, get_current_user, render
from services.db import get_db_connection, log_change

router = APIRouter()


def format_mac_address(mac: str) -> str:
    """Formats MAC to 00:1A:2B:3C:4D:5E and checks length."""
    mac = re.sub(r"[^a-fA-F0-9]", "", mac).upper()
    if len(mac) != 12:
        raise ValueError("MAC address must have exactly 12 hexadecimal digits.")
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2))


def validate_ip(ip: str) -> bool:
    """Returns True if ip is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _require_login(request: Request):
    """Returns the current user or None after storing a flash message."""
    user = get_current_user(request)
    if not user:
        flash(request, "Session expired or you are not logged in.", "danger")
    return user


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
                lease LIKE %s
            )
        """
        params.extend([like] * 9)

    if availability:
        query += " AND availability = %s"
        params.append(availability)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, params)
    devices = cur.fetchall()
    conn.close()

    return render("index.html", request, {"devices": devices})


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

    # Role 'user' always owns the device themselves
    actual_owner = user["username"] if user.get("role") == "user" else owner

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM devices WHERE mac_address = %s", (mac,))
    if cur.fetchone():
        conn.close()
        flash(request, "MAC address already exists.", "danger")
        return RedirectResponse(url="/add", status_code=303)

    cur.execute(
        """
        INSERT INTO devices
            (mac_address, device_model, owner, availability, reporting_manager, team, ip_address, location, lease)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (mac, device_model, actual_owner, availability, reporting_manager, team, ip_address, location, lease),
    )
    conn.commit()
    conn.close()
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
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()
    conn.close()

    if not device:
        flash(request, "Device not found", "danger")
        return RedirectResponse(url="/inventory", status_code=302)

    if not (user.get("role") == "admin" or device["owner"] == user["username"]):
        flash(request, "Access denied. Only the owner or an admin can edit this device.", "danger")
        return RedirectResponse(url="/inventory", status_code=302)

    return render("edit_item.html", request, {"device": dict(device)})


@router.post("/edit/{id}")
def edit_item_post(
    id: int,
    request: Request,
    availability: str = Form(...),
    reporting_manager: str = Form(""),
    team: str = Form(""),
    ip_address: str = Form(""),
    location: str = Form(""),
):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        conn.close()
        flash(request, "Device not found", "danger")
        return RedirectResponse(url="/inventory", status_code=302)

    if not (user.get("role") == "admin" or device["owner"] == user["username"]):
        conn.close()
        flash(request, "Access denied. Only the owner or an admin can edit this device.", "danger")
        return RedirectResponse(url="/inventory", status_code=302)

    cur.execute(
        """
        UPDATE devices
        SET mac_address = %s, device_model = %s, owner = %s, availability = %s,
            reporting_manager = %s, team = %s, ip_address = %s, location = %s, lease = %s
        WHERE id = %s
        """,
        (
            device["mac_address"],
            device["device_model"],
            device["owner"],
            availability,
            reporting_manager,
            team,
            ip_address,
            location,
            device["lease"],
            id,
        ),
    )
    conn.commit()
    conn.close()
    flash(request, "Device updated successfully.", "success")
    return RedirectResponse(url="/inventory", status_code=303)


# ---------------------------------------------------------------------------
# Reserve / Release / Request
# ---------------------------------------------------------------------------

@router.post("/reserve/{id}", name="reserve_device")
def reserve_device(id: int, request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        conn.close()
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

    conn.close()
    return RedirectResponse(url="/inventory", status_code=303)


@router.post("/release/{id}", name="release_device")
def release_device(id: int, request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        conn.close()
        flash(request, "Device not found.", "danger")
        return RedirectResponse(url="/inventory", status_code=303)

    if device["availability"] == "In Use" and device["owner"] == user["username"]:
        cur.execute(
            "UPDATE devices SET availability = %s, owner = %s WHERE id = %s",
            ("Available", "", id),
        )
        conn.commit()
        log_change(user["username"], "Release", device["mac_address"], {"released_by": user["username"]})
        flash(request, "Device released successfully.", "success")
    else:
        flash(request, "You are not allowed to release this device.", "danger")

    conn.close()
    return RedirectResponse(url="/inventory", status_code=303)


@router.post("/request/{id}", name="request_device")
def request_device(id: int, request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()
    conn.close()

    if not device:
        flash(request, "Device not found.", "danger")
    elif device["owner"] == user["username"]:
        flash(request, "You already own this device.", "info")
    else:
        flash(request, f"Request sent to owner ({device['owner']}) to use this device.", "success")

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
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()

    if not device:
        conn.close()
        flash(request, "Device not found", "danger")
        return RedirectResponse(url="/inventory", status_code=302)

    if user.get("role") == "user":
        if device["owner"] != user["username"] and device["availability"] != "Available":
            conn.close()
            flash(request, "Access denied. You can't delete devices owned by others.", "danger")
            return RedirectResponse(url="/inventory", status_code=302)

    cur.execute("DELETE FROM devices WHERE id = %s", (id,))
    conn.commit()
    log_change(user["username"], "Delete", device["mac_address"], dict(device))
    conn.close()
    return RedirectResponse(url="/inventory", status_code=302)
