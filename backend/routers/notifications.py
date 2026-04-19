from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from psycopg2.extras import RealDictCursor

from dependencies import flash, render, _require_login
from services.db import create_notification, get_db_connection, log_change, log_device_edit, return_db_connection

router = APIRouter()


@router.get("/notifications", name="notifications")
def notifications_page(request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        """
        SELECT n.id, n.message, n.related_mac_address, n.request_id, n.is_read, n.created_at,
               dr.request_status, dr.requester_username, dr.request_type, dr.requested_lease_date
        FROM notifications n
        LEFT JOIN device_requests dr ON n.request_id = dr.id
        WHERE n.recipient_username = %s
        ORDER BY n.created_at DESC
        """,
        (user["username"],)
    )
    notifications = cur.fetchall()

    cur.execute(
        "UPDATE notifications SET is_read = TRUE WHERE recipient_username = %s AND is_read = FALSE",
        (user["username"],)
    )
    conn.commit()
    return_db_connection(conn)

    return render("notifications.html", request, {"notifications": notifications})


@router.post("/accept-request/{request_id}", name="accept_request")
def accept_request(request_id: int, request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT * FROM device_requests WHERE id = %s", (request_id,))
    req = cur.fetchone()

    if not req:
        return_db_connection(conn)
        flash(request, "Request not found.", "danger")
        return RedirectResponse(url="/notifications", status_code=303)

    if req["request_status"] != "pending":
        return_db_connection(conn)
        flash(request, "This request is no longer pending.", "info")
        return RedirectResponse(url="/notifications", status_code=303)

    cur.execute("SELECT * FROM devices WHERE mac_address = %s", (req["mac_address"],))
    device = cur.fetchone()

    if not device:
        return_db_connection(conn)
        flash(request, "Device not found.", "danger")
        return RedirectResponse(url="/notifications", status_code=303)

    owner = device["owner"] or ""
    if owner.strip().lower() != user["username"].lower():
        return_db_connection(conn)
        flash(request, "Access denied. You are not the owner of this device.", "danger")
        return RedirectResponse(url="/notifications", status_code=303)

    mac = req["mac_address"]
    requester = req["requester_username"]
    lease_date = req["requested_lease_date"]
    request_type = req.get("request_type") or "request"

    cur.execute(
        "UPDATE device_requests SET request_status = 'accepted', resolved_at = NOW() WHERE id = %s",
        (request_id,)
    )

    if request_type == "renewal":
        # Extend existing lease expiry
        old_expiry = device.get("lease_expiry")
        cur.execute(
            "UPDATE devices SET lease_expiry = %s, lease_warning_sent = FALSE WHERE mac_address = %s",
            (lease_date, mac),
        )
        conn.commit()

        log_device_edit(mac, "lease_expiry", str(old_expiry or ""), str(lease_date or ""), user["username"])
        log_change(user["username"], "Lease Renewal Approved", mac, {
            "leasee": requester,
            "new_expiry": str(lease_date),
        })

        expiry_str = lease_date.strftime("%b %d, %Y") if lease_date else "N/A"
        create_notification(
            recipient_username=requester,
            message=f"Your lease renewal for device {mac} has been approved until {expiry_str}.",
            related_mac_address=mac,
            request_id=request_id,
        )
        flash(request, f"Lease renewal for {mac} approved until {expiry_str}.", "success")

    else:
        # New lease request — set leasee, keep owner + availability unchanged
        # Cancel all other pending 'request' type requests for this MAC
        cur.execute(
            "UPDATE device_requests SET request_status = 'cancelled', resolved_at = NOW() "
            "WHERE mac_address = %s AND request_status = 'pending' AND request_type = 'request' AND id != %s",
            (mac, request_id)
        )

        # If there's already a leasee, record it for notification
        existing_leasee = device.get("leasee_username") or ""

        cur.execute(
            "UPDATE devices SET leasee_username = %s, lease_expiry = %s, lease_warning_sent = FALSE "
            "WHERE mac_address = %s",
            (requester, lease_date, mac),
        )
        conn.commit()

        log_device_edit(mac, "leasee_username", existing_leasee, requester, user["username"])
        log_device_edit(mac, "lease_expiry", str(device.get("lease_expiry") or ""), str(lease_date or ""), user["username"])
        log_change(user["username"], "Lease Started", mac, {
            "leasee": requester,
            "expiry": str(lease_date),
        })

        # Notify old leasee if their lease was overridden
        if existing_leasee and existing_leasee.lower() != requester.lower():
            create_notification(
                recipient_username=existing_leasee,
                message=f"Your lease for device {mac} has been ended by the owner.",
                related_mac_address=mac,
            )

        expiry_str = lease_date.strftime("%b %d, %Y") if lease_date else "N/A"
        create_notification(
            recipient_username=requester,
            message=f"Your request for device {mac} has been approved. Lease until {expiry_str}.",
            related_mac_address=mac,
            request_id=request_id,
        )
        flash(request, f"Request accepted. {requester} is now leasing {mac} until {expiry_str}.", "success")

    return_db_connection(conn)
    return RedirectResponse(url="/notifications", status_code=303)


@router.post("/decline-request/{request_id}", name="decline_request")
def decline_request(request_id: int, request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT * FROM device_requests WHERE id = %s", (request_id,))
    req = cur.fetchone()

    if not req:
        return_db_connection(conn)
        flash(request, "Request not found.", "danger")
        return RedirectResponse(url="/notifications", status_code=303)

    if req["request_status"] != "pending":
        return_db_connection(conn)
        flash(request, "This request is no longer pending.", "info")
        return RedirectResponse(url="/notifications", status_code=303)

    cur.execute("SELECT * FROM devices WHERE mac_address = %s", (req["mac_address"],))
    device = cur.fetchone()

    if not device:
        return_db_connection(conn)
        flash(request, "Device not found.", "danger")
        return RedirectResponse(url="/notifications", status_code=303)

    owner = device["owner"] or ""
    if owner.strip().lower() != user["username"].lower():
        return_db_connection(conn)
        flash(request, "Access denied. You are not the owner of this device.", "danger")
        return RedirectResponse(url="/notifications", status_code=303)

    request_type = req.get("request_type") or "request"

    cur.execute(
        "UPDATE device_requests SET request_status = 'declined', resolved_at = NOW() WHERE id = %s",
        (request_id,)
    )
    conn.commit()

    action = "Lease Renewal Declined" if request_type == "renewal" else "Decline Request"
    log_change(user["username"], action, req["mac_address"], {"requester": req["requester_username"]})

    if request_type == "renewal":
        message = f"Your lease renewal request for device {req['mac_address']} has been declined."
    else:
        message = f"Your request for device {req['mac_address']} has been declined."

    create_notification(
        recipient_username=req["requester_username"],
        message=message,
        related_mac_address=req["mac_address"],
        request_id=request_id,
    )

    return_db_connection(conn)
    flash(request, f"Request from {req['requester_username']} declined.", "success")
    return RedirectResponse(url="/notifications", status_code=303)


@router.post("/notifications/mark-read", name="mark_notifications_read")
def mark_notifications_read(request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        "UPDATE notifications SET is_read = TRUE WHERE recipient_username = %s",
        (user["username"],)
    )
    conn.commit()
    return_db_connection(conn)
    return RedirectResponse(url="/notifications", status_code=303)
