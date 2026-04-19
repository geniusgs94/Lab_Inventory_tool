from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash

from dependencies import _require_login, flash, render
from services.db import get_db_connection, return_db_connection

router = APIRouter()


def _require_admin(request: Request):
    user = _require_login(request)
    if not user:
        return None, RedirectResponse(url="/login", status_code=302)
    if user.get("role") != "admin":
        flash(request, "Access denied", "danger")
        return None, RedirectResponse(url="/inventory", status_code=302)
    return user, None


# ── User list ──────────────────────────────────────────────────────────────────

@router.get("/users", name="users")
def users_list(request: Request):
    user, redirect = _require_admin(request)
    if redirect:
        return redirect
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, username, role FROM users ORDER BY username")
    all_users = cur.fetchall()
    return_db_connection(conn)
    return render("users.html", request, {"users": all_users})


# ── Add user ───────────────────────────────────────────────────────────────────

@router.get("/users/add", name="add_user")
def add_user_get(request: Request):
    user, redirect = _require_admin(request)
    if redirect:
        return redirect
    return render("add_user.html", request)


@router.post("/users/add")
def add_user_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    role: str = Form(...),
):
    user, redirect = _require_admin(request)
    if redirect:
        return redirect

    username = username.lower().strip()

    if not username:
        flash(request, "Username cannot be empty.", "danger")
        return RedirectResponse(url="/users/add", status_code=303)

    if len(password) < 6:
        flash(request, "Password must be at least 6 characters.", "danger")
        return RedirectResponse(url="/users/add", status_code=303)

    if password != confirm_password:
        flash(request, "Passwords do not match.", "danger")
        return RedirectResponse(url="/users/add", status_code=303)

    if role not in ("admin", "user"):
        flash(request, "Invalid role.", "danger")
        return RedirectResponse(url="/users/add", status_code=303)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    if cur.fetchone():
        return_db_connection(conn)
        flash(request, "Username already exists.", "danger")
        return RedirectResponse(url="/users/add", status_code=303)

    hashed = generate_password_hash(password, method="pbkdf2:sha256")
    cur.execute(
        "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
        (username, hashed, role),
    )
    conn.commit()
    return_db_connection(conn)

    flash(request, "User created successfully.", "success")
    return RedirectResponse(url="/users", status_code=303)


# ── Delete user ────────────────────────────────────────────────────────────────

@router.get("/users/delete/{user_id}", name="delete_user")
def delete_user(request: Request, user_id: int):
    admin, redirect = _require_admin(request)
    if redirect:
        return redirect

    if admin["user_id"] == user_id:
        flash(request, "Cannot delete your own account.", "danger")
        return RedirectResponse(url="/users", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
    target = cur.fetchone()
    if not target:
        return_db_connection(conn)
        flash(request, "User not found.", "danger")
        return RedirectResponse(url="/users", status_code=302)

    target_username = target["username"]

    # Release all devices owned by this user
    cur.execute(
        "UPDATE devices SET owner = 'Unassigned', availability = 'Available' WHERE owner = %s",
        (target_username,),
    )

    # Cancel any pending device requests by this user
    cur.execute(
        "UPDATE device_requests SET request_status = 'cancelled', resolved_at = NOW() "
        "WHERE requester_username = %s AND request_status = 'pending'",
        (target_username,),
    )

    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    return_db_connection(conn)

    flash(request, "User deleted successfully.", "success")
    return RedirectResponse(url="/users", status_code=302)


# ── Reset password (admin) ─────────────────────────────────────────────────────

@router.get("/users/reset-password/{user_id}", name="reset_password")
def reset_password_get(request: Request, user_id: int):
    user, redirect = _require_admin(request)
    if redirect:
        return redirect

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
    target = cur.fetchone()
    return_db_connection(conn)

    if not target:
        flash(request, "User not found.", "danger")
        return RedirectResponse(url="/users", status_code=302)

    return render("reset_password.html", request, {"target_user": target})


@router.post("/users/reset-password/{user_id}")
def reset_password_post(
    request: Request,
    user_id: int,
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    user, redirect = _require_admin(request)
    if redirect:
        return redirect

    if len(new_password) < 6:
        flash(request, "Password must be at least 6 characters.", "danger")
        return RedirectResponse(url=f"/users/reset-password/{user_id}", status_code=303)

    if new_password != confirm_password:
        flash(request, "Passwords do not match.", "danger")
        return RedirectResponse(url=f"/users/reset-password/{user_id}", status_code=303)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
    if not cur.fetchone():
        return_db_connection(conn)
        flash(request, "User not found.", "danger")
        return RedirectResponse(url="/users", status_code=302)

    hashed = generate_password_hash(new_password, method="pbkdf2:sha256")
    cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed, user_id))
    conn.commit()
    return_db_connection(conn)

    flash(request, "Password reset successfully.", "success")
    return RedirectResponse(url="/users", status_code=303)


# ── Change password (self) ─────────────────────────────────────────────────────

@router.get("/change-password", name="change_password")
def change_password_get(request: Request):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return render("change_password.html", request)


@router.post("/change-password")
def change_password_post(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    user = _require_login(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT password FROM users WHERE username = %s", (user["username"],))
    db_user = cur.fetchone()
    return_db_connection(conn)

    if not db_user or not check_password_hash(db_user["password"], current_password):
        flash(request, "Current password is incorrect.", "danger")
        return RedirectResponse(url="/change-password", status_code=303)

    if len(new_password) < 6:
        flash(request, "New password must be at least 6 characters.", "danger")
        return RedirectResponse(url="/change-password", status_code=303)

    if new_password != confirm_password:
        flash(request, "Passwords do not match.", "danger")
        return RedirectResponse(url="/change-password", status_code=303)

    if new_password == current_password:
        flash(request, "New password must differ from current password.", "danger")
        return RedirectResponse(url="/change-password", status_code=303)

    hashed = generate_password_hash(new_password, method="pbkdf2:sha256")
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("UPDATE users SET password = %s WHERE username = %s", (hashed, user["username"]))
    conn.commit()
    return_db_connection(conn)

    flash(request, "Password changed successfully.", "success")
    return RedirectResponse(url="/inventory", status_code=303)
