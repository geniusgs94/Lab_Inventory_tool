from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash

from dependencies import create_access_token, flash, get_current_user, render
from services.db import get_db_connection, return_db_connection

router = APIRouter()


@router.get("/", name="home")
def home(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/inventory", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@router.get("/login", name="login")
def login_get(request: Request):
    return render("login.html", request)


@router.post("/login")
def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    username = username.lower()

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    return_db_connection(conn)

    if user and check_password_hash(user["password"], password):
        token = create_access_token({
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
        })
        response = RedirectResponse(url="/inventory", status_code=303)
        response.set_cookie(
            key="access_token",
            value=token,
            httponly=True,
            max_age=900,  # 15 minutes
            samesite="lax",
        )
        return response

    flash(request, "Invalid username or password", "error")
    return RedirectResponse(url="/login", status_code=303)


@router.get("/logout", name="logout")
def logout(request: Request):
    flash(request, "Logged out successfully.", "success")
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response
