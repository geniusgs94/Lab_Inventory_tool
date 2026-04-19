from fastapi import APIRouter, Request

from fastapi.responses import RedirectResponse
from psycopg2.extras import RealDictCursor

from dependencies import flash, get_current_user, render
from services.db import get_db_connection, return_db_connection

router = APIRouter()

PER_PAGE = 10


@router.get("/history", name="history")
def history(request: Request, page: int = 1):
    user = get_current_user(request)
    if not user:
        flash(request, "Session expired or you are not logged in.", "danger")
        return RedirectResponse(url="/login", status_code=302)

    page = max(1, page)
    offset = (page - 1) * PER_PAGE

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT COUNT(*) AS total FROM device_edit_history")
    total = cur.fetchone()["total"]
    cur.execute(
        "SELECT * FROM device_edit_history ORDER BY changed_at DESC LIMIT %s OFFSET %s",
        (PER_PAGE, offset),
    )
    logs = cur.fetchall()
    return_db_connection(conn)

    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)

    return render("history.html", request, {
        "logs": logs,
        "page": page,
        "total_pages": total_pages,
    })
