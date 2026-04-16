from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from dependencies import flash, get_current_user, render
from services.db import get_db_connection

router = APIRouter()


@router.get("/history", name="history")
def history(request: Request):
    user = get_current_user(request)
    if not user:
        flash(request, "Session expired or you are not logged in.", "danger")
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM change_logs ORDER BY timestamp DESC")
    logs = cur.fetchall()
    conn.close()

    return render("history.html", request, {"logs": logs})
