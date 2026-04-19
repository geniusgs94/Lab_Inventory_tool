from fastapi import APIRouter, Form, Request
from fastapi.responses import FileResponse, RedirectResponse

from dependencies import _require_login, flash, render
from services.backup import (
    BACKUP_DIR,
    _safe_filename,
    create_backup,
    delete_backup,
    list_backups,
    restore_backup,
)
import os

router = APIRouter()


def _require_admin(request: Request):
    user = _require_login(request)
    if not user:
        return None, RedirectResponse(url="/login", status_code=302)
    if user.get("role") != "admin":
        flash(request, "Access denied", "danger")
        return None, RedirectResponse(url="/inventory", status_code=302)
    return user, None


@router.get("/backups", name="backups")
def backups_list(request: Request):
    user, redirect = _require_admin(request)
    if redirect:
        return redirect
    backups = list_backups()
    return render("backups.html", request, {"backups": backups})


@router.post("/backups/create")
def backups_create(request: Request):
    user, redirect = _require_admin(request)
    if redirect:
        return redirect
    try:
        result = create_backup()
        flash(
            request,
            f"Backup created successfully: {result['filename']} ({result['size_human']})",
            "success",
        )
    except Exception as e:
        flash(request, f"Backup failed: {e}", "danger")
    return RedirectResponse(url="/backups", status_code=303)


@router.get("/backups/download/{filename}", name="download_backup")
def backups_download(request: Request, filename: str):
    user, redirect = _require_admin(request)
    if redirect:
        return redirect
    try:
        safe_name = _safe_filename(filename)
    except ValueError:
        flash(request, "Invalid filename.", "danger")
        return RedirectResponse(url="/backups", status_code=302)
    filepath = os.path.join(BACKUP_DIR, safe_name)
    if not os.path.isfile(filepath):
        flash(request, "Backup file not found.", "danger")
        return RedirectResponse(url="/backups", status_code=302)
    return FileResponse(
        path=filepath,
        media_type="application/octet-stream",
        filename=safe_name,
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@router.post("/backups/restore/{filename}")
def backups_restore(request: Request, filename: str, confirm: str = Form("")):
    user, redirect = _require_admin(request)
    if redirect:
        return redirect
    if confirm != "yes":
        flash(request, "Restore cancelled: confirmation not provided.", "danger")
        return RedirectResponse(url="/backups", status_code=303)
    try:
        safe_name = _safe_filename(filename)
        restore_backup(safe_name)
        flash(request, f"Database restored successfully from {safe_name}.", "success")
    except Exception as e:
        flash(request, f"Restore failed: {e}", "danger")
    return RedirectResponse(url="/backups", status_code=303)


@router.get("/backups/delete/{filename}", name="delete_backup")
def backups_delete(request: Request, filename: str):
    user, redirect = _require_admin(request)
    if redirect:
        return redirect
    try:
        safe_name = _safe_filename(filename)
        delete_backup(safe_name)
        flash(request, "Backup deleted.", "success")
    except Exception as e:
        flash(request, f"Delete failed: {e}", "danger")
    return RedirectResponse(url="/backups", status_code=302)
