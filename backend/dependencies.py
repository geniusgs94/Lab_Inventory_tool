import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Request
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.environ.get("SECRET_KEY", "gaurav_secret_key_123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "../frontend/templates"))


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user(request: Request) -> Optional[dict]:
    """Returns the decoded JWT payload from the access_token cookie, or None."""
    token = request.cookies.get("access_token")
    if not token:
        return None
    return decode_access_token(token)


def flash(request: Request, message: str, category: str = "info"):
    """Store a flash message in the session (displayed once on next render)."""
    if "_flashes" not in request.session:
        request.session["_flashes"] = []
    request.session["_flashes"].append({"message": message, "category": category})


def _pop_flashes(request: Request, with_categories: bool = False):
    raw = request.session.pop("_flashes", [])
    if with_categories:
        return [(f["category"], f["message"]) for f in raw]
    return [f["message"] for f in raw]


def render(template_name: str, request: Request, context: Optional[dict] = None):
    """
    Render a Jinja2 template with JWT user info and flash messages pre-injected.

    Injects into every template context:
      - session   : dict of JWT payload (username, role, user_id) or {} if not logged in
      - get_flashed_messages : mimics Flask's built-in, pops flashes from session
    """
    ctx = context or {}
    user = get_current_user(request)
    ctx["request"] = request
    ctx["session"] = user or {}
    ctx["get_flashed_messages"] = lambda **kwargs: _pop_flashes(
        request, with_categories=kwargs.get("with_categories", False)
    )
    return templates.TemplateResponse(template_name, ctx)
