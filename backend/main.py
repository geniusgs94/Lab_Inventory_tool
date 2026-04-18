import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from routers import auth, devices, history, notifications

load_dotenv()

app = FastAPI(title="Lab Device Inventory")

# SessionMiddleware is used exclusively for flash messages.
# Authentication is handled via JWT stored in an HTTP-only cookie.
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SECRET_KEY", "gaurav_secret_key_123"),
    max_age=900,  # 15 minutes — matches ACCESS_TOKEN_EXPIRE_MINUTES
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(BASE_DIR, "../frontend/static")),
    name="static",
)

app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(history.router)
app.include_router(notifications.router)
