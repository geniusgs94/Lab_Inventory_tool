import os
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from routers import auth, backup, devices, history, notifications, users
from services.db import close_pool, init_pool

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
app.include_router(users.router)
app.include_router(backup.router)

_scheduler = BackgroundScheduler()


@app.on_event("startup")
def start_scheduler():
    init_pool(minconn=2, maxconn=10)
    #ensure_schema()
    from services.backup import create_backup
    _scheduler.add_job(
        create_backup,
        IntervalTrigger(weeks=1, start_date=datetime.now() + timedelta(minutes=1)),
        id="weekly_backup",
        replace_existing=True,
    )
    _scheduler.start()


@app.on_event("shutdown")
def stop_scheduler():
    _scheduler.shutdown(wait=False)
    close_pool()
