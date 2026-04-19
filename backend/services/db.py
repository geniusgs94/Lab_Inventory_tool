import os
import json
from datetime import datetime
from urllib.parse import unquote

import psycopg2
import psycopg2.extras
import psycopg2.pool
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")

_pool = None  # type: psycopg2.pool.ThreadedConnectionPool


def _parse_database_url(database_url: str) -> dict:
    if "://" not in database_url:
        raise ValueError("DATABASE_URL must include a URL scheme")

    _, remainder = database_url.split("://", 1)
    authority, sep, tail = remainder.partition("/")
    if not sep:
        raise ValueError("DATABASE_URL must include a database name")

    userinfo, hostinfo = ("", authority)
    if "@" in authority:
        userinfo, hostinfo = authority.rsplit("@", 1)

    username = ""
    password = ""
    if userinfo:
        if ":" in userinfo:
            username, password = userinfo.split(":", 1)
        else:
            username = userinfo

    host = hostinfo
    port = ""
    if hostinfo.startswith("["):
        end = hostinfo.find("]")
        if end == -1:
            raise ValueError("Invalid IPv6 host in DATABASE_URL")
        host = hostinfo[: end + 1]
        remainder = hostinfo[end + 1 :]
        if remainder.startswith(":"):
            port = remainder[1:]
    elif ":" in hostinfo:
        host, port = hostinfo.rsplit(":", 1)

    dbname = tail.split("?", 1)[0].split("#", 1)[0]
    if not dbname:
        raise ValueError("DATABASE_URL must include a database name")

    params = {
        "dbname": unquote(dbname),
        "host": host or "localhost",
        "user": unquote(username),
        "password": unquote(password),
    }
    if port:
        params["port"] = port
    return params


def get_database_config() -> dict:
    if os.environ.get("POSTGRES_DB"):
        params = {
            "dbname": os.environ["POSTGRES_DB"],
            "host": os.environ.get("POSTGRES_HOST", "localhost"),
            "user": os.environ.get("POSTGRES_USER", ""),
            "password": os.environ.get("POSTGRES_PASSWORD", ""),
        }
        port = os.environ.get("POSTGRES_PORT", "5432")
        if port:
            params["port"] = port
        return params

    if not DATABASE_URL:
        raise RuntimeError(
            "Database configuration missing. Set DATABASE_URL or POSTGRES_DB/POSTGRES_USER/POSTGRES_PASSWORD."
        )

    return _parse_database_url(DATABASE_URL)


def init_pool(minconn: int = 2, maxconn: int = 10) -> None:
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(minconn, maxconn, **get_database_config())


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.closeall()
        _pool = None


def get_db_connection():
    if _pool is None:
        raise RuntimeError("Database pool has not been initialized.")
    return _pool.getconn()


def return_db_connection(conn) -> None:
    if _pool is not None:
        try:
            conn.rollback()
        except Exception:
            pass
        _pool.putconn(conn)


def log_device_edit(mac_address: str, field_name: str, old_value: str, new_value: str, changed_by: str):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO device_edit_history (mac_address, field_name, old_value, new_value, changed_by, changed_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (mac_address, field_name, old_value, new_value, changed_by, datetime.now().isoformat()),
        )
        conn.commit()
    finally:
        return_db_connection(conn)


def log_change(username: str, action: str, item_name: str, details: dict):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO change_logs (username, action, item_name, details, timestamp)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (username, action, item_name, json.dumps(details), datetime.now().isoformat()),
        )
        conn.commit()
    finally:
        return_db_connection(conn)


def create_notification(recipient_username: str, message: str, related_mac_address: str = None, request_id: int = None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO notifications (recipient_username, message, related_mac_address, request_id, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (recipient_username, message, related_mac_address, request_id, datetime.now().isoformat()),
        )
        conn.commit()
    finally:
        return_db_connection(conn)


def get_unread_notification_count(username: str) -> int:
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "SELECT COUNT(*) as count FROM notifications WHERE recipient_username = %s AND is_read = FALSE",
            (username,),
        )
        row = cur.fetchone()
        return row["count"] if row else 0
    finally:
        return_db_connection(conn)
