import os
import json
from datetime import datetime

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")


def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def log_device_edit(mac_address: str, field_name: str, old_value: str, new_value: str, changed_by: str):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO device_edit_history (mac_address, field_name, old_value, new_value, changed_by, changed_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (mac_address, field_name, old_value, new_value, changed_by, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def log_change(username: str, action: str, item_name: str, details: dict):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO change_logs (username, action, item_name, details, timestamp)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (username, action, item_name, json.dumps(details), datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def create_notification(recipient_username: str, message: str, related_mac_address: str = None, request_id: int = None):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO notifications (recipient_username, message, related_mac_address, request_id, created_at)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (recipient_username, message, related_mac_address, request_id, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def get_unread_notification_count(username: str) -> int:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) as count FROM notifications WHERE recipient_username = %s AND is_read = FALSE",
        (username,)
    )
    row = cur.fetchone()
    conn.close()
    return row["count"] if row else 0
