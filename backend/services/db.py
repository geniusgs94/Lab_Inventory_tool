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
