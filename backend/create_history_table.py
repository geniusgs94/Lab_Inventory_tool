import psycopg2, os
from dotenv import load_dotenv
load_dotenv()
conn = psycopg2.connect(os.environ['DATABASE_URL'])
cur = conn.cursor()
cur.execute("""CREATE TABLE IF NOT EXISTS device_edit_history (
    id SERIAL PRIMARY KEY,
    mac_address TEXT NOT NULL,
    field_name TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_by TEXT NOT NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT NOW()
)""")
conn.commit()
conn.close()
print("Table created successfully.")
