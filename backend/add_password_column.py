"""One-time migration: adds the `password` column to an existing devices table."""
import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

conn = psycopg2.connect(os.environ.get("DATABASE_URL"))
cur = conn.cursor()
cur.execute("ALTER TABLE devices ADD COLUMN IF NOT EXISTS password TEXT DEFAULT ''")
conn.commit()
conn.close()
print("Done: `password` column added to devices table.")
