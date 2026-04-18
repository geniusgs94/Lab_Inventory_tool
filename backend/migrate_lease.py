import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()


def migrate():
    conn = psycopg2.connect(os.environ.get("DATABASE_URL"))
    cur = conn.cursor()

    steps = [
        ("leasee_username to devices",
         "ALTER TABLE devices ADD COLUMN IF NOT EXISTS leasee_username TEXT"),
        ("lease_expiry to devices",
         "ALTER TABLE devices ADD COLUMN IF NOT EXISTS lease_expiry TIMESTAMP"),
        ("lease_warning_sent to devices",
         "ALTER TABLE devices ADD COLUMN IF NOT EXISTS lease_warning_sent BOOLEAN DEFAULT FALSE"),
        ("requested_lease_date to device_requests",
         "ALTER TABLE device_requests ADD COLUMN IF NOT EXISTS requested_lease_date TIMESTAMP"),
        ("request_type to device_requests",
         "ALTER TABLE device_requests ADD COLUMN IF NOT EXISTS request_type TEXT DEFAULT 'request'"),
    ]

    for description, sql in steps:
        try:
            cur.execute(sql)
            conn.commit()
            print(f"✅ Added {description}")
        except Exception as e:
            conn.rollback()
            print(f"⚠️  {description}: {e}")

    conn.close()
    print("✅ Lease migration complete.")


if __name__ == "__main__":
    migrate()
