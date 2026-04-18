import psycopg2
from werkzeug.security import generate_password_hash
import os
from dotenv import load_dotenv

load_dotenv()

def init_db():
    conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
    cursor = conn.cursor()

    # Devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id                  SERIAL PRIMARY KEY,
            mac_address         TEXT UNIQUE NOT NULL,
            device_model        TEXT NOT NULL,
            owner               TEXT NOT NULL,
            availability        TEXT NOT NULL CHECK (availability IN ('Available', 'In Use')),
            reporting_manager   TEXT,
            team                TEXT,
            ip_address          TEXT,
            location            TEXT,
            lease               TEXT,
            password            TEXT DEFAULT '',
            leasee_username     TEXT,
            lease_expiry        TIMESTAMP,
            lease_warning_sent  BOOLEAN DEFAULT FALSE
        );
    ''')

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id       SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL CHECK (role IN ('admin', 'user'))
        );
    ''')

    # Change logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS change_logs (
            id        SERIAL PRIMARY KEY,
            username  TEXT NOT NULL,
            action    TEXT NOT NULL,
            item_name TEXT NOT NULL,
            details   TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
    ''')

    # Device edit history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_edit_history (
            id          SERIAL PRIMARY KEY,
            mac_address TEXT NOT NULL,
            field_name  TEXT NOT NULL,
            old_value   TEXT,
            new_value   TEXT,
            changed_by  TEXT NOT NULL,
            changed_at  TIMESTAMP NOT NULL DEFAULT NOW()
        );
    ''')

    # Device requests table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_requests (
            id                   SERIAL PRIMARY KEY,
            mac_address          TEXT NOT NULL,
            requester_username   TEXT NOT NULL,
            request_status       TEXT NOT NULL DEFAULT 'pending'
                                 CHECK (request_status IN ('pending', 'accepted', 'declined', 'cancelled')),
            requested_at         TIMESTAMP NOT NULL DEFAULT NOW(),
            resolved_at          TIMESTAMP,
            requested_lease_date TIMESTAMP,
            request_type         TEXT NOT NULL DEFAULT 'request'
                                 CHECK (request_type IN ('request', 'renewal'))
        );
    ''')

    # Notifications table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id                  SERIAL PRIMARY KEY,
            recipient_username  TEXT NOT NULL,
            message             TEXT NOT NULL,
            related_mac_address TEXT,
            request_id          INTEGER REFERENCES device_requests(id),
            is_read             BOOLEAN NOT NULL DEFAULT FALSE,
            created_at          TIMESTAMP NOT NULL DEFAULT NOW()
        );
    ''')

    # Allow owner to be empty/null for released devices
    try:
        cursor.execute("ALTER TABLE devices ALTER COLUMN owner DROP NOT NULL")
        conn.commit()
    except Exception:
        conn.rollback()

    # Insert default admin user
    hashed_password = generate_password_hash("admin123", method="pbkdf2:sha256")
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                       ("admin", hashed_password, "admin"))
        print("✅ Default admin user created.")
    except psycopg2.IntegrityError:
        conn.rollback()
        print("ℹ️ Admin user already exists.")

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully.")

if __name__ == '__main__':
    init_db()
