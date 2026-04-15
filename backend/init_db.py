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
            id                SERIAL PRIMARY KEY,
            mac_address       TEXT UNIQUE NOT NULL,
            device_model      TEXT NOT NULL,
            owner             TEXT NOT NULL,
            availability      TEXT NOT NULL CHECK (availability IN ('Available', 'In Use')),
            reporting_manager TEXT,
            team              TEXT,
            ip_address        TEXT,
            location          TEXT,
            lease             TEXT
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

    # Insert default admin user
    hashed_password = generate_password_hash("admin123")
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
