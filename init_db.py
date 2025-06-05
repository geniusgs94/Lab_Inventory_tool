import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    # Existing devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT UNIQUE NOT NULL,
            device_model TEXT NOT NULL,
            owner TEXT NOT NULL,
            availability TEXT NOT NULL CHECK (availability IN ('Available', 'In Use')),
            reporting_manager TEXT,
            team TEXT
        );
    ''')

    # New users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    ''')

    # Insert demo user with hashed password
    hashed_password = generate_password_hash("admin123")
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", hashed_password))
    except sqlite3.IntegrityError:
        pass  # user already exists

    conn.commit()
    conn.close()
    print("Database initialized with hashed passwords.")


if __name__ == '__main__':
    init_db()
