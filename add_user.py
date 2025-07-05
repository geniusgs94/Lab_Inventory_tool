import sqlite3
from werkzeug.security import generate_password_hash

# Set the new username and password
new_username = input("Enter new username: ")
new_password = input("Enter new password: ")
new_role = input("Enter role (admin/user): ").strip().lower()
# Hash the password
hashed_password = generate_password_hash(new_password)

# Connect to the database
conn = sqlite3.connect('inventory.db')
cursor = conn.cursor()

# Insert new user
if new_role not in ("admin", "user"):
    print("❌ Invalid role. Only 'admin' or 'user' are allowed.")
    exit()
try:
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (new_username, hashed_password, new_role))
    conn.commit()
    print(f"User '{new_username}' added successfully.")
except sqlite3.IntegrityError:
    print("Username already exists. Choose a different one.")
finally:
    conn.close()
