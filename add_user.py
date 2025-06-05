import sqlite3
from werkzeug.security import generate_password_hash

# Set the new username and password
new_username = input("Enter new username: ")
new_password = input("Enter new password: ")

# Hash the password
hashed_password = generate_password_hash(new_password)

# Connect to the database
conn = sqlite3.connect('inventory.db')
cursor = conn.cursor()

# Insert new user
try:
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_username, hashed_password))
    conn.commit()
    print(f"User '{new_username}' added successfully.")
except sqlite3.IntegrityError:
    print("Username already exists. Choose a different one.")
finally:
    conn.close()
