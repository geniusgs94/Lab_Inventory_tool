import psycopg2
from werkzeug.security import generate_password_hash
import os
from dotenv import load_dotenv

load_dotenv()

# Set the new username and password
new_username = input("Enter new username: ").lower()
new_password = input("Enter new password: ")
new_role = input("Enter role (admin/user): ").strip().lower()
# Hash the password
hashed_password = generate_password_hash(new_password, method="pbkdf2:sha256")

# Connect to the database
conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
cursor = conn.cursor()

# Insert new user
if new_role not in ("admin", "user"):
    print("❌ Invalid role. Only 'admin' or 'user' are allowed.")
    exit()
try:
    cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", (new_username, hashed_password, new_role))
    conn.commit()
    print(f"User '{new_username}' added successfully.")
except psycopg2.IntegrityError:
    print("Username already exists. Choose a different one.")
finally:
    conn.close()
