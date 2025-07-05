import sqlite3
from datetime import datetime
import json

DB = 'inventory.db'

def log_change(username, action, item_name, details):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO change_logs (username, action, item_name, details, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (username, action, item_name, json.dumps(details), datetime.now().isoformat()))
    conn.commit()
    conn.close()


def delete_user_and_release_devices(target_username):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Check if user exists
    cursor.execute("SELECT * FROM users WHERE username = ?", (target_username,))
    user = cursor.fetchone()

    if not user:
        print("❌ No user found with that username.")
        conn.close()
        return

    # Fetch devices owned by the user
    cursor.execute("SELECT * FROM devices WHERE owner = ?", (target_username,))
    devices = cursor.fetchall()

    if devices:
        print(f"⚠️ Releasing {len(devices)} device(s) owned by '{target_username}'...")
        for device in devices:
            old_details = dict(device)
            cursor.execute("""
                UPDATE devices 
                SET owner = 'Unassigned', availability = 'Available'
                WHERE id = ?
            """, (device['id'],))
            log_change('admin', 'Release', device['mac_address'], {
                'previous_owner': old_details['owner'],
                'status': 'Released during user deletion'
            })

    # Delete the user
    cursor.execute("DELETE FROM users WHERE username = ?", (target_username,))
    conn.commit()
    conn.close()
    print(f"✅ User '{target_username}' deleted and devices released.")


if __name__ == '__main__':
    target = input("Enter the username of the user to delete: ").strip()
    confirm = input(f"Are you sure you want to delete user '{target}' and release their devices? Type YES to confirm: ")
    if confirm == 'YES':
        delete_user_and_release_devices(target)
    else:
        print("❌ Operation cancelled.")
