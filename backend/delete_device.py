import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get('DATABASE_URL')

def delete_device(mac_address):
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()

    if mac_address == 'masterkeygaurav':
        confirm = input("⚠️ Are you sure you want to delete ALL devices? Type 'YES' to confirm: ")
        if confirm == 'YES':
            cursor.execute("DELETE FROM devices")
            conn.commit()
            print("✅ All devices deleted from the database.")
        else:
            print("❌ Operation canceled.")
    else:
        cursor.execute("SELECT * FROM devices WHERE mac_address = %s", (mac_address,))
        device = cursor.fetchone()
        if device:
            cursor.execute("DELETE FROM devices WHERE mac_address = %s", (mac_address,))
            conn.commit()
            print(f"✅ Device with MAC address {mac_address} deleted.")
        else:
            print("❌ No device found with that MAC address.")

    conn.close()


if __name__ == '__main__':
    mac_input = input("Enter MAC address of the device to delete: ")
    delete_device(mac_input.strip())
