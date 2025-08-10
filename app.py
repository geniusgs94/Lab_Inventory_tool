# app.py
from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
from functools import wraps
from datetime import datetime
import json
import os
from werkzeug.security import check_password_hash
from datetime import timedelta
import re
import ipaddress

def format_mac_address(mac: str) -> str:
    """Formats MAC to 00:1A:2B:3C:4D:5E and checks length"""
    mac = re.sub(r'[^a-fA-F0-9]', '', mac).upper()
    if len(mac) != 12:
        raise ValueError("MAC address must have exactly 12 hexadecimal digits.")
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

def validate_ip(ip: str) -> bool:
    """Checks if the IP address is valid"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
app = Flask(__name__)
app.secret_key = 'gaurav_secret_key_123'
app.debug=True
DB = 'inventory.db'
app.permanent_session_lifetime = timedelta(minutes=15)

def is_logged_in():
    return 'user_id' in session


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']  # ✅ Set user role in session
            flash('Logged in successfully!', 'success')
            return redirect(url_for('inventory'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

def is_admin():
    return session.get('role') == 'admin'

def is_user():
    return session.get('role') == 'user'

# ----------------------------
# Helpers
# ----------------------------
def get_db_connection():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Session expired or you are not logged in.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def log_change(username, action, item_name, details):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO change_logs (username, action, item_name, details, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (username, action, item_name, json.dumps(details), datetime.now().isoformat()))
    conn.commit()
    conn.close()

# ----------------------------
# Routes
# ----------------------------

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('inventory'))
    return redirect(url_for('login'))

@app.route('/inventory')
@login_required
def inventory():
    search = request.args.get('search')
    availability = request.args.get('availability')

    query = 'SELECT * FROM devices WHERE 1=1'
    params = []

    if search:
        like = f"%{search}%"
        query += '''
            AND (
                mac_address LIKE ? OR
                device_model LIKE ? OR
                owner LIKE ? OR
                availability LIKE ? OR
                reporting_manager LIKE ? OR
                team LIKE ? OR
                ip_address LIKE ? OR
                location LIKE ? OR
                lease LIKE ?
            )
        '''
        params.extend([like] * 9)

    if availability:
        query += ' AND availability = ?'
        params.append(availability)

    conn = get_db_connection()
    devices = conn.execute(query, params).fetchall()
    conn.close()

    return render_template('index.html', devices=devices)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        try:
            # 1. Validate and format MAC address
            mac = format_mac_address(request.form['mac_address'])

            # 2. Validate IP address
            ip = request.form['ip_address']
            if not validate_ip(ip):
                flash("Invalid IP address format", "danger")
                return render_template('add_item.html')

            # 3. Collect other fields
            model = request.form['device_model']
            owner = session['username'] if is_user() else request.form['owner']
            availability = request.form['availability']
            manager = request.form['reporting_manager']
            team = request.form['team']
            location = request.form['location']
            lease = request.form['lease']

            # 4. Check for duplicate MAC address
            conn = sqlite3.connect('inventory.db')
            cursor = conn.cursor()
            existing = cursor.execute("SELECT 1 FROM devices WHERE mac_address = ?", (mac,)).fetchone()
            if existing:
                flash("MAC address already exists.", "danger")
                conn.close()
                return render_template('add_item.html')

            # 5. Insert into database
            cursor.execute('''
                INSERT INTO devices 
                (mac_address, device_model, owner, availability, reporting_manager, team, ip_address, location, lease)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (mac, model, owner, availability, manager, team, ip, location, lease))
            conn.commit()
            conn.close()
            return redirect(url_for('inventory'))

        except ValueError as e:
            flash(str(e), "danger")
            return render_template('add_item.html')

    # This handles the GET request
    return render_template('add_item.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_item(id):
    conn = sqlite3.connect('inventory.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM devices WHERE id = ?', (id,))
    device = cursor.fetchone()

    if not device:
        conn.close()
        flash("Device not found", "danger")
        return redirect(url_for('inventory'))

    # Only allow Admin or Owner to edit allowed fields
    if not (is_admin() or device['owner'] == session['username']):
        conn.close()
        flash("Access denied. Only the owner or an admin can edit this device.", "danger")
        return redirect(url_for('inventory'))

    if request.method == 'POST':
        # These fields remain unchanged (read-only)
        mac = device['mac_address']
        model = device['device_model']
        owner = device['owner']
        lease = device['lease']

        # These fields can be edited
        availability = request.form['availability']
        manager = request.form['reporting_manager']
        team = request.form['team']
        ip = request.form['ip_address']
        location = request.form['location']

        cursor.execute('''
            UPDATE devices
            SET mac_address = ?, device_model = ?, owner = ?, availability = ?, 
                reporting_manager = ?, team = ?, ip_address = ?, location = ?, lease = ?
            WHERE id = ?
        ''', (mac, model, owner, availability, manager, team, ip, location, lease, id))

        conn.commit()
        conn.close()
        flash("Device updated successfully.", "success")
        return redirect(url_for('inventory'))

    # For GET request - display the device info
    device_dict = {
        'id': device['id'],
        'mac_address': device['mac_address'],
        'device_model': device['device_model'],
        'owner': device['owner'],
        'availability': device['availability'],
        'reporting_manager': device['reporting_manager'],
        'team': device['team'],
        'ip_address': device['ip_address'],
        'location': device['location'],
        'lease': device['lease']
    }
    conn.close()
    return render_template('edit_item.html', device=device_dict)

@app.route('/reserve/<int:id>', methods=['POST'])
@login_required
def reserve_device(id):
    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (id,)).fetchone()

    if not device:
        conn.close()
        flash("Device not found.", "danger")
        return redirect(url_for('inventory'))

    if device['availability'] == 'Available':
        conn.execute('''
            UPDATE devices
            SET availability = ?, owner = ?
            WHERE id = ?
        ''', ('In Use', session['username'], id))
        conn.commit()
        log_change(session['username'], 'Reserve', device['mac_address'], {'new_owner': session['username']})
        flash("Device reserved successfully.", "success")
    else:
        flash("Device is not available for reservation.", "danger")

    conn.close()
    return redirect(url_for('inventory'))

@app.route('/release/<int:id>', methods=['POST'])
@login_required
def release_device(id):
    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (id,)).fetchone()

    if not device:
        conn.close()
        flash("Device not found.", "danger")
        return redirect(url_for('inventory'))

    if device['availability'] == 'In Use' and device['owner'] == session['username']:
        conn.execute('''
            UPDATE devices
            SET availability = ?, owner = ?
            WHERE id = ?
        ''', ('Available', '', id))
        conn.commit()
        log_change(session['username'], 'Release', device['mac_address'], {'released_by': session['username']})
        flash("Device released successfully.", "success")
    else:
        flash("You are not allowed to release this device.", "danger")

    conn.close()
    return redirect(url_for('inventory'))

@app.route('/request/<int:id>', methods=['POST'])
@login_required
def request_device(id):
    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (id,)).fetchone()
    conn.close()

    if not device:
        flash("Device not found.", "danger")
    elif device['owner'] == session['username']:
        flash("You already own this device.", "info")
    else:
        # For now just flash a message. You can later add notification logic.
        flash(f"Request sent to owner ({device['owner']}) to use this device.", "success")

    return redirect(url_for('inventory'))


@app.route('/delete/<int:id>')
@login_required
def delete_item(id):
    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (id,)).fetchone()

    if not device:
        conn.close()
        flash("Device not found", "danger")
        return redirect(url_for('inventory'))


    # Access control
    if is_user():
        if device['owner'] != session['username'] and device['availability'] != 'Available':
            conn.close()
            flash("Access denied. You can't delete devices owned by others.", "danger")
            return redirect(url_for('inventory'))


    conn.execute('DELETE FROM devices WHERE id = ?', (id,))
    conn.commit()
    log_change(session['username'], 'Delete', device['mac_address'], dict(device))
    conn.close()
    return redirect(url_for('inventory'))


@app.route('/history')
@login_required
def history():
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM change_logs ORDER BY timestamp DESC').fetchall()
    conn.close()
    return render_template('history.html', logs=logs)

# ----------------------------
# Run Server
# ----------------------------
if __name__ == '__main__':
    if not os.path.exists(DB):
        print("❌ Database not found. Run init_db.py first.")
    else:
        app.run(debug=True)
