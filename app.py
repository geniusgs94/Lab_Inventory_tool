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
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


def login_required(f):
    """
    Apply @login_required to all routes that require authentication.
    # Example usage:
    @app.route('/')
    @login_required
    def index():
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


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
def index():
    owner = request.args.get('owner')
    availability = request.args.get('availability')
    team = request.args.get('team')

    query = 'SELECT * FROM devices WHERE 1=1'
    params = []

    if owner:
        query += ' AND owner LIKE ?'
        params.append(f'%{owner}%')

    if availability:
        query += ' AND availability = ?'
        params.append(availability)

    if team:
        query += ' AND team LIKE ?'
        params.append(f'%{team}%')

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
            owner = request.form['owner']
            availability = request.form['availability']
            manager = request.form['reporting_manager']
            team = request.form['team']
            location = request.form['location']
            lease = request.form['lease']

            # 4. Insert into database
            conn = sqlite3.connect('inventory.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO devices 
                (mac_address, device_model, owner, availability, reporting_manager, team, ip_address, location, lease)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (mac, model, owner, availability, manager, team, ip, location, lease))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

        except ValueError as e:
            flash(str(e), "danger")
            return render_template('add_item.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_item(id):
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        mac = request.form['mac_address']
        model = request.form['device_model']
        owner = request.form['owner']
        availability = request.form['availability']
        manager = request.form['reporting_manager']
        team = request.form['team']
        ip = request.form['ip_address']
        location = request.form['location']
        lease = request.form['lease']

        cursor.execute('''
            UPDATE devices
            SET mac_address = ?, device_model = ?, owner = ?, availability = ?, 
                reporting_manager = ?, team = ?, ip_address = ?, location = ?, lease = ?
            WHERE id = ?
        ''', (mac, model, owner, availability, manager, team, ip, location, lease, id))

        conn.commit()
        conn.close()
        return redirect(url_for('index'))

    cursor.execute('SELECT * FROM devices WHERE id = ?', (id,))
    row = cursor.fetchone()
    conn.close()

    device = {
        'id': row[0],
        'mac_address': row[1],
        'device_model': row[2],
        'owner': row[3],
        'availability': row[4],
        'reporting_manager': row[5],
        'team': row[6],
        'ip_address': row[7],
        'location': row[8],
        'lease': row[9]
    }
    return render_template('edit_item.html', device=device)

@app.route('/delete/<int:id>')
@login_required
def delete_item(id):
    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (id,)).fetchone()
    if device:
        conn.execute('DELETE FROM devices WHERE id = ?', (id,))
        conn.commit()
        log_change(session['username'], 'Delete', device['mac_address'], dict(device))
    conn.close()
    return redirect(url_for('index'))

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
