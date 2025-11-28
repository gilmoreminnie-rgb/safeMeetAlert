#!/usr/bin/env python3
"""
SafeMeet v5.0 Backend Server with Audio Recording
Features:
- All v5 features (forgot password, meeting comments, grace period, SMS)
- Audio file upload and storage (file system)
- Browser-based transcription (no server transcription)
- Auto-delete audio files older than 30 days
- Complete API endpoints for SQLite database storage
"""

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
import os
import threading
import time
import json

app = Flask(__name__)
CORS(app)

DATABASE = 'safemeet_v5_audio.db'
AUDIO_UPLOAD_FOLDER = 'audio_recordings'
AUDIO_RETENTION_DAYS = 30  # Delete audio files after 30 days

# Create audio upload folder if it doesn't exist
if not os.path.exists(AUDIO_UPLOAD_FOLDER):
    os.makedirs(AUDIO_UPLOAD_FOLDER)
    print(f"✅ Created audio upload folder: {AUDIO_UPLOAD_FOLDER}")

# ============= DATABASE SETUP =============

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with all tables including audio recordings"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            plan TEXT DEFAULT 'free',
            reset_token TEXT,
            reset_token_expires TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Emergency contacts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            relationship TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Meetings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS meetings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            person_name TEXT NOT NULL,
            location TEXT NOT NULL,
            start_time TIMESTAMP NOT NULL,
            end_time TIMESTAMP NOT NULL,
            comments TEXT,
            tracking_enabled BOOLEAN DEFAULT 0,
            audio_capture_enabled BOOLEAN DEFAULT 0,
            sms_enabled BOOLEAN DEFAULT 1,
            status TEXT DEFAULT 'scheduled',
            grace_period_start TIMESTAMP,
            last_latitude REAL,
            last_longitude REAL,
            last_location_time TIMESTAMP,
            pin TEXT NOT NULL,
            overdue_alert_sent BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Meeting contacts junction table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS meeting_contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meeting_id INTEGER NOT NULL,
            contact_id INTEGER NOT NULL,
            notified BOOLEAN DEFAULT 0,
            FOREIGN KEY (meeting_id) REFERENCES meetings(id),
            FOREIGN KEY (contact_id) REFERENCES contacts(id)
        )
    ''')
    
    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            meeting_id INTEGER,
            alert_type TEXT NOT NULL,
            latitude REAL,
            longitude REAL,
            cleared BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (meeting_id) REFERENCES meetings(id)
        )
    ''')
    
    # Audio recordings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audio_recordings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meeting_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            user_name TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            transcription TEXT,
            latitude REAL,
            longitude REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (meeting_id) REFERENCES meetings(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # User cleared alerts table (tracks which alerts each user has dismissed)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_cleared_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            alert_id INTEGER NOT NULL,
            cleared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (alert_id) REFERENCES alerts(id),
            UNIQUE(user_id, alert_id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")

def migrate_existing_db():
    """Add missing columns to existing database if needed"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("ALTER TABLE meetings ADD COLUMN audio_capture_enabled BOOLEAN DEFAULT 0")
        print("✅ Added audio_capture_enabled column to meetings")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cursor.execute("ALTER TABLE meetings ADD COLUMN overdue_alert_sent BOOLEAN DEFAULT 0")
        print("✅ Added overdue_alert_sent column to meetings")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE audio_recordings ADD COLUMN user_name TEXT")
        print("✅ Added user_name column to audio_recordings")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audio_recordings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                meeting_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                filename TEXT NOT NULL,
                transcription TEXT,
                latitude REAL,
                longitude REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (meeting_id) REFERENCES meetings(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        print("✅ Created audio_recordings table")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_cleared_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                cleared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (alert_id) REFERENCES alerts(id),
                UNIQUE(user_id, alert_id)
            )
        ''')
        print("✅ Created user_cleared_alerts table")
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    conn.close()
    print("✅ Database migration complete")

# ============= AUDIO FILE CLEANUP =============

def cleanup_old_audio_files():
    """Delete audio files and database records older than 30 days"""
    print("\n🧹 Starting audio file cleanup...")
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Calculate cutoff date
        cutoff_date = datetime.now() - timedelta(days=AUDIO_RETENTION_DAYS)
        cutoff_str = cutoff_date.isoformat()
        
        # Find old recordings
        cursor.execute('''
            SELECT id, filename, created_at 
            FROM audio_recordings 
            WHERE created_at < ?
        ''', (cutoff_str,))
        
        old_recordings = cursor.fetchall()
        
        deleted_count = 0
        for recording in old_recordings:
            # Delete file from filesystem
            filepath = os.path.join(AUDIO_UPLOAD_FOLDER, recording['filename'])
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    print(f"   Deleted file: {recording['filename']}")
                    deleted_count += 1
                except Exception as e:
                    print(f"   Error deleting {recording['filename']}: {e}")
            
            # Delete database record
            cursor.execute('DELETE FROM audio_recordings WHERE id = ?', (recording['id'],))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Cleanup complete: {deleted_count} audio files deleted")
        
    except Exception as e:
        print(f"❌ Error during cleanup: {e}")

def start_cleanup_scheduler():
    """Run cleanup daily in background thread"""
    def cleanup_loop():
        while True:
            cleanup_old_audio_files()
            # Sleep for 24 hours
            time.sleep(86400)
    
    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()
    print("✅ Audio cleanup scheduler started (runs daily)")

# ============= HELPER FUNCTIONS =============

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_reset_token():
    """Generate 6-digit reset token"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

def send_sms(phone, message):
    """
    Send SMS notification
    Currently logs to console - integrate Twilio in production
    """
    print(f"\n📱 SMS NOTIFICATION:")
    print(f"   To: {phone}")
    print(f"   Message: {message}")
    print()

def send_email(email, subject, body):
    """
    Send email notification
    Currently logs to console - integrate email service in production
    """
    print(f"\n📧 EMAIL NOTIFICATION:")
    print(f"   To: {email}")
    print(f"   Subject: {subject}")
    print(f"   Body: {body}")
    print()

# ============= API ENDPOINTS =============

@app.route('/')
def index():
    """Serve the main HTML file"""
    return send_from_directory('.', 'index-v5-audio-complete.html')

# ============= USER AUTHENTICATION =============

@app.route('/api/register', methods=['POST'])
def register():
    """Register new user"""
    data = request.json
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if email already exists
        cursor.execute('SELECT id FROM users WHERE email = ?', (data['email'],))
        if cursor.fetchone():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create user
        cursor.execute('''
            INSERT INTO users (name, email, phone, password, plan)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            data['name'],
            data['email'],
            data['phone'],
            hash_password(data['password']),
            data.get('plan', 'free')
        ))
        
        conn.commit()
        user_id = cursor.lastrowid
        
        # Return user data
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = dict(cursor.fetchone())
        user.pop('password')
        
        # Get contacts (will be empty for new user)
        cursor.execute('SELECT * FROM contacts WHERE user_id = ?', (user_id,))
        user['contacts'] = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'user': user
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Login user"""
    data = request.json
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM users 
            WHERE email = ? AND password = ?
        ''', (data['email'], hash_password(data['password'])))
        
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user_dict = dict(user)
        user_dict.pop('password')
        
        # Get user's contacts
        cursor.execute('SELECT * FROM contacts WHERE user_id = ?', (user_dict['id'],))
        contacts = [dict(row) for row in cursor.fetchall()]
        user_dict['contacts'] = contacts
        
        conn.close()
        
        return jsonify({
            'success': True,
            'user': user_dict
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============= FORGOT PASSWORD =============

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset"""
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email required'}), 400
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, name FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'No account found with this email'}), 404
        
        token = generate_reset_token()
        expires = datetime.now() + timedelta(hours=1)
        
        cursor.execute('''
            UPDATE users 
            SET reset_token = ?, reset_token_expires = ?
            WHERE email = ?
        ''', (token, expires, email))
        
        conn.commit()
        conn.close()
        
        send_email(
            email,
            'SafeMeet Password Reset',
            f'Hello {user["name"]},\n\n'
            f'Your password reset code is: {token}\n\n'
            f'This code will expire in 1 hour.\n\n'
            f'If you did not request this, please ignore this email.'
        )
        
        return jsonify({
            'success': True,
            'message': 'Reset code sent to email',
            'token': token  # Remove in production
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token"""
    data = request.json
    email = data.get('email')
    token = data.get('token')
    new_password = data.get('new_password')
    
    if not all([email, token, new_password]):
        return jsonify({'error': 'Email, token, and new password required'}), 400
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, reset_token, reset_token_expires 
            FROM users 
            WHERE email = ?
        ''', (email,))
        
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'Invalid email'}), 404
        
        if user['reset_token'] != token:
            return jsonify({'error': 'Invalid reset code'}), 400
        
        if datetime.now() > datetime.fromisoformat(user['reset_token_expires']):
            return jsonify({'error': 'Reset code expired'}), 400
        
        cursor.execute('''
            UPDATE users 
            SET password = ?, reset_token = NULL, reset_token_expires = NULL
            WHERE email = ?
        ''', (hash_password(new_password), email))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Password reset successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============= CONTACTS =============

@app.route('/api/contacts', methods=['GET', 'POST'])
def contacts():
    """Get or create contacts"""
    user_id = request.args.get('user_id') or (request.json.get('user_id') if request.json else None)
    
    if request.method == 'GET':
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM contacts WHERE user_id = ?', (user_id,))
            contacts_list = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
            return jsonify({'contacts': contacts_list})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        data = request.json
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO contacts (user_id, name, email, phone, relationship)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                user_id,
                data['name'],
                data['email'],
                data['phone'],
                data.get('relationship', '')
            ))
            
            conn.commit()
            contact_id = cursor.lastrowid
            
            cursor.execute('SELECT * FROM contacts WHERE id = ?', (contact_id,))
            contact = dict(cursor.fetchone())
            
            conn.close()
            
            return jsonify({
                'success': True,
                'contact': contact
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/contacts/<int:contact_id>', methods=['PUT', 'DELETE'])
def contact_detail(contact_id):
    """Update or delete contact"""
    
    if request.method == 'PUT':
        data = request.json
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE contacts 
                SET name = ?, email = ?, phone = ?, relationship = ?
                WHERE id = ?
            ''', (
                data['name'],
                data['email'],
                data['phone'],
                data.get('relationship', ''),
                contact_id
            ))
            
            conn.commit()
            conn.close()
            
            return jsonify({'success': True})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM contacts WHERE id = ?', (contact_id,))
            
            conn.commit()
            conn.close()
            
            return jsonify({'success': True})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

# ============= MEETINGS =============

@app.route('/api/meetings', methods=['GET', 'POST'])
def meetings():
    """Get or create meetings"""
    user_id = request.args.get('user_id') or (request.json.get('user_id') if request.json else None)
    
    if request.method == 'GET':
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            # Get meetings organized by user
            cursor.execute('''
                SELECT m.*, u.name as user_name, u.phone as user_phone
                FROM meetings m
                JOIN users u ON m.user_id = u.id
                WHERE m.user_id = ?
                ORDER BY m.start_time DESC
            ''', (user_id,))
            
            organized_meetings = []
            for row in cursor.fetchall():
                meeting = dict(row)
                
                # Get emergency contacts for this meeting
                cursor.execute('''
                    SELECT c.* FROM contacts c
                    JOIN meeting_contacts mc ON c.id = mc.contact_id
                    WHERE mc.meeting_id = ?
                ''', (meeting['id'],))
                
                meeting['contacts'] = [dict(c) for c in cursor.fetchall()]
                organized_meetings.append(meeting)
            
            # Get meetings where user is emergency contact
            cursor.execute('''
                SELECT DISTINCT m.*, u.name as user_name, u.phone as user_phone
                FROM meetings m
                JOIN users u ON m.user_id = u.id
                JOIN meeting_contacts mc ON m.id = mc.meeting_id
                JOIN contacts c ON mc.contact_id = c.id
                WHERE c.email = (SELECT email FROM users WHERE id = ?)
                   OR c.phone = (SELECT phone FROM users WHERE id = ?)
                ORDER BY m.start_time DESC
            ''', (user_id, user_id))
            
            monitoring_meetings = []
            for row in cursor.fetchall():
                meeting = dict(row)
                
                cursor.execute('''
                    SELECT c.* FROM contacts c
                    JOIN meeting_contacts mc ON c.id = mc.contact_id
                    WHERE mc.meeting_id = ?
                ''', (meeting['id'],))
                
                meeting['contacts'] = [dict(c) for c in cursor.fetchall()]
                monitoring_meetings.append(meeting)
            
            conn.close()
            
            return jsonify({
                'organized': organized_meetings,
                'monitoring': monitoring_meetings
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        data = request.json
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            # Get user info
            cursor.execute('SELECT name, phone FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            
            # Generate PIN
            pin = ''.join([str(secrets.randbelow(10)) for _ in range(4)])
            
            # Create meeting
            cursor.execute('''
                INSERT INTO meetings (
                    user_id, person_name, location, start_time, end_time,
                    comments, tracking_enabled, audio_capture_enabled, sms_enabled, status, pin
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'scheduled', ?)
            ''', (
                user_id,
                data['person_name'],
                data['location'],
                data['start_time'],
                data['end_time'],
                data.get('comments'),
                data.get('tracking_enabled', False),
                data.get('audio_capture', False),
                data.get('sms_enabled', True),
                pin
            ))
            
            meeting_id = cursor.lastrowid
            
            # Add emergency contacts
            for contact_id in data['contact_ids']:
                cursor.execute('''
                    INSERT INTO meeting_contacts (meeting_id, contact_id)
                    VALUES (?, ?)
                ''', (meeting_id, contact_id))
            
            conn.commit()
            
            # Send SMS if enabled
            if data.get('sms_enabled', True):
                cursor.execute('''
                    SELECT c.* FROM contacts c
                    JOIN meeting_contacts mc ON c.id = mc.contact_id
                    WHERE mc.meeting_id = ?
                ''', (meeting_id,))
                
                contacts = cursor.fetchall()
                
                start_time = datetime.fromisoformat(data['start_time']).strftime('%B %d, %Y at %I:%M %p')
                comments_text = f" Notes: {data['comments']}" if data.get('comments') else ""
                
                message = (
                    f"SafeMeet Alert: {user['name']} has a meeting with {data['person_name']} "
                    f"at {data['location']} on {start_time}. "
                    f"You are listed as an emergency contact. Monitor their safety.{comments_text} "
                    f"Safety PIN: {pin}"
                )
                
                for contact in contacts:
                    send_sms(contact['phone'], message)
                    cursor.execute('''
                        UPDATE meeting_contacts 
                        SET notified = 1 
                        WHERE meeting_id = ? AND contact_id = ?
                    ''', (meeting_id, contact['id']))
                
                conn.commit()
            
            # Return created meeting
            cursor.execute('SELECT * FROM meetings WHERE id = ?', (meeting_id,))
            meeting = dict(cursor.fetchone())
            
            cursor.execute('''
                SELECT c.* FROM contacts c
                JOIN meeting_contacts mc ON c.id = mc.contact_id
                WHERE mc.meeting_id = ?
            ''', (meeting_id,))
            
            meeting['contacts'] = [dict(c) for c in cursor.fetchall()]
            meeting['user_name'] = user['name']
            meeting['user_phone'] = user['phone']
            
            conn.close()
            
            return jsonify({
                'success': True,
                'meeting': meeting
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/meetings/<int:meeting_id>', methods=['GET', 'PUT', 'DELETE'])
def meeting_detail(meeting_id):
    """Get, update, or delete meeting"""
    
    if request.method == 'GET':
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT m.*, u.name as user_name, u.phone as user_phone
                FROM meetings m
                JOIN users u ON m.user_id = u.id
                WHERE m.id = ?
            ''', (meeting_id,))
            
            meeting = cursor.fetchone()
            
            if not meeting:
                return jsonify({'error': 'Meeting not found'}), 404
            
            meeting_dict = dict(meeting)
            
            cursor.execute('''
                SELECT c.* FROM contacts c
                JOIN meeting_contacts mc ON c.id = mc.contact_id
                WHERE mc.meeting_id = ?
            ''', (meeting_id,))
            
            meeting_dict['contacts'] = [dict(c) for c in cursor.fetchall()]
            
            conn.close()
            
            return jsonify(meeting_dict)
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'PUT':
        data = request.json
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            # Update various meeting fields
            update_fields = []
            update_values = []
            
            if 'status' in data:
                update_fields.append('status = ?')
                update_values.append(data['status'])
                
                if data['status'] == 'grace':
                    update_fields.append('grace_period_start = CURRENT_TIMESTAMP')
            
            if 'comments' in data:
                update_fields.append('comments = ?')
                update_values.append(data['comments'])
            
            if 'end_time' in data:
                update_fields.append('end_time = ?')
                update_values.append(data['end_time'])
                update_fields.append('grace_period_start = NULL')
                update_fields.append('overdue_alert_sent = 0')
            
            if 'latitude' in data and 'longitude' in data:
                update_fields.append('last_latitude = ?')
                update_values.append(data['latitude'])
                update_fields.append('last_longitude = ?')
                update_values.append(data['longitude'])
                update_fields.append('last_location_time = CURRENT_TIMESTAMP')
            
            if update_fields:
                update_values.append(meeting_id)
                query = f"UPDATE meetings SET {', '.join(update_fields)} WHERE id = ?"
                cursor.execute(query, update_values)
            
            conn.commit()
            conn.close()
            
            return jsonify({'success': True})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM meeting_contacts WHERE meeting_id = ?', (meeting_id,))
            cursor.execute('DELETE FROM meetings WHERE id = ?', (meeting_id,))
            
            conn.commit()
            conn.close()
            
            return jsonify({'success': True})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

# ============= ALERTS =============

@app.route('/api/alerts', methods=['GET', 'POST'])
def alerts():
    """Get or create alerts"""
    
    if request.method == 'GET':
        user_id = request.args.get('user_id')
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            # Get all alerts for meetings user organized or is monitoring
            cursor.execute('''
                SELECT DISTINCT a.*, u.name as user_name, u.phone as user_phone,
                       m.person_name, m.location, m.pin as meeting_pin
                FROM alerts a
                JOIN users u ON a.user_id = u.id
                LEFT JOIN meetings m ON a.meeting_id = m.id
                WHERE (a.user_id = ? OR m.id IN (
                    SELECT mc.meeting_id FROM meeting_contacts mc
                    JOIN contacts c ON mc.contact_id = c.id
                    WHERE c.email = (SELECT email FROM users WHERE id = ?)
                       OR c.phone = (SELECT phone FROM users WHERE id = ?)
                ))
                AND a.cleared = 0
                AND a.id NOT IN (
                    SELECT alert_id FROM user_cleared_alerts WHERE user_id = ?
                )
                ORDER BY a.created_at DESC
            ''', (user_id, user_id, user_id, user_id))
            
            alerts_list = []
            for row in cursor.fetchall():
                alert = dict(row)
                
                # Get contacts for this alert
                if alert['meeting_id']:
                    cursor.execute('''
                        SELECT c.* FROM contacts c
                        JOIN meeting_contacts mc ON c.id = mc.contact_id
                        WHERE mc.meeting_id = ?
                    ''', (alert['meeting_id'],))
                    alert['contacts'] = [dict(c) for c in cursor.fetchall()]
                else:
                    # SOS alert - get all user contacts
                    cursor.execute('''
                        SELECT * FROM contacts WHERE user_id = ?
                    ''', (alert['user_id'],))
                    alert['contacts'] = [dict(c) for c in cursor.fetchall()]
                
                alerts_list.append(alert)
            
            conn.close()
            
            return jsonify({'alerts': alerts_list})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        data = request.json
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (
                    user_id, meeting_id, alert_type, latitude, longitude
                )
                VALUES (?, ?, ?, ?, ?)
            ''', (
                data['user_id'],
                data.get('meeting_id'),
                data['alert_type'],
                data.get('latitude'),
                data.get('longitude')
            ))
            
            alert_id = cursor.lastrowid
            conn.commit()
            
            cursor.execute('''
                SELECT a.*, u.name as user_name, u.phone as user_phone,
                       m.person_name, m.location, m.pin as meeting_pin, m.comments
                FROM alerts a
                JOIN users u ON a.user_id = u.id
                LEFT JOIN meetings m ON a.meeting_id = m.id
                WHERE a.id = ?
            ''', (alert_id,))
            
            alert = dict(cursor.fetchone())
            
            # Send SMS to emergency contacts
            if data.get('meeting_id'):
                cursor.execute('''
                    SELECT c.* FROM contacts c
                    JOIN meeting_contacts mc ON c.id = mc.contact_id
                    WHERE mc.meeting_id = ?
                ''', (data['meeting_id'],))
            else:
                cursor.execute('''
                    SELECT * FROM contacts WHERE user_id = ?
                ''', (data['user_id'],))
            
            contacts = cursor.fetchall()
            
            # Format emergency message
            location_info = ""
            if data.get('latitude') and data.get('longitude'):
                location_info = f" GPS: {data['latitude']:.6f}, {data['longitude']:.6f}"
                location_info += f" Map: https://www.google.com/maps?q={data['latitude']},{data['longitude']}"
            
            meeting_info = ""
            if alert.get('person_name'):
                meeting_info = f" Meeting with {alert['person_name']} at {alert['location']}."
            
            comments_info = ""
            if alert.get('comments'):
                comments_info = f" NOTES: {alert['comments']}"
            
            pin_info = ""
            if alert.get('meeting_pin'):
                pin_info = f" Safety PIN: {alert['meeting_pin']}"
            
            message = (
                f"🚨 EMERGENCY: {alert['user_name']} needs help!{meeting_info}{comments_info}{location_info} "
                f"Call immediately: {alert['user_phone']}{pin_info}"
            )
            
            for contact in contacts:
                send_sms(contact['phone'], message)
            
            conn.close()
            
            return jsonify({
                'success': True,
                'alert': alert
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/<int:alert_id>/clear', methods=['POST'])
def clear_alert(alert_id):
    """Clear alert for specific user"""
    data = request.json
    user_id = data.get('user_id')
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Add to user_cleared_alerts table
        cursor.execute('''
            INSERT OR IGNORE INTO user_cleared_alerts (user_id, alert_id)
            VALUES (?, ?)
        ''', (user_id, alert_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/overdue', methods=['POST'])
def create_overdue_alert():
    """Create overdue alert for meeting"""
    data = request.json
    meeting_id = data.get('meeting_id')
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get meeting details
        cursor.execute('''
            SELECT m.*, u.name as user_name, u.phone as user_phone
            FROM meetings m
            JOIN users u ON m.user_id = u.id
            WHERE m.id = ?
        ''', (meeting_id,))
        
        meeting = cursor.fetchone()
        
        if not meeting:
            return jsonify({'error': 'Meeting not found'}), 404
        
        # Check if alert already exists
        cursor.execute('''
            SELECT id FROM alerts 
            WHERE meeting_id = ? AND alert_type = 'overdue' AND cleared = 0
        ''', (meeting_id,))
        
        if cursor.fetchone():
            return jsonify({'error': 'Overdue alert already exists'}), 400
        
        # Create overdue alert
        cursor.execute('''
            INSERT INTO alerts (
                user_id, meeting_id, alert_type, latitude, longitude
            )
            VALUES (?, ?, 'overdue', ?, ?)
        ''', (
            meeting['user_id'],
            meeting_id,
            meeting['last_latitude'],
            meeting['last_longitude']
        ))
        
        alert_id = cursor.lastrowid
        
        # Mark meeting as overdue alert sent
        cursor.execute('''
            UPDATE meetings SET overdue_alert_sent = 1 WHERE id = ?
        ''', (meeting_id,))
        
        conn.commit()
        
        # Send SMS to contacts
        cursor.execute('''
            SELECT c.* FROM contacts c
            JOIN meeting_contacts mc ON c.id = mc.contact_id
            WHERE mc.meeting_id = ?
        ''', (meeting_id,))
        
        contacts = cursor.fetchall()
        
        location_info = ""
        if meeting['last_latitude'] and meeting['last_longitude']:
            update_time = meeting['last_location_time'] if meeting['last_location_time'] else 'Unknown'
            location_info = f" Last GPS: {meeting['last_latitude']:.6f}, {meeting['last_longitude']:.6f} (Updated: {update_time})."
            location_info += f" Track: https://www.google.com/maps?q={meeting['last_latitude']},{meeting['last_longitude']}"
        
        comments_info = ""
        if meeting['comments']:
            comments_info = f" NOTES: {meeting['comments']}"
        
        end_time = datetime.fromisoformat(meeting['end_time']).strftime('%I:%M %p on %B %d')
        
        message = (
            f"🚨 ALERT: {meeting['user_name']} has not checked in after their meeting with "
            f"{meeting['person_name']} at {meeting['location']}. Meeting ended at {end_time}. "
            f"They may need assistance.{comments_info}{location_info} "
            f"Contact them at {meeting['user_phone']} Safety PIN: {meeting['pin']}"
        )
        
        for contact in contacts:
            send_sms(contact['phone'], message)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'alert_id': alert_id
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============= AUDIO RECORDING ENDPOINTS =============

@app.route('/api/upload-audio', methods=['POST'])
def upload_audio():
    """Upload audio recording file"""
    try:
        # Check if audio file is in request
        if 'audio' not in request.files:
            return jsonify({'error': 'No audio file provided'}), 400
        
        audio_file = request.files['audio']
        meeting_id = request.form.get('meetingId')
        user_id = request.form.get('userId')
        alert_type = request.form.get('alertType', 'emergency')
        transcription = request.form.get('transcription', '')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        
        if not audio_file.filename:
            return jsonify({'error': 'Invalid audio file'}), 400
        
        # Get user name
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT name FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        user_name = user['name'] if user else 'Unknown'
        
        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{meeting_id}_{timestamp}_{user_id}_{alert_type}.webm"
        filepath = os.path.join(AUDIO_UPLOAD_FOLDER, filename)
        
        # Save audio file
        audio_file.save(filepath)
        print(f"✅ Audio file saved: {filepath} ({os.path.getsize(filepath)} bytes)")
        
        # Save to database
        cursor.execute('''
            INSERT INTO audio_recordings (
                meeting_id, user_id, user_name, alert_type, filename, transcription, latitude, longitude
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            meeting_id,
            user_id,
            user_name,
            alert_type,
            filename,
            transcription,
            float(latitude) if latitude else None,
            float(longitude) if longitude else None
        ))
        
        conn.commit()
        recording_id = cursor.lastrowid
        conn.close()
        
        # Return URL to access the audio file
        audio_url = f"/api/audio/{filename}"
        
        return jsonify({
            'success': True,
            'url': audio_url,
            'filename': filename,
            'id': recording_id
        })
        
    except Exception as e:
        print(f"❌ Error uploading audio: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/audio/<filename>')
def get_audio(filename):
    """Serve audio file"""
    try:
        filepath = os.path.join(AUDIO_UPLOAD_FOLDER, filename)
        if os.path.exists(filepath):
            return send_file(filepath, mimetype='audio/webm')
        else:
            return jsonify({'error': 'Audio file not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/audio-recordings', methods=['GET'])
def get_audio_recordings():
    """Get all audio recordings (optionally filtered by meeting_id or alert_type)"""
    meeting_id = request.args.get('meeting_id')
    alert_type = request.args.get('alert_type')
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM audio_recordings WHERE 1=1'
        params = []
        
        if meeting_id:
            query += ' AND meeting_id = ?'
            params.append(meeting_id)
        
        if alert_type:
            query += ' AND alert_type = ?'
            params.append(alert_type)
        
        query += ' ORDER BY created_at DESC'
        
        cursor.execute(query, params)
        recordings = [dict(row) for row in cursor.fetchall()]
        
        # Add audio URL to each recording
        for recording in recordings:
            recording['url'] = f"/api/audio/{recording['filename']}"
        
        conn.close()
        
        return jsonify({'recordings': recordings})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============= USER ACCOUNT =============

@app.route('/api/user/<int:user_id>', methods=['GET', 'PUT'])
def user_detail(user_id):
    """Get or update user"""
    
    if request.method == 'GET':
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            user_dict = dict(user)
            user_dict.pop('password')
            
            # Get contacts
            cursor.execute('SELECT * FROM contacts WHERE user_id = ?', (user_id,))
            user_dict['contacts'] = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
            
            return jsonify({'user': user_dict})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'PUT':
        data = request.json
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            update_fields = []
            update_values = []
            
            if 'name' in data:
                update_fields.append('name = ?')
                update_values.append(data['name'])
            
            if 'email' in data:
                update_fields.append('email = ?')
                update_values.append(data['email'])
            
            if 'phone' in data:
                update_fields.append('phone = ?')
                update_values.append(data['phone'])
            
            if 'password' in data:
                update_fields.append('password = ?')
                update_values.append(hash_password(data['password']))
            
            if 'plan' in data:
                update_fields.append('plan = ?')
                update_values.append(data['plan'])
            
            if update_fields:
                update_values.append(user_id)
                query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
                cursor.execute(query, update_values)
            
            conn.commit()
            
            # Get updated user
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            user_dict = dict(user)
            user_dict.pop('password')
            
            # Get contacts
            cursor.execute('SELECT * FROM contacts WHERE user_id = ?', (user_id,))
            user_dict['contacts'] = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
            
            return jsonify({
                'success': True,
                'user': user_dict
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

# ============= MAIN =============

if __name__ == '__main__':
    # Check if database exists
    db_exists = os.path.exists(DATABASE)
    
    if not db_exists:
        print("🆕 Creating new database...")
        init_db()
    else:
        print("📂 Database found, checking for needed migrations...")
        migrate_existing_db()
    
    # Run initial cleanup on startup
    cleanup_old_audio_files()
    
    # Start background cleanup scheduler
    start_cleanup_scheduler()
    
    print("\n" + "="*60)
    print("🛡️  SafeMeet v5.0 Audio Server Starting")
    print("="*60)
    print("\n✨ Features:")
    print("   • Complete SQLite database storage")
    print("   • Forgot password with reset tokens")
    print("   • Meeting comments field")
    print("   • 10-minute grace period tracking")
    print("   • SMS notifications to emergency contacts")
    print("   • Audio recording upload and storage")
    print("   • Browser-based transcription (no server transcription)")
    print("   • Auto-delete audio files after 30 days")
    print("\n🌐 Server running on http://localhost:5000")
    print("📱 SMS notifications: Console logging (integrate Twilio for production)")
    print("📧 Email notifications: Console logging (integrate SMTP for production)")
    print(f"🎤 Audio files stored in: {os.path.abspath(AUDIO_UPLOAD_FOLDER)}")
    print(f"🧹 Audio retention period: {AUDIO_RETENTION_DAYS} days")
    print("\n💡 Tips:")
    print("   • Check console for SMS/email logs")
    print("   • Audio files are cleaned up automatically every 24 hours")
    print("   • Transcription is done in the browser (Chrome/Edge only)")
    print("="*60 + "\n")
    
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
