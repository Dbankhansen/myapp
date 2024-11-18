from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a random secret key
DB_NAME = 'database.db'

def init_db():
    """Initialize the database with required tables."""
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                content TEXT NOT NULL,
                created_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
         # New activities table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                time TEXT NOT NULL,
                date DATE NOT NULL,
                icon TEXT,
                location TEXT,
                participants TEXT,
                entry_id INTEGER NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (entry_id) REFERENCES entries (id)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS activity_participants (
                activity_id INTEGER,
                participant_id INTEGER,
                FOREIGN KEY (activity_id) REFERENCES activities (id),
                FOREIGN KEY (participant_id) REFERENCES participants (id),
                PRIMARY KEY (activity_id, participant_id)
            )
        ''')

# Initialize the database when the application starts
with app.app_context():
    init_db()

def adapt_datetime(ts):
    return ts.isoformat()

sqlite3.register_adapter(datetime, adapt_datetime)

@app.route('/')
def home():
    """Redirect to login or dashboard depending on session state."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            with sqlite3.connect(DB_NAME) as conn:
                password_hash = generate_password_hash(password)
                conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                             (username, password_hash))
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with sqlite3.connect(DB_NAME) as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?',
                                (username,)).fetchone()
            
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """Show the user dashboard."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT content, created_at 
            FROM entries 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        ''', (session['user_id'],))
        entries = cursor.fetchall()
        
        cursor.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
        username = cursor.fetchone()[0]
    
    # Format current datetime for the default value
    current_datetime = datetime.now().strftime('%Y-%m-%dT%H:%M')
    
    return render_template('dashboard.html', 
                         entries=entries, 
                         username=username, 
                         current_datetime=current_datetime)

@app.route('/add_entry', methods=['POST'])
def add_entry():
    """Add a new journal entry."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form.get('content')
    entry_datetime = request.form.get('entry_datetime')
    
    if not content:
        flash('Entry cannot be empty', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Parse the datetime string or use current time if not provided
        if entry_datetime:
            created_at = datetime.strptime(entry_datetime, '%Y-%m-%dT%H:%M')
        else:
            created_at = datetime.now()
        
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute('''
                INSERT INTO entries (user_id, content, created_at) 
                VALUES (?, ?, ?)
            ''', (session['user_id'], content, created_at))
        
        flash('Entry added successfully!', 'success')
    except ValueError:
        flash('Invalid date format', 'error')
    except Exception as e:
        flash('Error adding entry', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    """Log the user out."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/planner')
def visual_planner():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('visual-planner.html')

@app.route('/api/activities', methods=['GET'])
def get_activities():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    date = request.args.get('date')  # Format: YYYY-MM-DD
    
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = conn.cursor()
        
        query = '''
            SELECT 
                a.id, a.title, a.time, a.date, a.icon, 
                a.location, a.participants, a.entry_id,
                e.content as entry_content
            FROM activities a
            LEFT JOIN entries e ON a.entry_id = e.id
            WHERE a.user_id = ?
        '''
        params = [session['user_id']]
        
        if date:
            query += ' AND a.date = ?'
            params.append(date)
            
        cursor.execute(query, params)
        activities = cursor.fetchall()
        
        # Convert rows to dictionaries
        return jsonify([dict(activity) for activity in activities])

@app.route('/api/activities', methods=['POST'])
def create_activity():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    required_fields = ['title', 'time', 'date']
    
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO activities 
                (user_id, title, time, date, icon, location, participants)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                session['user_id'],
                data['title'],
                data['time'],
                data['date'],
                data.get('icon'),
                data.get('location'),
                ','.join(data.get('participants', [])) if data.get('participants') else None
            ))
            
            activity_id = cursor.lastrowid
            
            return jsonify({
                'id': activity_id,
                'message': 'Activity created successfully'
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/activities/<int:activity_id>', methods=['PUT'])
def update_activity(activity_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            
            # Verify activity ownership
            cursor.execute(
                'SELECT id FROM activities WHERE id = ? AND user_id = ?',
                (activity_id, session['user_id'])
            )
            
            if not cursor.fetchone():
                return jsonify({'error': 'Activity not found'}), 404
            
            # Update activity
            update_fields = []
            params = []
            
            for field in ['title', 'time', 'date', 'icon', 'location']:
                if field in data:
                    update_fields.append(f"{field} = ?")
                    params.append(data[field])
            
            # Handle participants separately
            if 'participants' in data:
                update_fields.append("participants = ?")
                params.append(','.join(str(p) for p in data['participants']))
            
            params.extend([datetime.now(), activity_id, session['user_id']])
            
            query = f'''
                UPDATE activities 
                SET {', '.join(update_fields)}, updated_at = ?
                WHERE id = ? AND user_id = ?
            '''
            cursor.execute(query, params)
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'Update failed'}), 500
            
            return jsonify({'message': 'Activity updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/activities/<int:activity_id>', methods=['DELETE'])
def delete_activity(activity_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM activities 
                WHERE id = ? AND user_id = ?
            ''', (activity_id, session['user_id']))
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'Activity not found'}), 404
            
            return jsonify({'message': 'Activity deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/participants', methods=['GET'])
def get_participants():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, name, email, phone 
            FROM participants 
            WHERE user_id = ?
            ORDER BY name
        ''', (session['user_id'],))
        participants = cursor.fetchall()
        return jsonify([dict(p) for p in participants])

@app.route('/api/participants', methods=['POST'])
def create_participant():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    if not data.get('name'):
        return jsonify({'error': 'Name is required'}), 400
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO participants (user_id, name, email, phone)
                VALUES (?, ?, ?, ?)
            ''', (
                session['user_id'],
                data['name'],
                data.get('email'),
                data.get('phone')
            ))
            return jsonify({
                'id': cursor.lastrowid,
                'message': 'Participant created successfully'
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/participants/<int:participant_id>', methods=['PUT'])
def update_participant(participant_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    if not data.get('name'):
        return jsonify({'error': 'Name is required'}), 400
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE participants 
                SET name = ?, email = ?, phone = ?
                WHERE id = ? AND user_id = ?
            ''', (
                data['name'],
                data.get('email'),
                data.get('phone'),
                participant_id,
                session['user_id']
            ))
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'Participant not found'}), 404
                
            return jsonify({'message': 'Participant updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/participants/<int:participant_id>', methods=['DELETE'])
def delete_participant(participant_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM participants 
                WHERE id = ? AND user_id = ?
            ''', (participant_id, session['user_id']))
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'Participant not found'}), 404
                
            return jsonify({'message': 'Participant deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/participants')
def manage_participants():
    """Show the participants management page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('participants.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4000, debug=True)

    
