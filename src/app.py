from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import secrets
import datetime
import random
import os
import uuid
import logging
import requests

# Authorship: Josia Mosses, May 2025. All rights reserved.

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# File upload configuration
UPLOAD_FOLDER = 'src/static/asset'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}
MAX_FILE_SIZE = 5 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database initialization
def init_db_7x9():
    with sqlite3.connect('voting.db') as conn:
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      reg_number TEXT UNIQUE,
                      full_name TEXT,
                      email TEXT,
                      phone TEXT,
                      level TEXT,
                      password TEXT,
                      is_admin BOOLEAN DEFAULT 0,
                      created_by INTEGER,
                      FOREIGN KEY(created_by) REFERENCES users(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS votes
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      president TEXT,
                      vice TEXT,
                      FOREIGN KEY(user_id) REFERENCES users(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS candidates
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT,
                      position TEXT,
                      photo TEXT,
                      education TEXT,
                      course TEXT)''')
        
        c.execute("PRAGMA table_info(candidates)")
        columns = [col[1] for col in c.fetchall()]
        if 'education' not in columns:
            c.execute("ALTER TABLE candidates ADD COLUMN education TEXT")
        if 'course' not in columns:
            c.execute("ALTER TABLE candidates ADD COLUMN course TEXT")
        
        c.execute('''CREATE TABLE IF NOT EXISTS password_resets
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      email TEXT,
                      token TEXT,
                      created_at TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS winners
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      position TEXT,
                      candidate_id INTEGER,
                      announced_at TIMESTAMP,
                      FOREIGN KEY (candidate_id) REFERENCES candidates(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      content TEXT,
                      created_at TIMESTAMP)''')
        
        try:
            c.execute("SELECT COUNT(*) FROM messages WHERE content LIKE ?", ('%Authorship%',))
            if c.fetchone()[0] == 0:
                c.execute('INSERT INTO messages (content, created_at) VALUES (?, ?)',
                          (f"Authorship: Voting system created by Josia Mosses, 2025", datetime.datetime.now()))
                logging.debug("Watermark message inserted successfully")
        except sqlite3.Error as e:
            logging.error(f"Error inserting watermark message: {str(e)}")
        
        # Ensure ADMIN001 exists with updated password
        try:
            c.execute("SELECT COUNT(*) FROM users WHERE reg_number = 'ADMIN001'")
            if c.fetchone()[0] == 0:
                c.execute('''INSERT INTO users (reg_number, full_name, email, phone, level, password, is_admin, created_by)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                          ('ADMIN001', 'Default Admin', 'admin@example.com', '1234567890', 'Bachelor',
                           generate_password_hash('admin@may2025'), 1, 1))
            else:
                c.execute("UPDATE users SET password = ?, is_admin = 1, created_by = 1 WHERE reg_number = 'ADMIN001'",
                          (generate_password_hash('admin@may2025'),))
        except sqlite3.Error as e:
            logging.error(f"Error setting up ADMIN001: {str(e)}")
        
        try:
            c.execute("UPDATE users SET created_by = 1 WHERE created_by IS NULL AND reg_number != 'ADMIN001'")
        except sqlite3.Error as e:
            logging.error(f"Error updating created_by: {str(e)}")
        
        conn.commit()

init_db_7x9()

# Helper functions
def get_db_conn_3z():
    conn = sqlite3.connect('voting.db', timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def get_cands_4p(position):
    with get_db_conn_3z() as conn:
        candidates = conn.execute('SELECT * FROM candidates WHERE position = ?', (position,)).fetchall()
    return candidates

def get_all_cands_8q():
    with get_db_conn_3z() as conn:
        candidates = conn.execute('SELECT * FROM candidates').fetchall()
    return candidates

def has_voted_2r(user_id):
    with get_db_conn_3z() as conn:
        vote = conn.execute('SELECT * FROM votes WHERE user_id = ?', (user_id,)).fetchone()
    return vote is not None

def gr_94x():
    with get_db_conn_3z() as conn:
        total_voters = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        votes_cast = conn.execute('SELECT COUNT(*) FROM votes').fetchone()[0]
        president_results = conn.execute('''
            SELECT c.id, c.name, c.photo, COUNT(v.id) as votes
            FROM candidates c
            LEFT JOIN votes v ON c.id = v.president
            WHERE c.position = 'president'
            GROUP BY c.id
        ''').fetchall()
        vice_results = conn.execute('''
            SELECT c.id, c.name, c.photo, COUNT(v.id) as votes
            FROM candidates c
            LEFT JOIN votes v ON c.id = v.vice
            WHERE c.position = 'vice'
            GROUP BY c.id
        ''').fetchall()
        president_results = [{'id': r['id'], 'name': r['name'], 'photo': r['photo'], 
                             'votes': r['votes'], 
                             'percentage': (r['votes'] / votes_cast * 100) if votes_cast > 0 else 0}
                            for r in president_results]
        vice_results = [{'id': r['id'], 'name': r['name'], 'photo': r['photo'], 
                         'votes': r['votes'], 
                         'percentage': (r['votes'] / votes_cast * 100) if votes_cast > 0 else 0}
                        for r in vice_results]
        winners = conn.execute('''
            SELECT w.position, c.name
            FROM winners w
            JOIN candidates c ON w.candidate_id = c.id
        ''').fetchall()
        winners_dict = {w['position']: w['name'] for w in winners}
        message = conn.execute('SELECT content, created_at FROM messages WHERE content NOT LIKE ? ORDER BY created_at DESC LIMIT 1', ('%Authorship%',)).fetchone()
        message_dict = {'content': message['content'], 'created_at': message['created_at']} if message else None
    return total_voters, winners_dict, president_results, vice_results, winners_dict, message_dict

def allowed_file_6t(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def index():
    return redirect(url_for('voting'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        reg_number = request.form['username']
        password = request.form['password']
        
        with get_db_conn_3z() as conn:
            user = conn.execute('SELECT * FROM users WHERE reg_number = ?', (reg_number,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['reg_number'] = user['reg_number']
            session['is_admin'] = user['is_admin']
            return redirect(url_for('voting'))
        else:
            error = 'Invalid registration number or password.'
    
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        try:
            user = {
                'reg_number': request.form['regNumber'],
                'full_name': request.form['fullName'],
                'email': request.form['email'],
                'phone': request.form['phone'],
                'level': request.form['level'],
                'password': generate_password_hash(request.form['password']),
                'created_by': session.get('user_id', 1)  # Default to ADMIN001
            }
            
            with get_db_conn_3z() as conn:
                conn.execute('''INSERT INTO users (reg_number, full_name, email, phone, level, password, created_by)
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                             (user['reg_number'], user['full_name'], user['email'],
                              user['phone'], user['level'], user['password'], user['created_by']))
                conn.commit()
            
            return redirect(url_for('login'))
        
        except sqlite3.IntegrityError:
            error = 'Registration number or email already exists.'
        except sqlite3.OperationalError as e:
            error = f'Database error: {str(e)}'
        except Exception as e:
            error = f'Registration failed: {str(e)}'
    
    return render_template('register.html', error=error)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    error = None
    success = None
    if request.method == 'POST':
        email = request.form['email']
        with get_db_conn_3z() as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if user:
                token = secrets.token_urlsafe(32)
                created_at = datetime.datetime.now()
                conn.execute('INSERT INTO password_resets (email, token, created_at) VALUES (?, ?, ?)',
                             (email, token, created_at))
                conn.commit()
                success = f'Recovery link: {url_for("reset_password", token=token, _external=True)} (Simulated; copy this link)'
            else:
                error = 'Email not found.'
    return render_template('forgot_password.html', error=error, success=success)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    error = None
    success = None
    with get_db_conn_3z() as conn:
        reset = conn.execute('SELECT * FROM password_resets WHERE token = ?', (token,)).fetchone()
        if not reset or (datetime.datetime.now() - datetime.datetime.strptime(reset['created_at'], '%Y-%m-%d %H:%M:%S.%f')).total_seconds() > 3600:
            error = 'Invalid or expired token.'
            return render_template('reset_password.html', error=error)
        
        if request.method == 'POST':
            password = request.form['password']
            with get_db_conn_3z() as conn:
                conn.execute('UPDATE users SET password = ? WHERE email = ?', (generate_password_hash(password), reset['email']))
                conn.execute('DELETE FROM password_resets WHERE token = ?', (token,))
                conn.commit()
            success = 'Password reset successfully. Please login.'
            return render_template('reset_password.html', success=success)
    
    return render_template('reset_password.html', error=error)

@app.route('/voting', methods=['GET', 'POST'])
def voting():
    error = None
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    total_voters, winners, president_results, vice_results, winners_dict, message = gr_94x()
    
    if request.method == 'POST':
        if has_voted_2r(session['user_id']):
            error = 'You have already voted.'
        else:
            president = request.form.get('president')
            vice = request.form.get('vice')
            
            if president and vice:
                try:
                    with get_db_conn_3z() as conn:
                        conn.execute('INSERT INTO votes (user_id, president, vice) VALUES (?, ?, ?)',
                                     (session['user_id'], president, vice))
                        conn.commit()
                    return redirect(url_for('voting'))
                except sqlite3.OperationalError as e:
                    error = f'Failed to submit vote: {str(e)}'
    
    presidents = get_cands_4p('president')
    vice_presidents = get_cands_4p('vice')
    
    return render_template('index.html',
                          presidents=presidents,
                          vice_presidents=vice_presidents,
                          total_voters=total_voters,
                          votes_cast=total_voters - (total_voters - len([v for v in president_results if v['votes'] > 0])),
                          president_results=president_results,
                          vice_results=vice_results,
                          winners=winners,
                          error=error,
                          message=message,
                          has_voted=has_voted_2r(session['user_id']) if 'user_id' in session else False)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    sort_by = request.args.get('sort', 'reg_number')
    order = request.args.get('order', 'asc')
    valid_sorts = ['id', 'reg_number', 'full_name', 'email', 'phone', 'level']
    sort_by = sort_by if sort_by in valid_sorts else 'reg_number'
    order = order if order in ['asc', 'desc'] else 'asc'
    error = None
    success = None
    
    with get_db_conn_3z() as conn:
        # Exclude ADMIN001 from user list
        users = conn.execute(f'SELECT * FROM users WHERE reg_number != "ADMIN001" ORDER BY {sort_by} {order.upper()}').fetchall()
        presidents = get_cands_4p('president')
        vice_presidents = get_cands_4p('vice')
        all_candidates = get_all_cands_8q()
        current_message = conn.execute('SELECT content, created_at FROM messages WHERE content NOT LIKE ? ORDER BY created_at DESC LIMIT 1', ('%Authorship%',)).fetchone()
        # Fetch watermark message
        try:
            watermark = conn.execute('SELECT content, created_at FROM messages WHERE content LIKE ?', ('%Authorship%',)).fetchone()
            logging.debug("Watermark message fetched successfully")
        except sqlite3.Error as e:
            logging.error(f"Error fetching watermark message: {str(e)}")
            watermark = None
        
        if request.method == 'POST':
            if 'toggle_admin' in request.form:
                user_id = request.form['user_id']
                is_admin = request.form['is_admin'] == '1'
                # PModMADMIN001
                user = conn.execute('SELECT reg_number FROM users WHERE id = ?', (user_id,)).fetchone()
                if user and user['reg_number'] == 'ADMIN001':
                    error = 'Cannot modify the default admin account.'
                else:
                    conn.execute('UPDATE users SET is_admin = ? WHERE id = ?', (1 if is_admin else 0, user_id))
                    conn.commit()
                    success = 'Admin status updated successfully.'
            elif 'announce_winner' in request.form:
                president_id = request.form.get('president')
                vice_id = request.form.get('vice')
                announced_at = datetime.datetime.now()
                conn.execute('DELETE FROM winners')
                if president_id:
                    conn.execute('INSERT INTO winners (position, candidate_id, announced_at) VALUES (?, ?, ?)',
                                 ('president', president_id, announced_at))
                if vice_id:
                    conn.execute('INSERT INTO winners (position, candidate_id, announced_at) VALUES (?, ?, ?)',
                                 ('vice', vice_id, announced_at))
                conn.commit()
                success = 'Winners announced successfully.'
            elif 'add_candidate' in request.form:
                name = request.form.get('name')
                position = request.form.get('position')
                education = request.form.get('education')
                course = request.form.get('course')
                file = request.files.get('photo')
                
                if not all([name, position, education, course]):
                    error = 'All fields are required.'
                elif position not in ['president', 'vice']:
                    error = 'Invalid position.'
                elif file and file.filename and allowed_file_6t(file.filename):
                    if file.content_length > MAX_FILE_SIZE:
                        error = 'File size exceeds 5MB limit.'
                    else:
                        filename = secure_filename(file.filename)
                        ext = filename.rsplit('.', 1)[1].lower()
                        unique_filename = f"{uuid.uuid4().hex}.{ext}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                        logging.debug(f"Saving file to: {file_path}")
                        try:
                            file.save(file_path)
                            if os.path.exists(file_path):
                                logging.debug(f"File saved successfully: {file_path}")
                            else:
                                logging.error(f"File not saved: {file_path}")
                                error = 'Failed to save photo.'
                                return render_template('admin.html', users=users, presidents=presidents,
                                                      vice_presidents=vice_presidents, all_candidates=all_candidates,
                                                      sort_by=sort_by, order=order, error=error, success=success,
                                                      current_message=current_message, watermark=watermark)
                            photo = f"asset/{unique_filename}"
                            
                            try:
                                conn.execute('''INSERT INTO candidates (name, position, photo, education, course)
                                             VALUES (?, ?, ?, ?, ?)''',
                                            (name, position, photo, education, course))
                                conn.commit()
                                success = f'Candidate {name} added successfully.'
                            except sqlite3.IntegrityError:
                                error = 'Candidate name already exists.'
                                os.remove(file_path)
                            except Exception as e:
                                error = f'Failed to add candidate: {str(e)}'
                                os.remove(file_path)
                        except Exception as e:
                            logging.error(f"File save error: {str(e)}")
                            error = f'Failed to save photo: {str(e)}'
                else:
                    error = 'Invalid or missing photo (only JPG, JPEG, PNG allowed).'
            
            elif 'delete_user' in request.form:
                user_id = request.form.get('user_id')
                try:
                    user = conn.execute('SELECT reg_number, created_by FROM users WHERE id = ?', (user_id,)).fetchone()
                    if user['reg_number'] == 'ADMIN001':
                        error = "The default admin account cannot be deleted."
                    elif user['created_by'] != 1:
                        error = "Only users created by the default admin can be deleted."
                    else:
                        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
                        conn.commit()
                        success = 'User deleted successfully.'
                except Exception as e:
                    error = f'Failed to delete user: {str(e)}'
            elif 'delete_candidate' in request.form:
                candidate_id = request.form.get('candidate_id')
                try:
                    candidate = conn.execute('SELECT photo FROM candidates WHERE id = ?', (candidate_id,)).fetchone()
                    if candidate and candidate['photo']:
                        photo_path = os.path.join('static', candidate['photo'])
                        if os.path.exists(photo_path):
                            os.remove(photo_path)
                            logging.debug(f"Deleted photo: {photo_path}")
                        else:
                            logging.warning(f"Photo not found for deletion: {photo_path}")
                    conn.execute('DELETE FROM candidates WHERE id = ?', (candidate_id,))
                    conn.commit()
                    success = 'Candidate deleted successfully.'
                except Exception as e:
                    logging.error(f"Delete candidate error: {str(e)}")
                    error = f'Failed to delete candidate: {str(e)}'
            elif 'post_message' in request.form:
                content = request.form.get('message')
                if not content or len(content.strip()) == 0:
                    error = 'Message cannot be empty.'
                elif len(content) > 500:
                    error = 'Message cannot exceed 500 characters.'
                else:
                    try:
                        created_at = datetime.datetime.now()
                        conn.execute('DELETE FROM messages WHERE content NOT LIKE ?', ('%Authorship%',))
                        conn.execute('INSERT INTO messages (content, created_at) VALUES (?, ?)',
                                     (content, created_at))
                        conn.commit()
                        success = 'Message posted successfully.'
                    except Exception as e:
                        error = f'Failed to post message: {str(e)}'
    
    return render_template('admin.html', users=users, presidents=presidents, vice_presidents=vice_presidents,
                          all_candidates=all_candidates, sort_by=sort_by, order=order, error=error, success=success,
                          current_message=current_message, watermark=watermark)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)