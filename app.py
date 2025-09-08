import os
import time
import base64
import io
from datetime import datetime
from bson.objectid import ObjectId
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from flask_pymongo import PyMongo
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
from pymongo.errors import ConnectionFailure, OperationFailure

# --- Configuration ---
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-super-secret-key-you-should-change'
    MONGO_URI = os.environ.get('MONGO_URI') or "mongodb://localhost:27017/attendance_app"
    QR_REFRESH_RATE_SECONDS = 2
    TOKEN_VALIDITY_SECONDS = 5

# --- App Initialization ---
app = Flask(__name__)
app.config.from_object(Config)

# Initialize MongoDB connection with error handling
try:
    mongo = PyMongo(app)
    # Test the connection
    mongo.db.command('ping')
    print("Successfully connected to MongoDB Atlas.")
    mongo_connected = True
except (ConnectionFailure, OperationFailure, Exception) as e:
    print(f"MongoDB connection failed: {e}")
    mongo_connected = False
    # Create a dummy mongo object to avoid attribute errors
    class DummyMongo:
        def __getattr__(self, name):
            return self
        def __call__(self, *args, **kwargs):
            return self
    mongo = DummyMongo()

socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Setup for generating and verifying secure, timed tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Constants ---
CHECKPOINTS = ["Period 1", "Period 2", "Period 3", "Period 4"]

# --- Custom User Class for Flask-Login ---
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data["username"]
        self.password_hash = user_data["password"]
        self.role = user_data.get("role", "student")
        self.section = user_data.get("section", "Unassigned")
        self.student_name = user_data.get("student_name", user_data["username"])

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- User Loader ---
@login_manager.user_loader
def load_user(user_id):
    if not mongo_connected:
        # Fallback to demo users if MongoDB is not connected
        demo_users = {
            "111111111111111111111111": {
                "_id": ObjectId("111111111111111111111111"),
                "username": "teacher",
                "password": generate_password_hash("password", method='pbkdf2:sha256'),
                "role": "teacher",
                "section": "A",
                "student_name": "Demo Teacher"
            },
            "222222222222222222222222": {
                "_id": ObjectId("222222222222222222222222"),
                "username": "student1",
                "password": generate_password_hash("password", method='pbkdf2:sha256'),
                "role": "student",
                "section": "A",
                "student_name": "Student One"
            },
            "333333333333333333333333": {
                "_id": ObjectId("333333333333333333333333"),
                "username": "student2",
                "password": generate_password_hash("password", method='pbkdf2:sha256'),
                "role": "student",
                "section": "B",
                "student_name": "Student Two"
            }
        }
        user_data = demo_users.get(user_id)
        if user_data:
            return User(user_data)
        return None
    
    user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

# --- Helper Functions ---
def generate_qr_code_image(token):
    """Generates a base64 encoded QR code image from a token."""
    img = qrcode.make(token)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')

def db_find_one(collection, query):
    """Safe database find_one operation with fallback"""
    if not mongo_connected:
        return None
    try:
        return mongo.db[collection].find_one(query)
    except:
        return None

def db_find(collection, query=None):
    """Safe database find operation with fallback"""
    if not mongo_connected:
        return []
    try:
        if query:
            return list(mongo.db[collection].find(query))
        return list(mongo.db[collection].find())
    except:
        return []

def db_count_documents(collection, query=None):
    """Safe database count_documents operation with fallback"""
    if not mongo_connected:
        return 0
    try:
        if query:
            return mongo.db[collection].count_documents(query)
        return mongo.db[collection].count_documents({})
    except:
        return 0

def db_update_one(collection, filter, update, upsert=False):
    """Safe database update_one operation with fallback"""
    if not mongo_connected:
        return type('result', (object,), {'modified_count': 0})
    try:
        return mongo.db[collection].update_one(filter, update, upsert=upsert)
    except:
        return type('result', (object,), {'modified_count': 0})

def db_insert_one(collection, document):
    """Safe database insert_one operation with fallback"""
    if not mongo_connected:
        return type('result', (object,), {'inserted_id': ObjectId()})
    try:
        return mongo.db[collection].insert_one(document)
    except:
        return type('result', (object,), {'inserted_id': ObjectId()})

def db_insert_many(collection, documents):
    """Safe database insert_many operation with fallback"""
    if not mongo_connected:
        return type('result', (object,), {'inserted_ids': [ObjectId() for _ in documents]})
    try:
        return mongo.db[collection].insert_many(documents)
    except:
        return type('result', (object,), {'inserted_ids': [ObjectId() for _ in documents]})

# --- Authentication Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        redirect_url = url_for('teacher_dashboard') if current_user.role == 'teacher' else url_for('student_dashboard')
        return redirect(redirect_url)
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check against demo users first if MongoDB is not connected
        if not mongo_connected:
            demo_users = {
                "teacher": {
                    "_id": ObjectId("111111111111111111111111"),
                    "username": "teacher",
                    "password": generate_password_hash("password", method='pbkdf2:sha256'),
                    "role": "teacher",
                    "section": "A",
                    "student_name": "Demo Teacher"
                },
                "student1": {
                    "_id": ObjectId("222222222222222222222222"),
                    "username": "student1",
                    "password": generate_password_hash("password", method='pbkdf2:sha256'),
                    "role": "student",
                    "section": "A",
                    "student_name": "Student One"
                },
                "student2": {
                    "_id": ObjectId("333333333333333333333333"),
                    "username": "student2",
                    "password": generate_password_hash("password", method='pbkdf2:sha256'),
                    "role": "student",
                    "section": "B",
                    "student_name": "Student Two"
                }
            }
            
            user_data = demo_users.get(username)
            if not user_data:
                flash(f"No user found with username '{username}'.")
            elif not check_password_hash(user_data['password'], password):
                flash('Incorrect password, please try again.')
            else:
                user = User(user_data)
                login_user(user)
                redirect_url = url_for('teacher_dashboard') if user.role == 'teacher' else url_for('student_dashboard')
                return redirect(redirect_url)
        else:
            # Use MongoDB for authentication
            user_data = db_find_one('users', {"username": username})
            
            if not user_data:
                flash(f"No user found with username '{username}'.")
            elif not check_password_hash(user_data['password'], password):
                flash('Incorrect password, please try again.')
            else:
                user = User(user_data)
                login_user(user)
                redirect_url = url_for('teacher_dashboard') if user.role == 'teacher' else url_for('student_dashboard')
                return redirect(redirect_url)
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Core Application Routes ---
@app.route('/api/student_stats')
@login_required
def student_stats():
    if current_user.role == 'teacher':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    student_id = ObjectId(current_user.id)
    total_classes = db_count_documents('attendance')
    attended_classes = db_count_documents('attendance', {"records.user_id": student_id})
    percentage = round((attended_classes / total_classes) * 100, 2) if total_classes > 0 else 0

    today_date = datetime.utcnow().strftime('%Y-%m-%d')
    today_doc = db_find_one('attendance', {"date": today_date})
    classes_today = 0
    if today_doc:
        classes_today = len({rec['checkpoint'] for rec in today_doc.get("records", [])
                             if str(rec["user_id"]) == str(student_id)})

    return jsonify({
        'success': True, 'percentage': percentage, 'classes_today': classes_today,
        'total_classes_today': len(CHECKPOINTS), 'emergency_contacts': 5
    })

@app.route('/teacher')
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        return "Access Denied", 403
    return render_template('teacher_dashboard.html')

@app.route('/teacher_qr')
@login_required
def teacher_qr():
    if current_user.role != 'teacher':
        return "Access Denied", 403
    today_date = datetime.utcnow().strftime('%Y-%m-%d')
    qr_refresh_ms = app.config.get('QR_REFRESH_RATE_SECONDS', 10) * 1000
    return render_template('teacher_qr.html', qr_refresh_ms=qr_refresh_ms, today_date=today_date, checkpoints=CHECKPOINTS)

@app.route('/teacher/monitor')
@login_required
def teacher_monitor():
    if current_user.role != 'teacher':
        return "Access Denied", 403
    date_str = request.args.get('date', datetime.utcnow().strftime('%Y-%m-%d'))
    daily_attendance_doc = db_find_one('attendance', {"date": date_str})
    return render_template('teacher_monitor.html', daily_doc=daily_attendance_doc, date_str=date_str)

@app.route('/teacher/manual_entry')
@login_required
def teacher_manual_entry():
    if current_user.role != 'teacher':
        return "Access Denied", 403
    today_date = datetime.utcnow().strftime('%Y-%m-%d')
    students = db_find('users', {"role": "student"})
    sections = sorted(list({s.get("section", "Unassigned") for s in students}))
    return render_template(
        'teacher_manual_entry.html', students=students, sections=sections,
        today_date=today_date, checkpoints=CHECKPOINTS
    )

@app.route('/student')
@login_required
def student_dashboard():
    name = current_user.student_name
    if current_user.role == 'teacher':
        return "Access Denied", 403
    
    return render_template('student_dashboard.html', name=name)

# --- New Teacher Dashboard Routes ---
@app.route('/teacher/students')
@login_required
def teacher_students():
    """Route to view all students."""
    if current_user.role != 'teacher':
        return "Access Denied", 403
    
    students = db_find('users', {"role": "student"})
    return render_template('teacher_students.html', students=students)

@app.route('/teacher/assignments')
@login_required
def teacher_assignments():
    """Placeholder route for the assignments section."""
    if current_user.role != 'teacher':
        return "Access Denied", 403
    
    assignments = [
        {"title": "Math Homework 1", "due_date": "2025-09-10", "status": "Pending"},
        {"title": "Science Project", "due_date": "2025-09-12", "status": "Submitted"}
    ]
    return render_template('teacher_assignments.html', assignments=assignments)

@app.route('/teacher/grades')
@login_required
def teacher_grades():
    """Placeholder route for the grades section."""
    if current_user.role != 'teacher':
        return "Access Denied", 403

    grades = [
        {"student_name": "Amit Sharma", "subject": "Math", "grade": "A"},
        {"student_name": "Priya Verma", "subject": "Science", "grade": "B+"},
        {"student_name": "Rohit Kumar", "subject": "English", "grade": "A-"},
    ]
    return render_template('teacher_grades.html', grades=grades)

@app.route('/teacher/add_student')
@login_required
def teacher_add_student():
    """Route to view the add student form."""
    if current_user.role != 'teacher':
        return "Access Denied", 403
    return render_template('add_student.html')

@app.route('/api/add_student', methods=['POST'])
@login_required
def api_add_student():
    """API endpoint for teachers to add a new student."""
    if current_user.role != 'teacher':
        return jsonify({'success': False, 'error': 'Access Denied'}), 403

    data = request.get_json()
    required_fields = ['studentName', 'rollNumber', 'section', 'username', 'password']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'success': False, 'error': f'Missing field: {field}'}), 400

    # Check for duplicate username
    if db_find_one('users', {"username": data['username']}):
        return jsonify({'success': False, 'error': 'Username already exists'}), 400

    # Insert student into DB
    new_student = {
        "username": data['username'],
        "password": generate_password_hash(data['password'], method='pbkdf2:sha256'),
        "role": "student",
        "student_name": data['studentName'],
        "roll_number": data['rollNumber'],
        "section": data['section'],
        "status": "absent"
    }
    result = db_insert_one('users', new_student)

    return jsonify({'success': True, 'message': 'Student added successfully', 'id': str(result.inserted_id)})

# --- API and WebSocket Logic ---
@socketio.on('connect', namespace='/teacher')
def teacher_connect():
    print("Teacher client connected")

@socketio.on('request_qr_code', namespace='/teacher')
def handle_qr_request(data):
    date, checkpoint = data.get('date'), data.get('checkpoint')
    if not date or not checkpoint: return
    token = serializer.dumps({'date': date, 'checkpoint': checkpoint, 'ts': time.time()})
    qr_image = generate_qr_code_image(token)
    emit('new_qr_code', {'image': qr_image})

@app.route('/api/mark_attendance', methods=['POST'])
@login_required
def api_mark_attendance():
    token = request.get_json().get('token')
    if not token: return jsonify({'success': False, 'error': 'Token is missing.'}), 400

    try:
        payload = serializer.loads(token, max_age=app.config.get('TOKEN_VALIDITY_SECONDS', 15))
        date, checkpoint = payload['date'], payload['checkpoint']

        existing_record = db_find_one('attendance', {
            "date": date, "records": {"$elemMatch": {"user_id": ObjectId(current_user.id), "checkpoint": checkpoint}}
        })
        if existing_record: return jsonify({'success': False, 'error': f'Attendance already marked for {checkpoint}.'}), 409

        new_record = {"user_id": ObjectId(current_user.id), "username": current_user.username, "timestamp": datetime.utcnow(), "checkpoint": checkpoint, "method": "QR"}
        db_update_one('attendance', {"date": date}, {"$push": {"records": new_record}}, upsert=True)
        socketio.emit('student_checked_in', {**new_record, 'timestamp': new_record['timestamp'].strftime('%I:%M:%S %p'), 'date': date}, namespace='/teacher', broadcast=True)
        return jsonify({'success': True, 'message': 'Attendance marked successfully!'})

    except SignatureExpired: return jsonify({'success': False, 'error': 'QR Code has expired.'}), 400
    except (BadTimeSignature, Exception): return jsonify({'success': False, 'error': 'Invalid QR Code.'}), 400

@app.route('/api/manual_mark', methods=['POST'])
@login_required
def manual_mark():
    if current_user.role != 'teacher': return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    data = request.get_json()
    student_id, date, checkpoint = data.get('student_id'), data.get('date'), data.get('checkpoint')
    if not all([student_id, date, checkpoint]): return jsonify({'success': False, 'error': 'Missing data.'}), 400

    student_data = db_find_one('users', {"_id": ObjectId(student_id)})
    if not student_data: return jsonify({'success': False, 'error': 'Student not found'}), 404

    existing_record = db_find_one('attendance', {
        "date": date, "records": {"$elemMatch": {"user_id": ObjectId(student_id), "checkpoint": checkpoint}}
    })
    if existing_record: return jsonify({'success': False, 'error': f'{student_data["username"]} already marked for {checkpoint}.'}), 409

    new_record = {"user_id": ObjectId(student_id), "username": student_data["username"], "timestamp": datetime.utcnow(), "checkpoint": checkpoint, "method": "Manual"}
    db_update_one('attendance', {"date": date}, {"$push": {"records": new_record}}, upsert=True)
    socketio.emit('student_checked_in', {**new_record, 'timestamp': new_record['timestamp'].strftime('%I:%M:%S %p'), 'date': date}, namespace='/teacher', broadcast=True)
    return jsonify({'success': True, 'username': student_data["username"]})

@app.route('/api/manual_bulk_mark', methods=['POST'])
@login_required
def manual_bulk_mark():
    if current_user.role != 'teacher': return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    data = request.get_json()
    student_ids, date, checkpoint = data.get('student_ids', []), data.get('date'), data.get('checkpoint')
    if not student_ids or not date or not checkpoint: return jsonify({'success': False, 'error': 'Missing data'}), 400

    updated, skipped = [], []
    for sid in student_ids:
        student_data = db_find_one('users', {"_id": ObjectId(sid)})
        if not student_data:
            skipped.append(f"ID:{sid}"); continue

        existing_record = db_find_one('attendance', {
            "date": date, "records": {"$elemMatch": {"user_id": ObjectId(sid), "checkpoint": checkpoint}}
        })
        if existing_record:
            skipped.append(student_data["username"]); continue

        new_record = {"user_id": ObjectId(sid), "username": student_data["username"], "timestamp": datetime.utcnow(), "checkpoint": checkpoint, "method": "Manual"}
        db_update_one('attendance', {"date": date}, {"$push": {"records": new_record}}, upsert=True)
        updated.append(student_data["username"])
        socketio.emit('student_checked_in', {**new_record, 'timestamp': new_record['timestamp'].strftime('%I:%M:%S %p'), 'date': date}, namespace='/teacher', broadcast=True)

    return jsonify({'success': True, 'updated': updated, 'skipped': skipped})

# --- Health Check Endpoint ---
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'database_connected': mongo_connected,
        'timestamp': datetime.utcnow().isoformat()
    })

# --- Main Execution & Data Seeding ---
if __name__ == '__main__':
    # Only seed data if MongoDB is connected
    if mongo_connected:
        with app.app_context(): 
            if db_count_documents('users') == 0:
                print("Seeding database with demo users...")
                hashed_password = generate_password_hash("password", method='pbkdf2:sha256')
                
                demo_users = [
                    {"username": "teacher", "password": hashed_password, "role": "teacher", "section": "A", "status": "absent", "student_name": "Demo Teacher"},
                    {"username": "student1", "password": hashed_password, "role": "student", "section": "A", "status": "absent", "student_name": "Student One"},
                    {"username": "student2", "password": hashed_password, "role": "student", "section": "B", "status": "absent", "student_name": "Student Two"},
                ]
                db_insert_many('users', demo_users)
                print("Demo users created.")
    
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
