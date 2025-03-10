from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # For production, use a fixed secret key stored securely
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(days=7)  # Set session to last for 7 days

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'

    def __repr__(self):
        return f'<User {self.username}>'

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login', next=request.url))
        
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('home'))
            
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password or not confirm_password:
            flash('All fields are required', 'error')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
            
        # Check if username or email already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('register.html')
            
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Hash password and create user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            session.permanent = remember
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            flash(f'Welcome back, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Login failed. Please check your username and password.', 'error')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/courses')
def courses():
    # Basic courses available to all users
    courses_list = [
        {"name": "Basic Penetration Testing", "difficulty": "Beginner"},
        {"name": "Web Security", "difficulty": "Intermediate"},
        {"name": "Malware Analysis", "difficulty": "Advanced"}
    ]
    
    # Add premium courses for logged-in users
    if 'user_id' in session:
        premium_courses = [
            {'name': 'Wireless Network Hacking', 'difficulty': 'Advanced'},
            {'name': 'Advanced Exploit Development', 'difficulty': 'Expert'}
        ]
        courses_list.extend(premium_courses)
    
    return render_template('courses.html', courses=courses_list)

@app.route('/labs')
@login_required  # Only logged-in users can access labs
def labs():
    labs = [
        {'name': 'Command Injection Lab', 'difficulty': 'Beginner'},
        {'name': 'SQL Injection Lab', 'difficulty': 'Intermediate'},
        {'name': 'XSS Attack Lab', 'difficulty': 'Intermediate'},
        {'name': 'Password Cracking Lab', 'difficulty': 'Advanced'}
    ]
    return render_template('labs.html', labs=labs)

@app.route('/tools')
@login_required  # Only logged-in users can access tools
def tools():
    tools = [
        {'name': 'Network Scanner', 'description': 'Scan networks for open ports and services'},
        {'name': 'Password Generator', 'description': 'Generate strong, random passwords'},
        {'name': 'Hash Analyzer', 'description': 'Identify hash types and attempt decryption'}
    ]
    return render_template('tools.html', tools=tools)

@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')
        
        # Update email
        if email and email != user.email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('Email already registered', 'error')
            else:
                user.email = email
                flash('Email updated successfully', 'success')
        
        # Update password
        if current_password and new_password and confirm_new_password:
            if not bcrypt.check_password_hash(user.password, current_password):
                flash('Current password is incorrect', 'error')
            elif new_password != confirm_new_password:
                flash('New passwords do not match', 'error')
            else:
                user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                flash('Password updated successfully', 'success')
        
        db.session.commit()
        return redirect(url_for('profile'))
        
    return render_template('update_profile.html', user=user)

# Admin dashboard
@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin/dashboard.html', users=users)

# Create admin user command
@app.cli.command('create-admin')
def create_admin():
    """Creates an admin user."""
    username = input('Enter admin username: ')
    email = input('Enter admin email: ')
    password = input('Enter admin password: ')
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    admin = User(username=username, email=email, password=hashed_password, role='admin')
    
    db.session.add(admin)
    db.session.commit()
    print(f'Admin user {username} created successfully!')

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)