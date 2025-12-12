import os
import logging
import csv
from io import StringIO
from functools import wraps
from datetime import datetime, timedelta

from django.shortcuts import render, redirect
from django.http import HttpResponse, FileResponse, Http404
from django.urls import reverse
from django.conf import settings
from django.contrib import messages
from django.views.decorators.http import require_http_methods

# database helper - you should create core/db.py as discussed
from .db import db_cursor, get_db_connection

# password utils (kept same as your Flask app)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png'}

# Upload folder (use MEDIA_ROOT if available)
UPLOAD_BASE = getattr(settings, 'MEDIA_ROOT', None)
if not UPLOAD_BASE:
    UPLOAD_BASE = os.path.join(settings.BASE_DIR, 'uploads')
os.makedirs(os.path.join(UPLOAD_BASE, 'uploads'), exist_ok=True)
UPLOAD_FOLDER = os.path.join(UPLOAD_BASE, 'uploads')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Decorators (session-based, similar to Flask)
def login_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.session.get('user_id'):
            messages.warning(request, 'Please log in to access this page.')
            # store next param
            next_url = request.get_full_path()
            return redirect(f"{reverse('login')}?next={next_url}")
        return view_func(request, *args, **kwargs)
    return _wrapped


def admin_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if request.session.get('role') != 'Admin' and request.session.get('role') != 'admin':
            messages.error(request, 'Admin access required')
            return redirect('dashboard')
        return view_func(request, *args, **kwargs)
    return _wrapped


# Helper utility to map pyodbc cursor results to dicts
def rows_to_dicts(cursor, rows):
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, r)) for r in rows]


# -------------------------
# Basic routes: index, home
# -------------------------
def index(request):
    if request.session.get('user_id'):
        return redirect('dashboard')
    return render(request, 'index.html')


def home(request):
    # old Flask had duplicate '/', keep behavior identical to Flask's home()
    return render(request, 'dashboard.html')


# -------------------------
# Auth: register, login, logout
# -------------------------
@require_http_methods(["GET", "POST"])
def register(request):
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        if not all([name, email, password, confirm_password]):
            messages.error(request, 'All fields are required')
            return redirect('register')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match')
            return redirect('register')

        # password validation similar to Flask validate_password
        def validate_password(pwd):
            import re
            if len(pwd) < 8:
                return False
            if not re.search("[a-z]", pwd): return False
            if not re.search("[A-Z]", pwd): return False
            if not re.search("[0-9]", pwd): return False
            if not re.search("[!@#$%^&*()]", pwd): return False
            return True

        if not validate_password(password):
            messages.error(request,
                           'Password must be at least 8 characters with uppercase, lowercase, number and special character')
            return redirect('register')

        hashed_password = generate_password_hash(password)

        try:
            with db_cursor() as cursor:
                cursor.execute('''
                    INSERT INTO Users (Name, Email, Password, Role, CreatedAt)
                    VALUES (?, ?, ?, ?, ?)
                ''', (name, email, hashed_password, 'User', datetime.now()))
            # send verification email (best-effort)
            try:
                send_verification_email(email, name)
            except Exception as e:
                logger.warning("Email send for verification failed: %s", e)

            messages.success(request, 'Registration successful! Please check your email to verify your account.')
            return redirect('login')
        except Exception as e:
            logger.exception("Registration failed")
            messages.error(request, 'Registration failed. Email may already be in use.')
            return redirect('register')

    return render(request, 'register.html')


@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        if not email or not password:
            messages.error(request, "Email and password are required")
            return redirect('login')

        try:
            with db_cursor() as cursor:
                cursor.execute('''
                    SELECT UserID, Name, Email, Password, Role
                    FROM Users 
                    WHERE Email = ?
                ''', (email,))
                user = cursor.fetchone()

            if user:
                # user is a tuple (UserID, Name, Email, Password, Role)
                user_id, name, user_email, db_password, role = user
                if check_password_hash(db_password, password):
                    request.session['user_id'] = user_id
                    request.session['name'] = name
                    request.session['email'] = user_email
                    request.session['role'] = role
                    messages.success(request, "Login successful!")

                    # redirect based on role
                    if role == 'Admin' or role == 'admin':
                        return redirect('admin_panel')
                    return redirect('dashboard')
                else:
                    messages.error(request, "Incorrect password")
            else:
                messages.warning(request, "No user found with this email")
        except Exception as e:
            logger.exception("Login error")
            messages.error(request, "A database error occurred. Please try again.")

    return render(request, 'login.html')


@login_required
def logout_view(request):
    request.session.flush()
    messages.success(request, 'Logged out successfully.')
    return redirect('login')


# -------------------------
# Database test / debug
# -------------------------
def db_test(request):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM healthdata")
            count = cur.fetchone()[0]
            return HttpResponse(f"Healthdata rows: {count}")
    except Exception as e:
        logger.exception("Database test failed")
        return HttpResponse(f"Error: {e}", status=500)


def debug_all(request):
    try:
        with db_cursor() as cursor:
            cursor.execute("SELECT TOP 5 * FROM Users")
            users = cursor.fetchall()
            cursor.execute("SELECT TOP 5 * FROM HealthData")
            health = cursor.fetchall()
            cursor.execute("SELECT TOP 5 * FROM Reminders")
            reminders = cursor.fetchall()

        return HttpResponse(f"""
            <pre>
            ✅ Users: {len(users)}
            ✅ HealthData: {len(health)}
            ✅ Reminders: {len(reminders)}
            </pre>
        """)
    except Exception as e:
        logger.exception("Debug all failed")
        return HttpResponse(f"<pre>❌ ERROR: {e}</pre>")


# -------------------------
# Dashboard
# -------------------------
@login_required
def dashboard(request):
    now = datetime.now()

    health_data = []
    medical_records = []
    reminders = []
    goals = []
    labels = []
    calories_data = []
    duration_data = []

    try:
        with db_cursor() as cursor:
            # Health Data
            cursor.execute("""
                SELECT HealthDataID, UserID, Date, Type, Category, Schedule,
                       Description, Calories, Duration
                FROM HealthData
                WHERE UserID = ?
                ORDER BY Date DESC
            """, (request.session['user_id'],))
            raw_health = cursor.fetchall()
            # columns are in cursor.description
            health_data = rows_to_dicts(cursor, raw_health)
            # lowercase keys (original app used .lower() keys)
            for h in health_data:
                for k in list(h.keys()):
                    h[k.lower()] = h.pop(k)

            # Medical Records
            cursor.execute("""
                SELECT record_id, UserID, title, description, file_path, record_date
                FROM MedicalRecords
                WHERE UserID = ?
                ORDER BY record_date DESC
            """, (request.session['user_id'],))
            med_raw = cursor.fetchall()
            medical_records = rows_to_dicts(cursor, med_raw)
            for r in medical_records:
                for k in list(r.keys()):
                    r[k.lower()] = r.pop(k)

            # Reminders (Pending and future)
            try:
                cursor.execute("""
                    SELECT ReminderID, UserID, Type, Description, Date, Time, Status
                    FROM Reminders
                    WHERE UserID = ? AND Status = 'Pending'
                        AND DATEADD(SECOND, DATEDIFF(SECOND, 0, [Time]), CAST([Date] AS DATETIME)) > ?
                    ORDER BY [Date], [Time]
                """, (request.session['user_id'], now))
                rem_raw = cursor.fetchall()
                reminders = rows_to_dicts(cursor, rem_raw)
                for r in reminders:
                    for k in list(r.keys()):
                        r[k.lower()] = r.pop(k)
            except Exception as e:
                logger.exception("Reminder query failed")
                messages.error(request, "Failed to load reminders")
                reminders = []

            # Goals
            cursor.execute("""
                SELECT goal_id, UserID, goal_type, target_value,
                       current_value, start_date, end_date
                FROM Goals
                WHERE UserID = ?
                ORDER BY end_date DESC
            """, (request.session['user_id'],))
            raw_goals = cursor.fetchall()
            goals = rows_to_dicts(cursor, raw_goals)
            for g in goals:
                for k in list(g.keys()):
                    g[k.lower()] = g.pop(k)
                try:
                    target = float(g.get('target_value') or 0)
                    current = float(g.get('current_value') or 0)
                    g['progress'] = min(round((current / target) * 100), 100) if target > 0 else 0
                except Exception:
                    g['progress'] = 0

            # Chart data (last 7 rows)
            cursor.execute("""
                SELECT Date, 
                       SUM(Calories) AS total_calories,
                       SUM(Duration) AS total_duration
                FROM HealthData
                WHERE UserID = ?
                GROUP BY Date
                ORDER BY Date DESC
                OFFSET 0 ROWS FETCH NEXT 7 ROWS ONLY
            """, (request.session['user_id'],))
            chart_data = cursor.fetchall()

            labels = [
                row[0].strftime('%Y-%m-%d') if hasattr(row[0], 'strftime') else str(row[0])
                for row in chart_data
            ]
            calories_data = [row[1] or 0 for row in chart_data]
            duration_data = [row[2] or 0 for row in chart_data]

    except Exception as e:
        logger.exception("Dashboard load failed")
        messages.error(request, 'Error loading dashboard. Please try again.')
        health_data = []
        medical_records = []
        reminders = []
        goals = []
        labels = []
        calories_data = []
        duration_data = []

    return render(request, 'dashboard.html', {
        'health_data': health_data,
        'medical_records': medical_records,
        'reminders': reminders,
        'goals': goals,
        'labels': labels,
        'calories_data': calories_data,
        'duration_data': duration_data,
        'current_date': datetime.now().strftime('%B %d, %Y')
    })


# -------------------------
# Profile & password
# -------------------------
@login_required
def profile(request):
    try:
        with db_cursor() as cursor:
            cursor.execute('SELECT * FROM Users WHERE UserID = ?', (request.session['user_id'],))
            row = cursor.fetchone()
            if row:
                user = dict(zip([c[0] for c in cursor.description], row))
                # lower keys for template parity
                user = {k.lower(): v for k, v in user.items()}
                return render(request, 'profile.html', {'user': user})
            else:
                messages.error(request, 'User not found')
                return redirect('dashboard')
    except Exception as e:
        logger.exception("Error fetching profile")
        messages.error(request, 'Error loading profile')
        return redirect('dashboard')


@login_required
@require_http_methods(["POST"])
def update_profile(request):
    name = request.POST.get('name', '').strip()
    email = request.POST.get('email', '').strip()
    try:
        with db_cursor() as cursor:
            cursor.execute('''
                UPDATE Users 
                SET Name = ?, Email = ?
                WHERE UserID = ?
            ''', (name, email, request.session['user_id']))
        request.session['name'] = name
        request.session['email'] = email
        messages.success(request, 'Profile updated successfully!')
    except Exception as e:
        logger.exception("Error updating profile")
        messages.error(request, 'Error updating profile')
    return redirect('profile')


@login_required
@require_http_methods(["GET", "POST"])
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match')
            return redirect('change_password')

        # re-use same password validation
        def validate_password(password):
            import re
            if len(password) < 8: return False
            if not re.search("[a-z]", password): return False
            if not re.search("[A-Z]", password): return False
            if not re.search("[0-9]", password): return False
            if not re.search("[!@#$%^&*()]", password): return False
            return True

        if not validate_password(new_password):
            messages.error(request, 'Password must be at least 8 characters with uppercase, lowercase, number and special character')
            return redirect('change_password')

        try:
            with db_cursor() as cursor:
                cursor.execute('SELECT Password FROM Users WHERE UserID = ?', (request.session['user_id'],))
                row = cursor.fetchone()
                if row:
                    db_password = row[0]
                    if check_password_hash(db_password, current_password):
                        hashed_password = generate_password_hash(new_password)
                        cursor.execute('UPDATE Users SET Password = ? WHERE UserID = ?', (hashed_password, request.session['user_id']))
                        messages.success(request, 'Password changed successfully!')
                        return redirect('profile')
                    else:
                        messages.error(request, 'Current password is incorrect')
                else:
                    messages.error(request, 'User not found')
        except Exception as e:
            logger.exception("Error changing password")
            messages.error(request, 'Error changing password')

    return render(request, 'change_password.html')


# -------------------------
# Password reset / forgot
# -------------------------
@require_http_methods(["GET", "POST"])
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            with db_cursor() as cursor:
                cursor.execute('SELECT UserID, Name FROM Users WHERE Email = ?', (email,))
                row = cursor.fetchone()
                if row:
                    user_id, name = row
                    token = generate_password_hash(f"{user_id}{datetime.now()}")
                    expires = datetime.now() + timedelta(hours=1)
                    cursor.execute('''
                        INSERT INTO PasswordResetTokens (UserID, Token, ExpiresAt)
                        VALUES (?, ?, ?)
                    ''', (user_id, token, expires))
                    send_password_reset_email(email, name, token)
                    messages.success(request, 'Password reset link sent to your email')
                    return redirect('login')
                else:
                    messages.error(request, 'Email not found')
        except Exception as e:
            logger.exception("Error processing forgot password")
            messages.error(request, 'Error processing request')

    return render(request, 'forgot_password.html')


@require_http_methods(["GET", "POST"])
def reset_password(request, token):
    try:
        with db_cursor() as cursor:
            cursor.execute('''
                SELECT UserID FROM PasswordResetTokens 
                WHERE Token = ? AND ExpiresAt > ?
            ''', (token, datetime.now()))
            row = cursor.fetchone()
            if not row:
                messages.error(request, 'Invalid or expired token')
                return redirect('login')

            user_id = row[0]

            if request.method == 'POST':
                new_password = request.POST.get('new_password')
                confirm_password = request.POST.get('confirm_password')
                if new_password != confirm_password:
                    messages.error(request, 'Passwords do not match')
                    return render(request, 'reset_password.html', {'token': token})
                # validate
                def validate_password(p):
                    import re
                    if len(p) < 8: return False
                    if not re.search("[a-z]", p): return False
                    if not re.search("[A-Z]", p): return False
                    if not re.search("[0-9]", p): return False
                    if not re.search("[!@#$%^&*()]", p): return False
                    return True
                if not validate_password(new_password):
                    messages.error(request, 'Password must be at least 8 characters with uppercase, lowercase, number and special character')
                    return render(request, 'reset_password.html', {'token': token})
                hashed = generate_password_hash(new_password)
                cursor.execute('UPDATE Users SET Password = ? WHERE UserID = ?', (hashed, user_id))
                cursor.execute('DELETE FROM PasswordResetTokens WHERE Token = ?', (token,))
                messages.success(request, 'Password reset successfully! Please log in.')
                return redirect('login')

            return render(request, 'reset_password.html', {'token': token})
    except Exception as e:
        logger.exception("Error resetting password")
        messages.error(request, 'Error resetting password')
        return redirect('login')


# -------------------------
# Email verification
# -------------------------
def verify_email(request, token):
    try:
        with db_cursor() as cursor:
            cursor.execute('''
                SELECT UserID FROM EmailVerificationTokens 
                WHERE Token = ? AND ExpiresAt > ?
            ''', (token, datetime.now()))
            row = cursor.fetchone()
            if row:
                user_id = row[0]
                cursor.execute('UPDATE Users SET Verified = 1 WHERE UserID = ?', (user_id,))
                cursor.execute('DELETE FROM EmailVerificationTokens WHERE Token = ?', (token,))
                messages.success(request, 'Email verified successfully! Please log in.')
            else:
                messages.error(request, 'Invalid or expired verification link')
    except Exception as e:
        logger.exception("Error verifying email")
        messages.error(request, 'Error verifying email')

    return redirect('login')


# -------------------------
# Global search
# -------------------------
@login_required
def global_search(request):
    query = request.GET.get('q', '').strip()
    if not query:
        messages.warning(request, "Please enter a search term")
        return redirect('dashboard')

    try:
        user_id = request.session['user_id']
        like_query = f"%{query}%"
        results = {}

        with db_cursor() as cursor:
            # HealthData
            cursor.execute('''
                SELECT * FROM HealthData
                WHERE UserID = ? AND (Description LIKE ? OR Category LIKE ? OR Type LIKE ?)
            ''', (user_id, like_query, like_query, like_query))
            results['Health Data'] = rows_to_dicts(cursor, cursor.fetchall())

            # Reminders
            cursor.execute('''
                SELECT * FROM Reminders
                WHERE UserID = ? AND (Description LIKE ? OR Type LIKE ? OR Status LIKE ?)
            ''', (user_id, like_query, like_query, like_query))
            results['Reminders'] = rows_to_dicts(cursor, cursor.fetchall())

            # Goals
            cursor.execute('''
                SELECT * FROM Goals
                WHERE UserID = ? AND (goal_type LIKE ?)
            ''', (user_id, like_query))
            results['Goals'] = rows_to_dicts(cursor, cursor.fetchall())

            # Medical Records
            cursor.execute('''
                SELECT * FROM MedicalRecords
                WHERE UserID = ? AND (title LIKE ? OR description LIKE ?)
            ''', (user_id, like_query, like_query))
            results['Medical Records'] = rows_to_dicts(cursor, cursor.fetchall())

            # Activity Logs
            cursor.execute('''
                SELECT * FROM ActivityLogs
                WHERE UserID = ? AND (activity_type LIKE ? OR description LIKE ?)
            ''', (user_id, like_query, like_query))
            results['Activity Logs'] = rows_to_dicts(cursor, cursor.fetchall())

        return render(request, 'global_search.html', {'query': query, 'results': results})

    except Exception as e:
        logger.exception("Global search failed")
        messages.error(request, "Search failed. Please try again.")
        return redirect('dashboard')


# -------------------------
# Health logging
# -------------------------
@login_required
@require_http_methods(["GET", "POST"])
def log_health_data(request,type):
    if request.method == 'POST':
        try:
            entry_date_str = request.POST.get('date', '')
            entry_date = datetime.strptime(entry_date_str, '%Y-%m-%d') if entry_date_str else datetime.now()

            def to_int(value, default=0):
                try:
                    return int(value)
                except (ValueError, TypeError):
                    return default

            entry_type = request.POST.get('type', '').strip()
            category = request.POST.get('category', '').strip()
            schedule = request.POST.get('schedule', '').strip()
            description = request.POST.get('description', '').strip()
            calories = to_int(request.POST.get('calories', 0))
            duration = to_int(request.POST.get('duration', 0))
            user_id = request.session.get('user_id')

            if not entry_type or not category or not description:
                messages.error(request, 'Type, category, and description are required.')
                return redirect('log_health')

            with db_cursor() as cursor:
                cursor.execute('''
                    INSERT INTO HealthData 
                    (UserID, Date, Type, Category, Schedule, Description, Calories, Duration)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (user_id, entry_date, entry_type, category, schedule, description, calories, duration))

                cursor.execute('''
                    INSERT INTO ActivityLogs 
                    (UserID, activity_type, description, timestamp)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, 'Health Entry', f"{entry_type} - {description}", datetime.now()))

            messages.success(request, 'Health entry added successfully!')
            return redirect('dashboard')
        except Exception as e:
            logger.exception("Database error while logging health")
            messages.error(request, 'Failed to log health data. Please try again.')

    return render(request, 'log_health_data.html', {'type': type})


# -------------------------
# Reminders
# -------------------------
@login_required
@require_http_methods(["GET", "POST"])
def add_reminder(request):
    if request.method == 'POST':
        try:
            reminder_type = request.POST.get('type')
            reminder_expiry = request.POST.get('expiry')
            reminder_date_str = request.POST.get('date')
            reminder_time_str = request.POST.get('time')
            description = request.POST.get('description', '').strip()

            if not all([reminder_type, reminder_date_str, reminder_time_str]):
                messages.error(request, 'All fields are required')
                return redirect('add_reminder')

            reminder_date = datetime.strptime(reminder_date_str, '%Y-%m-%d').date()
            reminder_time = datetime.strptime(reminder_time_str, '%H:%M').time()

            with db_cursor() as cursor:
                cursor.execute('''
                    INSERT INTO Reminders 
                    (UserID, Type, Date, Time, Status, Description, expiry)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (request.session['user_id'], reminder_type, reminder_date, reminder_time, 'Pending', description, reminder_expiry))

            messages.success(request, 'Reminder added successfully!')
            return redirect('dashboard')
        except Exception as e:
            logger.exception("Error adding reminder")
            messages.error(request, 'Failed to add reminder. Please try again.')

    return render(request, 'add_reminder.html')

# views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from .models import HealthRecord
import json

@login_required
def health_trends(request):
    """
    View for displaying health trends and analytics
    """
    # Get date range from query parameters (default: last 30 days)
    date_range = request.GET.get('range', '30days')
    
    # Calculate date range
    end_date = timezone.now().date()
    
    if date_range == '7days':
        start_date = end_date - timedelta(days=7)
        period_text = "Last 7 Days"
    elif date_range == '90days':
        start_date = end_date - timedelta(days=90)
        period_text = "Last 90 Days"
    elif date_range == '1year':
        start_date = end_date - timedelta(days=365)
        period_text = "Last Year"
    else:  # 30 days default
        start_date = end_date - timedelta(days=30)
        period_text = "Last 30 Days"
    
    # Get user's health records
    records = HealthRecord.objects.filter(
        user=request.user,
        date__gte=start_date,
        date__lte=end_date
    ).order_by('date')
    
    # Prepare chart data
    chart_data = prepare_chart_data(records)
    
    # Calculate statistics
    stats = calculate_statistics(records)
    
    # Get recent records for table
    recent_records = HealthRecord.objects.filter(
        user=request.user
    ).order_by('-date')[:10]
    
    context = {
        'records': records,
        'chart_data': chart_data,
        'stats': stats,
        'recent_records': recent_records,
        'date_range': date_range,
        'period_text': period_text,
        'start_date': start_date,
        'end_date': end_date,
    }
    
    return render(request, 'trend.html', context)
# views.py
from django.shortcuts import render

def privacy_policy(request):
    return render(request, 'privacy.html')

def terms_of_service(request):
    return render(request, 'terms.html')

def contact_us(request):
    return render(request, 'contact.html')

def support_center(request):
    return render(request, 'support.html')

def prepare_chart_data(records):
    """
    Prepare data for Chart.js charts
    """
    dates = [record.date.strftime('%b %d') for record in records]
    weights = [float(record.weight) if record.weight else None for record in records]
    calories = [int(record.calories) if record.calories else None for record in records]
    steps = [int(record.steps) if record.steps else None for record in records]
    
    # Prepare data structure for template
    chart_data = {
        'labels': json.dumps(dates),
        'weight_data': json.dumps(weights),
        'calories_data': json.dumps(calories),
        'steps_data': json.dumps(steps),
    }
    
    return chart_data


def calculate_statistics(records):
    """
    Calculate statistics from health records
    """
    if not records:
        return {
            'avg_weight': 0,
            'avg_calories': 0,
            'avg_steps': 0,
            'weight_change': 0,
            'calories_change': 0,
            'steps_change': 0,
            'trend_score': 0,
        }
    
    # Calculate averages
    valid_weights = [r.weight for r in records if r.weight]
    valid_calories = [r.calories for r in records if r.calories]
    valid_steps = [r.steps for r in records if r.steps]
    
    avg_weight = sum(valid_weights) / len(valid_weights) if valid_weights else 0
    avg_calories = sum(valid_calories) / len(valid_calories) if valid_calories else 0
    avg_steps = sum(valid_steps) / len(valid_steps) if valid_steps else 0
    
    # Calculate trends (compare first and last record)
    if len(records) >= 2:
        first = records.first()
        last = records.last()
        
        weight_change = ((last.weight or 0) - (first.weight or 0)) if (first.weight and last.weight) else 0
        calories_change = ((last.calories or 0) - (first.calories or 0)) if (first.calories and last.calories) else 0
        steps_change = ((last.steps or 0) - (first.steps or 0)) if (first.steps and last.steps) else 0
    else:
        weight_change = 0
        calories_change = 0
        steps_change = 0
    
    # Calculate trend score (0-100)
    trend_score = calculate_trend_score(records)
    
    return {
        'avg_weight': round(avg_weight, 1),
        'avg_calories': round(avg_calories),
        'avg_steps': round(avg_steps),
        'weight_change': round(weight_change, 1),
        'calories_change': round(calories_change),
        'steps_change': round(steps_change),
        'trend_score': trend_score,
        'total_records': records.count(),
    }


def calculate_trend_score(records):
    """
    Calculate an overall health trend score (0-100)
    """
    if not records or len(records) < 2:
        return 50  # Neutral score
    
    score = 50  # Start at neutral
    
    # Weight trend (losing weight is positive for most people)
    weight_changes = []
    for i in range(1, len(records)):
        if records[i].weight and records[i-1].weight:
            change = records[i-1].weight - records[i].weight  # Negative if gaining
            weight_changes.append(change)
    
    if weight_changes:
        avg_weight_change = sum(weight_changes) / len(weight_changes)
        # Lose 0.5kg per week is optimal = +20 points
        score += min(20, max(-20, avg_weight_change * 10))
    
    # Steps trend (more steps is positive)
    step_changes = []
    for i in range(1, len(records)):
        if records[i].steps and records[i-1].steps:
            change = records[i].steps - records[i-1].steps
            step_changes.append(change)
    
    if step_changes:
        avg_step_change = sum(step_changes) / len(step_changes)
        # Gain 500 steps per day is good = +15 points
        score += min(15, max(-15, avg_step_change / 33.3))
    
    # Calories trend (consistent is positive)
    calorie_values = [r.calories for r in records if r.calories]
    if len(calorie_values) >= 3:
        # Calculate consistency (lower variance is better)
        mean_calories = sum(calorie_values) / len(calorie_values)
        variance = sum((x - mean_calories) ** 2 for x in calorie_values) / len(calorie_values)
        std_dev = variance ** 0.5
        
        # Less than 200 calorie variance is good
        if std_dev < 200:
            score += 10
        elif std_dev > 500:
            score -= 10
    
    # Ensure score is between 0-100
    return max(0, min(100, round(score)))


@login_required
def add_health_record(request):
    """
    View for adding a new health record
    """
    if request.method == 'POST':
        try:
            # Get form data
            weight = request.POST.get('weight')
            calories = request.POST.get('calories')
            steps = request.POST.get('steps')
            sleep_hours = request.POST.get('sleep_hours')
            water_intake = request.POST.get('water_intake')
            date = request.POST.get('date') or timezone.now().date()
            
            # Create new record
            HealthRecord.objects.create(
                user=request.user,
                date=date,
                weight=float(weight) if weight else None,
                calories=int(calories) if calories else None,
                steps=int(steps) if steps else None,
                sleep_hours=float(sleep_hours) if sleep_hours else None,
                water_intake=int(water_intake) if water_intake else None,
            )
            
            messages.success(request, 'Health record added successfully!')
            return redirect('health_trends')
            
        except Exception as e:
            messages.error(request, f'Error adding record: {str(e)}')
    
    return render(request, 'add_health_record.html')


@login_required
def delete_health_record(request, record_id):
    """
    View for deleting a health record
    """
    try:
        record = HealthRecord.objects.get(id=record_id, user=request.user)
        record.delete()
        messages.success(request, 'Health record deleted successfully!')
    except HealthRecord.DoesNotExist:
        messages.error(request, 'Record not found!')
    except Exception as e:
        messages.error(request, f'Error deleting record: {str(e)}')
    
    return redirect('health_trends')


@login_required
def export_health_data(request):
    """
    View for exporting health data
    """
    format_type = request.GET.get('format', 'csv')
    date_range = request.GET.get('range', '30days')
    
    # Get records based on date range
    end_date = timezone.now().date()
    
    if date_range == '7days':
        start_date = end_date - timedelta(days=7)
    elif date_range == '90days':
        start_date = end_date - timedelta(days=90)
    elif date_range == '1year':
        start_date = end_date - timedelta(days=365)
    else:
        start_date = end_date - timedelta(days=30)
    
    records = HealthRecord.objects.filter(
        user=request.user,
        date__gte=start_date,
        date__lte=end_date
    ).order_by('date')
    
    if format_type == 'csv':
        # Generate CSV response
        import csv
        from django.http import HttpResponse
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="health_data_{start_date}_to_{end_date}.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Date', 'Weight (kg)', 'Calories', 'Steps', 'Sleep (hours)', 'Water Intake (ml)'])
        
        for record in records:
            writer.writerow([
                record.date,
                record.weight or '',
                record.calories or '',
                record.steps or '',
                record.sleep_hours or '',
                record.water_intake or ''
            ])
        
        return response
    
    elif format_type == 'json':
        # Generate JSON response
        from django.http import JsonResponse
        
        data = []
        for record in records:
            data.append({
                'date': record.date.isoformat(),
                'weight': record.weight,
                'calories': record.calories,
                'steps': record.steps,
                'sleep_hours': record.sleep_hours,
                'water_intake': record.water_intake,
            })
        
        return JsonResponse({'records': data})
    
    messages.error(request, 'Invalid export format')
    return redirect('health_trends')

@login_required
@require_http_methods(["GET", "POST"])
def edit_reminder(request, id):
    try:
        with db_cursor() as cursor:
            if request.method == 'GET':
                cursor.execute("""
                    SELECT ReminderID, Type, Description, Date, Time, Status
                    FROM Reminders
                    WHERE ReminderID = ? AND UserID = ?
                """, (id, request.session['user_id']))
                row = cursor.fetchone()
                if not row:
                    messages.error(request, "Reminder not found")
                    return redirect('dashboard')
                reminder = dict(zip([c[0].lower() for c in cursor.description], row))
                return render(request, 'edit_reminder.html', {'reminder': reminder})

            # POST: update
            reminder_type = request.POST.get('type')
            description = request.POST.get('description')
            date_str = request.POST.get('date')
            time_str = request.POST.get('time')

            if not all([reminder_type, description, date_str, time_str]):
                messages.error(request, "All fields are required")
                return redirect(request.path)

            date = datetime.strptime(date_str, "%Y-%m-%d").date()
            time = datetime.strptime(time_str, "%H:%M").time()

            cursor.execute("""
                UPDATE Reminders
                SET Type = ?, Description = ?, Date = ?, Time = ?
                WHERE ReminderID = ? AND UserID = ?
            """, (reminder_type, description, date, time, id, request.session['user_id']))

            messages.success(request, "Reminder updated successfully!")
            return redirect('dashboard')
    except Exception as e:
        logger.exception("Failed to edit reminder")
        messages.error(request, "Error updating reminder")
        return redirect('dashboard')


@login_required
def all_reminders(request):
    try:
        with db_cursor() as cursor:
            cursor.execute("""
                SELECT ReminderID, UserID, Type, Description, Date, Time, Status
                FROM Reminders
                WHERE UserID = ?
                ORDER BY Date DESC, Time DESC
            """, (request.session['user_id'],))
            rems = cursor.fetchall()
            reminders = []
            cols = [c[0].lower() for c in cursor.description]
            for r in rems:
                reminders.append(dict(zip(cols, r)))
    except Exception as e:
        logger.exception("Failed to load all reminders")
        messages.error(request, "Unable to load reminders.")
        return redirect('dashboard')

    return render(request, 'all_reminders.html', {'reminders': reminders})


@login_required
@require_http_methods(["POST"])
def complete_reminder(request, reminder_id):
    try:
        with db_cursor() as cursor:
            cursor.execute('''
                UPDATE Reminders 
                SET Status = 'Completed' 
                WHERE ReminderID = ? AND UserID = ?
            ''', (reminder_id, request.session['user_id']))

            cursor.execute('''
                INSERT INTO ActivityLogs 
                (UserID, activity_type, description, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (request.session['user_id'], 'Reminder Completed', f"Completed reminder ID: {reminder_id}", datetime.now()))

        messages.success(request, 'Reminder marked as completed.')
    except Exception as e:
        logger.exception("Failed to complete reminder")
        messages.error(request, 'Failed to complete reminder.')

    return redirect('dashboard')


# -------------------------
# Goals
# -------------------------
@login_required
@require_http_methods(["GET", "POST"])
def goals_view(request):
    user_id = request.session.get('user_id')
    goals = []
    try:
        if request.method == 'POST':
            goal_type = request.POST.get('goal_type')
            target_value = request.POST.get('target_value')
            current_value = request.POST.get('current_value')
            start_date = request.POST.get('start_date')
            end_date = request.POST.get('end_date')

            if not goal_type or not target_value or not start_date or not end_date:
                messages.error(request, "All fields except current value are required.")
                return redirect('goals')

            try:
                target_value = float(target_value)
                current_value = float(current_value or 0)
            except ValueError:
                messages.error(request, "Target and current values must be numbers.")
                return redirect('goals')

            with db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO Goals (UserID, goal_type, target_value, current_value, start_date, end_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (user_id, goal_type, target_value, current_value, start_date, end_date))

            messages.success(request, "Goal added successfully!")
            return redirect('goals')

        # GET
        with db_cursor() as cursor:
            cursor.execute("SELECT * FROM Goals WHERE UserID = ? ORDER BY end_date DESC", (user_id,))
            raw_goals = cursor.fetchall()
            cols = [c[0].lower() for c in cursor.description]
            goals = [dict(zip(cols, r)) for r in raw_goals]

        for goal in goals:
            try:
                target = float(goal.get('target_value') or 0)
                current = float(goal.get('current_value') or 0)
                goal['progress'] = min(round((current / target) * 100), 100) if target > 0 else 0
            except Exception:
                goal['progress'] = 0
    except Exception as e:
        logger.exception("GOALS ERROR")
        messages.error(request, "Something went wrong while processing goals.")

    return render(request, 'goals.html', {'goals': goals})


@login_required
def view_goals(request):
    try:
        with db_cursor() as cursor:
            cursor.execute("""
                SELECT goal_id, goal_type, target_value, current_value, start_date, end_date
                FROM Goals
                WHERE UserID = ?
                ORDER BY end_date DESC
            """, (request.session['user_id'],))
            raw = cursor.fetchall()
            cols = [c[0].lower() for c in cursor.description]
            goals = [dict(zip(cols, r)) for r in raw]

        for goal in goals:
            try:
                target = float(goal.get('target_value') or 0)
                current = float(goal.get('current_value') or 0)
                goal['progress'] = min(round((current / target) * 100), 100) if target > 0 else 0
            except Exception:
                goal['progress'] = 0
    except Exception as e:
        logger.exception("Failed to load goals")
        messages.error(request, 'Unable to load goals')
        goals = []

    return render(request, 'view_goals.html', {'goals': goals})


@login_required
@require_http_methods(["GET", "POST"])
def update_goal(request, goal_id):
    try:
        with db_cursor() as cursor:
            cursor.execute('SELECT * FROM Goals WHERE goal_id = ? AND UserID = ?', (goal_id, request.session['user_id']))
            goal_row = cursor.fetchone()
            if not goal_row:
                messages.error(request, 'Goal not found.')
                return redirect('goals')
            cols = [c[0].lower() for c in cursor.description]
            goal = dict(zip(cols, goal_row))

            if request.method == 'POST':
                goal_type = request.POST.get('goal_type')
                target_value = float(request.POST.get('target_value'))
                current_value = float(request.POST.get('current_value'))
                start_date = request.POST.get('start_date')
                end_date = request.POST.get('end_date')
                goal_name = request.POST.get('goal_name')

                cursor.execute('''
                    UPDATE Goals 
                    SET goal_type = ?, target_value = ?, current_value = ?, 
                        start_date = ?, end_date = ?, goal_name = ?
                    WHERE goal_id = ? AND UserID = ?
                ''', (goal_type, target_value, current_value, start_date, end_date, goal_name, goal_id, request.session['user_id']))

                cursor.execute('''
                    INSERT INTO ActivityLogs (UserID, activity_type, timestamp, description)
                    VALUES (?, ?, ?, ?)
                ''', (request.session['user_id'], 'Goal Updated', datetime.now(), f"Updated goal: {goal_name} ({goal_type})"))

                messages.success(request, 'Goal updated successfully!')
                return redirect('goals')

            return render(request, 'update_goal.html', {'goal': goal})
    except Exception as e:
        logger.exception("Error updating goal")
        messages.error(request, 'An error occurred while updating the goal.')
        return redirect('goals')


@login_required
@require_http_methods(["GET", "POST"])
def edit_goal(request, goal_id):
    try:
        with db_cursor() as cursor:
            if request.method == 'POST':
                goal_name = request.POST.get('goal_name')
                goal_type = request.POST.get('goal_type')
                target_value = request.POST.get('target_value')
                current_value = request.POST.get('current_value')
                start_date = request.POST.get('start_date')
                end_date = request.POST.get('end_date')

                cursor.execute("""
                    UPDATE Goals
                    SET goal_name = ?, goal_type = ?, target_value = ?, current_value = ?, start_date = ?, end_date = ?
                    WHERE goal_id = ? AND UserID = ?
                """, (goal_name, goal_type, target_value, current_value, start_date, end_date, goal_id, request.session['user_id']))

                messages.success(request, "Goal updated successfully!")
                return redirect('view_goals')
            else:
                cursor.execute("""
                    SELECT goal_id, UserID, goal_type, target_value, current_value, start_date, end_date, goal_name
                    FROM Goals
                    WHERE goal_id = ? AND UserID = ?
                """, (goal_id, request.session['user_id']))
                row = cursor.fetchone()
                if not row:
                    messages.error(request, "Goal not found.")
                    return redirect('view_goals')
                cols = [c[0] for c in cursor.description]
                goal_data = dict(zip(cols, row))
                return render(request, 'edit_goal.html', {'goal': goal_data})
    except Exception as e:
        logger.exception("Failed to edit goal")
        messages.error(request, "Something went wrong while editing the goal.")
        return redirect('view_goals')


# -------------------------
# Medical Records (uploads, view, download, delete, export)
# -------------------------
@login_required
@require_http_methods(["GET", "POST"])
def upload_record(request):
    if request.method == 'POST' and request.FILES.get('file'):
        file = request.FILES['file']

        if file.name == '':
            messages.error(request, 'No file selected')
            return redirect(request.path)

        if not allowed_file(file.name):
            messages.error(request, 'Invalid file type. Allowed: PDF, DOCX, TXT, JPG, PNG.')
            return redirect(request.path)

        try:
            filename = secure_filename(file.name)
            save_path = os.path.join(UPLOAD_FOLDER, filename)

            # save uploaded file
            with open(save_path, 'wb+') as dest:
                for chunk in file.chunks():
                    dest.write(chunk)

            record_date = datetime.strptime(request.POST.get('record_date'), '%Y-%m-%d').date()

            with db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO MedicalRecords (UserID, title, description, file_path, record_date)
                    VALUES (?, ?, ?, ?, ?)
                """, (request.session['user_id'], request.POST.get('title'), request.POST.get('description'), save_path, record_date))

                cursor.execute("""
                    INSERT INTO ActivityLogs (UserID, activity_type, description, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (request.session['user_id'], 'Record Uploaded', f"Uploaded record: {request.POST.get('title')}", datetime.now()))

            messages.success(request, 'Medical record uploaded successfully.')
            return redirect('view_records')
        except Exception as e:
            logger.exception("Upload failed")
            # attempt cleanup
            try:
                if os.path.exists(save_path):
                    os.remove(save_path)
            except Exception:
                pass
            messages.error(request, 'Upload failed. Try again.')

    return render(request, 'upload_record.html')


@login_required
def view_records(request):
    try:
        with db_cursor() as cursor:
            cursor.execute("""
                SELECT record_id, title, description, record_date, file_path 
                FROM MedicalRecords 
                WHERE UserID = ?
                ORDER BY record_date DESC
            """, (request.session['user_id'],))
            rows = cursor.fetchall()
            records = []
            for r in rows:
                records.append({
                    "record_id": r[0],
                    "title": r[1],
                    "description": r[2],
                    "record_date": r[3],
                    "file_path": r[4]
                })
    except Exception as e:
        logger.exception("Failed to fetch records")
        messages.error(request, 'Could not load medical records.')
        records = []

    return render(request, 'view_records.html', {'records': records})


@login_required
def download_record(request, record_id):
    try:
        with db_cursor() as cursor:
            cursor.execute("""
                SELECT file_path FROM MedicalRecords 
                WHERE record_id = ? AND UserID = ?
            """, (record_id, request.session['user_id']))
            row = cursor.fetchone()
            if row:
                file_path = row[0]
                if not file_path or not os.path.exists(file_path):
                    messages.error(request, 'Record file not found')
                    return redirect('view_records')
                # Use FileResponse to stream file
                return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=os.path.basename(file_path))
            else:
                messages.error(request, 'Record not found')
    except Exception as e:
        logger.exception("Failed to download record")
        messages.error(request, 'Failed to download record')

    return redirect('view_records')


@login_required
@require_http_methods(["POST"])
def delete_record(request, record_id):
    try:
        with db_cursor() as cursor:
            cursor.execute("SELECT file_path FROM MedicalRecords WHERE record_id = ? AND UserID = ?", (record_id, request.session['user_id']))
            row = cursor.fetchone()
            if row:
                file_path = row[0]
                cursor.execute("DELETE FROM MedicalRecords WHERE record_id = ? AND UserID = ?", (record_id, request.session['user_id']))
                cursor.execute("DELETE FROM Uploads WHERE file_path = ? AND UserID = ?", (file_path, request.session['user_id']))
                cursor.execute("""
                    INSERT INTO ActivityLogs (UserID, activity_type, description, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (request.session['user_id'], 'Record Deleted', f"Deleted medical record ID: {record_id}", datetime.now()))
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
                messages.success(request, 'Record deleted successfully.')
            else:
                messages.error(request, 'Record not found.')
    except Exception as e:
        logger.exception("Failed to delete record")
        messages.error(request, 'Failed to delete record.')

    return redirect('view_records')


@login_required
def export_csv(request):
    user_id = request.session.get('user_id')
    try:
        with db_cursor() as cursor:
            cursor.execute("SELECT title, description, record_date FROM MedicalRecords WHERE UserID = ?", (user_id,))
            records = cursor.fetchall()

        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(['Title', 'Description', 'Date'])
        for row in records:
            writer.writerow(row)
        response = HttpResponse(si.getvalue(), content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=medical_records.csv'
        return response
    except Exception as e:
        logger.exception("Export CSV failed")
        messages.error(request, 'Failed to export CSV')
        return redirect('view_records')


@login_required
def view_uploads(request):
    try:
        with db_cursor() as cursor:
            cursor.execute("""
                SELECT record_id, title, file_path, record_date
                FROM MedicalRecords
                WHERE UserID = ?
                ORDER BY record_date DESC
            """, (request.session['user_id'],))
            rows = cursor.fetchall()
            uploads = [dict(zip([c[0] for c in cursor.description], r)) for r in rows]
    except Exception as e:
        logger.exception("Failed to retrieve uploads")
        uploads = []
        messages.error(request, 'Failed to load uploaded records.')

    return render(request, 'view_uploads.html', {'uploads': uploads})


# -------------------------
# Activity logs
# -------------------------
@login_required
def view_activities(request):
    try:
        with db_cursor() as cursor:
            cursor.execute('''
                SELECT ActivityID, ActivityType, ActivityDate, Description
                FROM ActivityLogs
                WHERE UserID = ?
                ORDER BY ActivityDate DESC
            ''', (request.session['user_id'],))
            rows = cursor.fetchall()
            cols = [c[0] for c in cursor.description]
            activities = [dict(zip(cols, r)) for r in rows]
    except Exception as e:
        logger.exception("Failed to retrieve activities")
        activities = []
        messages.error(request, 'Failed to load activity logs.')

    return render(request, 'view_activities.html', {'activities': activities})


# -------------------------
# Admin panel and admin actions
# -------------------------
@admin_required
def admin_panel(request):
    if request.session.get('role') != 'Admin' and request.session.get('role') != 'admin':
        messages.error(request, "Access denied")
        return redirect('dashboard')

    try:
        with db_cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM Users')
            user_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM ActivityLogs')
            activity_count = cursor.fetchone()[0]

            cursor.execute('''
                SELECT a.activity_id, u.Name, a.activity_type, a.timestamp, a.description
                FROM ActivityLogs a
                JOIN Users u ON a.UserID = u.UserID
                ORDER BY a.timestamp DESC OFFSET 0 ROWS FETCH NEXT 10 ROWS ONLY
            ''')
            recent_activities = rows_to_dicts(cursor, cursor.fetchall())

            cursor.execute('''
                SELECT UserID, Name, Email, Role, CreatedAt
                FROM Users
                ORDER BY CreatedAt DESC OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY
            ''')
            recent_users = rows_to_dicts(cursor, cursor.fetchall())

            cursor.execute('SELECT COUNT(*) FROM MedicalRecords')
            record_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM Reminders')
            reminder_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM Goals')
            goal_count = cursor.fetchone()[0]
    except Exception as e:
        logger.exception("Admin panel error")
        messages.error(request, "Error loading admin panel")
        return redirect('dashboard')

    return render(request, 'admin_panel.html', {
        'user_count': user_count,
        'activity_count': activity_count,
        'recent_activities': recent_activities,
        'recent_users': recent_users,
        'record_count': record_count,
        'reminder_count': reminder_count,
        'goal_count': goal_count,
        'users': recent_users
    })


@admin_required
def admin_users(request):
    try:
        with db_cursor() as cursor:
            cursor.execute('''
                SELECT UserID, Name, Email, Role, CreatedAt
                FROM Users
                ORDER BY CreatedAt DESC
            ''')
            users = rows_to_dicts(cursor, cursor.fetchall())
    except Exception as e:
        logger.exception("Error loading users")
        messages.error(request, 'Error loading users')
        users = []

    return render(request, 'admin_users.html', {'users': users})


@admin_required
def admin_activities(request):
    try:
        with db_cursor() as cursor:
            cursor.execute('''
                SELECT a.activity_id, u.Name, a.activity_type, a.timestamp, a.description
                FROM ActivityLogs a
                JOIN Users u ON a.UserID = u.UserID
                ORDER BY a.timestamp DESC
            ''')
            activities = rows_to_dicts(cursor, cursor.fetchall())
    except Exception as e:
        logger.exception("Error loading activities")
        messages.error(request, 'Error loading activities')
        activities = []

    return render(request, 'admin_activities.html', {'activities': activities})


@admin_required
@require_http_methods(["GET", "POST"])
def system_settings(request):
    if request.method == 'POST':
        site_name = request.POST.get('site_name')
        support_email = request.POST.get('support_email')
        # TODO: persist settings to DB or config table
        messages.success(request, "Settings updated successfully")
        return redirect('system_settings')

    return render(request, 'admin_settings.html')


@admin_required
@require_http_methods(["POST"])
def add_user(request):
    try:
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        role = request.POST.get('role', 'User')

        if not name or not email or not password:
            messages.error(request, "All fields are required.")
            return redirect('admin_users')

        hashed = generate_password_hash(password)
        with db_cursor() as cursor:
            cursor.execute('''
                INSERT INTO Users (Name, Email, Password, Role)
                VALUES (?, ?, ?, ?)
            ''', (name, email, hashed, role))
        messages.success(request, "User added successfully")
    except Exception as e:
        logger.exception("Failed to add user")
        messages.error(request, "Failed to add user")

    return redirect('admin_users')


@admin_required
def make_admin(request, user_id):
    try:
        with db_cursor() as cursor:
            cursor.execute("UPDATE Users SET Role = 'Admin' WHERE UserID = ?", (user_id,))
        messages.success(request, "User promoted to admin")
    except Exception as e:
        logger.exception("Failed to promote user")
        messages.error(request, "Error promoting user")
    return redirect('admin_users')


@admin_required
def remove_admin(request, user_id):
    try:
        with db_cursor() as cursor:
            cursor.execute("UPDATE Users SET Role = 'User' WHERE UserID = ?", (user_id,))
        messages.success(request, "Admin privileges removed")
    except Exception as e:
        logger.exception("Failed to demote user")
        messages.error(request, "Error removing admin rights")
    return redirect('admin_users')


@admin_required
@require_http_methods(["POST"])
def delete_user(request, user_id):
    try:
        with db_cursor() as cursor:
            cursor.execute('DELETE FROM Users WHERE UserID = ?', (user_id,))
        messages.success(request, "User deleted successfully")
    except Exception as e:
        logger.exception("Failed to delete user")
        messages.error(request, "Failed to delete user")
    return redirect('admin_users')


# -------------------------
# Email helpers (basic conversion to Django mail)
# -------------------------
def send_verification_email(email, name):
    try:
        from django.core.mail import EmailMessage
        token = generate_password_hash(f"{email}{datetime.now()}")
        expires_at = datetime.now() + timedelta(hours=24)
        with db_cursor() as cursor:
            cursor.execute('''
                INSERT INTO EmailVerificationTokens (Email, Token, ExpiresAt)
                VALUES (?, ?, ?)
            ''', (email, token, expires_at))

        # build message
        link = request_build_absolute_url('verify_email', args=(token,))
        body = f"""Hello {name},

Please verify your Wellness360 account by clicking this link:
{link}

This link will expire in 24 hours.

If you didn't create an account, please ignore this email.

The Wellness360 Team"""
        msg = EmailMessage("Verify Your Wellness360 Account", body, getattr(settings, 'EMAIL_HOST_USER', None), [email])
        msg.send(fail_silently=True)
    except Exception as e:
        logger.exception("Error sending verification email")


def send_password_reset_email(email, name, token):
    try:
        from django.core.mail import EmailMessage
        link = request_build_absolute_url('reset_password', args=(token,))
        body = f"""Hello {name},

You requested a password reset for your Wellness360 account. 
Click this link to reset your password:
{link}

This link will expire in 1 hour.

If you didn't request this, please ignore this email.

The Wellness360 Team"""
        msg = EmailMessage("Password Reset Request", body, getattr(settings, 'EMAIL_HOST_USER', None), [email])
        msg.send(fail_silently=True)
    except Exception as e:
        logger.exception("Error sending password reset email")


def send_reminder_email(reminder):
    try:
        from django.core.mail import EmailMessage
        recipient = request.session.get('email')
        subject = "Reminder: " + str(reminder.get('ReminderType', 'Reminder'))
        body = f"""Reminder: {reminder.get('ReminderType')}
Time: {reminder.get('ReminderDate')} {reminder.get('ReminderTime')}

Description: {reminder.get('Description', 'No description provided')}

The Wellness360 Team"""
        msg = EmailMessage(subject, body, getattr(settings, 'EMAIL_HOST_USER', None), [recipient])
        msg.send(fail_silently=True)
    except Exception as e:
        logger.exception("Failed to send reminder email")


# Utility to build absolute URL (since we don't have Flask url_for)
def request_build_absolute_url(viewname, args=(), kwargs=None):
    """
    Helper to create absolute URLs for email links.
    Will use settings.SITE_DOMAIN if provided, otherwise builds relative path.
    """
    try:
        path = reverse(viewname, args=args, kwargs=kwargs)
        domain = getattr(settings, 'SITE_DOMAIN', None)
        if domain:
            # ensure domain has scheme
            if not domain.startswith('http'):
                domain = 'https://' + domain
            return domain.rstrip('/') + path
        # fallback to relative path (useful in dev)
        return path
    except Exception:
        return reverse(viewname, args=args, kwargs=kwargs)
    
    
def logout(request):
    auth_logout(request)
    return redirect('home')
