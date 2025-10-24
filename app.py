from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf, validate_csrf
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta, UTC
from sqlalchemy import or_
import json
from dotenv import load_dotenv
from urllib.parse import quote_plus, urlparse, urlunparse, quote, unquote
from secrets import token_hex
from jinja2 import TemplateNotFound, ChoiceLoader, FileSystemLoader

# Load environment variables
load_dotenv()

# Import database models and utilities
from database.models import db, User, NGO, Volunteer, Donor, Event, TimeSlot, Booking, Message, Resource, Project, Donation, AdminAuditLog, AdminRole, AdminUserRole
from database.queries import init_queries
from admin_decorators import (
    admin_required, admin_permission_required, log_admin_action, get_admin_permissions,
    generate_csrf_token, validate_csrf_token, rate_limit_admin_requests, validate_admin_input
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
# Ensure Flask-WTF accepts CSRF tokens via headers for AJAX
app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken', 'X-CSRF-Token']
# Development convenience: disable static caching and auto-reload templates
if os.environ.get('FLASK_ENV', '').lower() != 'production':
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    app.config['TEMPLATES_AUTO_RELOAD'] = True

# Allow resolving templates from both 'templates/' (new) and 'templates_old/' (legacy)
try:
    app.jinja_loader = ChoiceLoader([
        app.jinja_loader,
        FileSystemLoader('templates_old')
    ])
except Exception:
    pass
"""
Database configuration
Order of precedence:
- DATABASE_URL
- SQLALCHEMY_DATABASE_URI
- Construct MySQL URL from MYSQL_* env vars (default to localhost)
"""
db_url = os.environ.get('DATABASE_URL') or os.environ.get('SQLALCHEMY_DATABASE_URI')
if not db_url:
    mysql_host = os.environ.get('MYSQL_HOST', '127.0.0.1')
    mysql_port = os.environ.get('MYSQL_PORT', '3306')
    mysql_db = os.environ.get('MYSQL_DB', 'ngo_connect')
    mysql_user = os.environ.get('MYSQL_USER', 'root')
    mysql_password = os.environ.get('MYSQL_PASSWORD', 'sai0001sai')
    # Safely encode password
    pwd_enc = quote_plus(mysql_password)
    # Encode database name to avoid spaces/special chars issues
    db_enc = quote(unquote(mysql_db), safe='')
    db_url = f"mysql+pymysql://{mysql_user}:{pwd_enc}@{mysql_host}:{mysql_port}/{db_enc}"
else:
    # Sanitize provided URL: percent-encode path (database name) if it contains spaces or unsafe chars
    try:
        parsed = urlparse(db_url)
        if parsed.scheme.startswith('mysql') and parsed.path:
            # Remove leading '/'; unquote then re-quote to avoid double-encoding
            raw_db = parsed.path.lstrip('/')
            if raw_db:
                db_part = quote(unquote(raw_db), safe='')
                sanitized_path = '/' + db_part
                if sanitized_path != parsed.path:
                    parsed = parsed._replace(path=sanitized_path)
                    db_url = urlunparse(parsed)
    except Exception:
        # If parsing fails, keep original db_url
        pass
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 280
}
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None

# Security settings
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Ensure MySQL database exists if using MySQL
def _ensure_mysql_database_exists(db_uri: str):
    try:
        parsed = urlparse(db_uri)
        if not parsed.scheme.startswith('mysql'):
            return
        user = parsed.username or ''
        password = parsed.password or ''
        host = parsed.hostname or '127.0.0.1'
        port = parsed.port or 3306
        dbname = unquote(parsed.path.lstrip('/'))
        if not dbname:
            return
        try:
            import mysql.connector as mysql_connector
        except Exception:
            # Fall back to PyMySQL via SQLAlchemy engine
            from sqlalchemy import create_engine, text
            server_url = f"{parsed.scheme.split('+')[0]}+pymysql://{user}:{quote_plus(password)}@{host}:{port}/"
            engine = create_engine(server_url, isolation_level="AUTOCOMMIT")
            with engine.connect() as conn:
                conn.execute(text(f"CREATE DATABASE IF NOT EXISTS `{dbname}` CHARACTER SET utf8mb4"))
            return
        # Use mysql-connector directly
        conn = mysql_connector.connect(user=user, password=password, host=host, port=port)
        cur = conn.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{dbname}` CHARACTER SET utf8mb4")
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        # Do not block app startup if creation fails
        pass

_ensure_mysql_database_exists(app.config['SQLALCHEMY_DATABASE_URI'])

# Initialize database
db.init_app(app)

# Initialize other extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*")
csrf = CSRFProtect(app)

# Initialize queries
queries = init_queries(db, {
    'User': User, 'NGO': NGO, 'Volunteer': Volunteer, 'Donor': Donor,
    'Event': Event, 'TimeSlot': TimeSlot, 'Booking': Booking, 'Message': Message,
    'Resource': Resource, 'Project': Project
})

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# A generic form for admin actions that only need CSRF protection
class AdminActionForm(FlaskForm):
    pass

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Force HTTPS in production
    if os.environ.get('FLASK_ENV') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# Ensure csrf_token() and current_year are available in all templates
@app.context_processor
def inject_common_context():
    try:
        year = datetime.now(UTC).year
    except Exception:
        year = 2025
    try:
        perms = get_admin_permissions(current_user) if current_user.is_authenticated else []
    except Exception:
        perms = []
    # Safe defaults for stats used in admin/base.html sidebar badges
    safe_stats = {
        'pending_users': 0,
        'pending_ngos': 0,
    }
    return dict(csrf_token=generate_csrf, current_year=year, admin_permissions=perms, stats=safe_stats)

# Friendly CSRF error handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash(f'Form security check failed: {e.description}', 'error')
    return redirect(request.referrer or url_for('index'))

# If UI templates are missing/archived, return a JSON payload instead of a 500
@app.errorhandler(TemplateNotFound)
def handle_template_not_found(e):
    try:
        path = request.path
    except Exception:
        path = None
    return jsonify({
        'error': 'ui_removed',
        'message': 'The HTML UI for this route has been removed.',
        'route': path,
        'template': str(e)
    }), 501

# Add global no-cache headers in development to avoid 304 during iteration
if os.environ.get('FLASK_ENV', '').lower() != 'production':
    @app.after_request
    def add_no_cache_headers(resp):
        try:
            resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            resp.headers['Pragma'] = 'no-cache'
            resp.headers['Expires'] = '0'
        except Exception:
            pass
        return resp

# Serve a favicon to avoid 404s when browsers request /favicon.ico
@app.route('/favicon.ico')
def favicon_ico():
    try:
        # Reuse the SVG favicon; many browsers accept it even at .ico path
        from flask import send_from_directory
        return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.svg', mimetype='image/svg+xml')
    except Exception:
        return ('', 204)

# Friendly 404 and 500 error pages
@app.errorhandler(404)
def not_found(e):
    try:
        return render_template('404.html'), 404
    except Exception:
        return jsonify({'error': 'not_found'}), 404

@app.errorhandler(500)
def server_error(e):
    try:
        return render_template('500.html'), 500
    except Exception:
        return jsonify({'error': 'server_error'}), 500

# CSRF token refresh endpoint for AJAX clients
@app.route('/api/csrf-token', methods=['GET'])
def api_csrf_token():
    token = generate_csrf()
    resp = jsonify({'csrf_token': token})
    # Prevent caching of the token response
    resp.headers['Cache-Control'] = 'no-store'
    return resp

# Ensure AJAX/JSON requests get a 401 JSON instead of HTML redirect
@login_manager.unauthorized_handler
def unauthorized_handler():
    try:
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Authentication required. Please login and try again.'}), 401
    except Exception:
        pass
    flash('Please login to continue.', 'error')
    return redirect(url_for('login', next=request.path))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

# Favicon route to avoid 404s
@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='favicon.svg'), code=302)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        phone = data.get('phone')

        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))

        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            first_name=first_name,
            last_name=last_name,
            phone=phone
        )
        db.session.add(user)
        db.session.commit()

        # Create role-specific profile
        if role == 'ngo':
            ngo = NGO(
                user_id=user.id,
                organization_name=data.get('organization_name'),
                description=data.get('description'),
                mission=data.get('mission'),
                website=data.get('website'),
                address=data.get('address'),
                city=data.get('city'),
                state=data.get('state'),
                zip_code=data.get('zip_code'),
                email=data.get('email'),
                category=data.get('category'),
                established_year=data.get('established_year')
            )
            db.session.add(ngo)
        elif role == 'volunteer':
            # Handle skills and interests - check if they exist in form data
            skills = data.getlist('skills') if 'skills' in data else []
            interests = data.getlist('interests') if 'interests' in data else []
            
            volunteer = Volunteer(
                user_id=user.id,
                bio=data.get('bio'),
                skills=json.dumps(skills),
                interests=json.dumps(interests)
            )
            db.session.add(volunteer)
        elif role == 'donor':
            donor = Donor(
                user_id=user.id,
                company_name=data.get('company_name')
            )
            db.session.add(donor)

        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Simple rate limiting - check session for failed attempts
        failed_attempts = session.get('failed_login_attempts', 0)
        if failed_attempts >= 5:
            flash('Too many failed login attempts. Please try again later.', 'error')
            return render_template('login.html')
        
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            # Reset failed attempts on successful login
            session.pop('failed_login_attempts', None)
            login_user(user)
            user.last_login = datetime.now(UTC)
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            # Increment failed attempts
            session['failed_login_attempts'] = failed_attempts + 1
            flash('Invalid email or password')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# File upload configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# File upload route
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)
        
        if file_length > MAX_FILE_SIZE:
            flash('File too large. Maximum size is 16MB', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to prevent filename conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            flash('File uploaded successfully', 'success')
            return redirect(request.url)
        else:
            flash('Invalid file type. Allowed: PNG, JPG, JPEG, GIF, PDF, DOC, DOCX', 'error')
            return redirect(request.url)
            
    except Exception as e:
        flash(f'File upload failed: {str(e)}', 'error')
        return redirect(request.url)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_home'))
    elif current_user.role == 'ngo':
        return redirect(url_for('ngo_dashboard'))
    elif current_user.role == 'volunteer':
        return redirect(url_for('volunteer_dashboard'))
    elif current_user.role == 'donor':
        return redirect(url_for('donor_dashboard'))
    else:
        flash('Unknown user role. Please contact support.', 'error')
        return redirect(url_for('index'))



@app.route('/ngo/dashboard')
@login_required
def ngo_dashboard():
    if current_user.role != 'ngo':
        flash('Access denied. NGO privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get NGO statistics and data using queries
    stats = queries.get_ngo_stats(ngo.id)
    events = Event.query.filter_by(ngo_id=ngo.id).order_by(Event.created_at.desc()).limit(5).all()
    
    return render_template('ngo/dashboard.html', ngo=ngo, events=events, **stats)

@app.route('/volunteer/dashboard')
@login_required
def volunteer_dashboard():
    if current_user.role != 'volunteer':
        flash('Access denied. Volunteer privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
    if not volunteer:
        flash('Volunteer profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get volunteer statistics and data using queries
    stats = queries.get_volunteer_stats(volunteer.id)
    bookings = queries.get_user_bookings(current_user.id, 'confirmed')[:5]
    recommended_events = queries.get_recommended_events(volunteer.id, 5)
    
    # Get completed events count
    completed_events = Booking.query.filter_by(
        volunteer_id=volunteer.id, 
        status='completed'
    ).count()
    
    return render_template('volunteer/dashboard.html', 
                         volunteer=volunteer, 
                         bookings=bookings, 
                         recommended_events=recommended_events,
                         completed_events=completed_events,
                         **stats)

@app.route('/donor/dashboard')
@login_required
def donor_dashboard():
    if current_user.role != 'donor':
        return redirect(url_for('dashboard'))
    
    donor = Donor.query.filter_by(user_id=current_user.id).first()
    if not donor:
        flash('Donor profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get donor statistics from real donations table
    donations = Donation.query.filter_by(donor_id=donor.id).order_by(Donation.created_at.desc()).all()
    total_donated = sum(d.amount_inr or 0 for d in donations)
    total_donations = len(donations)
    
    # Get unique organizations supported
    organizations_supported = len(set(d.ngo_id for d in donations))
    
    # Estimate lives impacted (rough calculation) - adjust for INR
    lives_impacted = int(total_donated * 0.03)  # Rough estimate: ₹1 = 0.03 lives impacted
    
    # Get recommended NGOs
    recommended_ngos = queries.get_recommended_ngos(donor.id, limit=5) if queries else []
    
    # Get all NGOs for quick donation form (include all, show in alphabetical order)
    try:
        all_ngos = NGO.query.order_by(NGO.organization_name.asc()).all()
    except Exception:
        all_ngos = NGO.query.all()
    
    return render_template('donor/dashboard.html', 
                         donor=donor,
                         total_donated=total_donated,
                         total_donations=total_donations,
                         organizations_supported=organizations_supported,
                         lives_impacted=lives_impacted,
                         donations=donations,
                         recommended_ngos=recommended_ngos,
                         all_ngos=all_ngos)

@app.route('/donor/certificates')
@login_required
def donor_certificates():
    if current_user.role != 'donor':
        return redirect(url_for('dashboard'))
    donor = Donor.query.filter_by(user_id=current_user.id).first()
    if not donor:
        flash('Donor profile not found.', 'error')
        return redirect(url_for('dashboard'))
    # Show only confirmed donations
    confirmed = Donation.query.filter_by(donor_id=donor.id, status='confirmed').order_by(Donation.created_at.desc()).all()
    return render_template('donor/certificates.html', donor=donor, certificates=confirmed)

@app.route('/donor/certificates/<int:donation_id>')
@login_required
def donor_certificate_view(donation_id: int):
    if current_user.role != 'donor':
        return redirect(url_for('dashboard'))
    donor = Donor.query.filter_by(user_id=current_user.id).first()
    if not donor:
        flash('Donor profile not found.', 'error')
        return redirect(url_for('dashboard'))
    donation = Donation.query.get_or_404(donation_id)
    if donation.donor_id != donor.id:
        flash('Access denied.', 'error')
        return redirect(url_for('donor_certificates'))
    if donation.status != 'confirmed':
        flash('Certificate is only available for confirmed donations.', 'error')
        return redirect(url_for('donor_certificates'))
    ngo = db.session.get(NGO, donation.ngo_id) if donation.ngo_id else None
    if request.args.get('download'):
        html = render_template('donor/certificate_view.html', donor=donor, donation=donation, ngo=ngo)
        resp = make_response(html)
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        resp.headers['Content-Disposition'] = f"attachment; filename=CERT-{donation.id}.html"
        return resp
    return render_template('donor/certificate_view.html', donor=donor, donation=donation, ngo=ngo)

@app.route('/volunteer/achievements')
@login_required
def volunteer_achievements():
    if current_user.role != 'volunteer':
        flash('Access denied. Volunteer privileges required.', 'error')
        return redirect(url_for('dashboard'))

    volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
    if not volunteer:
        flash('Volunteer profile not found.', 'error')
        return redirect(url_for('dashboard'))

    stats = queries.get_volunteer_stats(volunteer.id)
    recent_bookings = queries.get_user_bookings(current_user.id)[:10]

    return render_template(
        'volunteer/achievements.html',
        volunteer=volunteer,
        recent_bookings=recent_bookings,
        **stats
    )

@app.route('/volunteers/leaderboard')
def volunteers_leaderboard():
    # Source leaderboards
    points_leaders = queries.get_volunteer_leaderboard(limit=50)
    hours_leaders = queries.get_hours_leaderboard(limit=50)

    # Build a unified ranking primarily by hours (desc)
    # Fallbacks ensure route works even with sparse data
    def v_to_dict(v, rank=None):
        user = getattr(v, 'user', None)
        first = getattr(user, 'first_name', '') or ''
        last = getattr(user, 'last_name', '') or ''
        name = f"{first} {last}".strip() or f"Volunteer #{getattr(v, 'id', '')}"
        avatar = (first[:1] or '?').upper()
        return {
            'id': getattr(v, 'id', None),
            'name': name,
            'avatar': avatar,
            'hours': getattr(v, 'total_hours', 0) or 0,
            'points': getattr(v, 'total_points', 0) or 0,
            'rank': rank,
        }

    ranked = [v_to_dict(v, idx + 1) for idx, v in enumerate(hours_leaders or [])]
    top_three = ranked[:3]
    others = ranked[3:]

    return render_template(
        'volunteers_leaderboard.html',
        # New template context
        top_three=top_three,
        others=others,
        # Backward compatibility (in case template still references old vars)
        points_leaders=points_leaders,
        hours_leaders=hours_leaders,
    )

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/donations/checkout', methods=['GET'])
@login_required
def donation_checkout():
    if current_user.role != 'donor':
        flash('Please login as a donor to make a donation.', 'error')
        return redirect(url_for('login', next=request.full_path))

    ngo_id = request.args.get('ngo') or request.args.get('ngo_id')
    amount = request.args.get('amount')
    message = request.args.get('message', '')
    anonymous = request.args.get('anonymous') in ('true', '1', 'on')

    ngo = None
    if ngo_id:
        try:
            ngo = NGO.query.get(int(ngo_id))
        except Exception:
            ngo = None
    if not ngo:
        ngo = NGO.query.order_by(NGO.organization_name.asc()).first()

    # Payment config (UPI)
    upi_id = os.environ.get('DONATIONS_UPI_ID', '8106286518@ptyes')  # e.g., myngo@okhdfcbank
    upi_name = os.environ.get('DONATIONS_UPI_NAME', 'NGO Connect')

    return render_template('donor/checkout.html', ngo=ngo, amount=amount, message=message, anonymous=anonymous,
                           upi_id=upi_id, upi_name=upi_name)

@app.route('/api/donations/confirm', methods=['POST'])
@login_required
def api_donations_confirm():
    if current_user.role != 'donor':
        return jsonify({'error': 'Only donors can confirm donations'}), 403
    try:
        payload = request.get_json(force=True)
        ngo_id = int(payload.get('ngo_id'))
        amount_inr = float(payload.get('amount_inr')) if payload.get('amount_inr') else None
        amount_crypto = None  # Not applicable for UPI
        currency = 'INR'
        network = 'upi'
        tx_hash = payload.get('upi_reference') or None
        message_text = payload.get('message') or ''
        anonymous = bool(payload.get('anonymous'))

        donor = Donor.query.filter_by(user_id=current_user.id).first()
        if not donor:
            return jsonify({'error': 'Donor profile not found'}), 400

        ngo = NGO.query.get(ngo_id)
        if not ngo:
            return jsonify({'error': 'NGO not found'}), 404

        # Prevent duplicate UPI reference submissions
        if tx_hash:
            existing = Donation.query.filter_by(network='upi', tx_hash=tx_hash).first()
            if existing:
                return jsonify({'message': 'Donation reference already recorded', 'donation_id': existing.id}), 200

        # Decide initial status based on simple verification
        def _looks_like_valid_upi_ref(ref: str) -> bool:
            try:
                import re
                if not ref:
                    return False
                # Common UPI refs are 8-18 chars, alphanumeric; many banks use 12-digit or alphanum tokens
                return bool(re.fullmatch(r"[A-Za-z0-9]{8,18}", ref))
            except Exception:
                return False

        auto_verify = os.environ.get('UPI_AUTO_VERIFY', 'false').lower() in ('1','true','yes')
        initial_status = 'pending_verification' if tx_hash else 'pending'
        if tx_hash and _looks_like_valid_upi_ref(tx_hash) and auto_verify:
            initial_status = 'confirmed'

        donation = Donation(
            donor_id=None if anonymous else donor.id,
            ngo_id=ngo.id,
            amount_inr=amount_inr,
            amount_crypto=amount_crypto,
            currency=currency,
            network=network,
            tx_hash=tx_hash,
            message=message_text,
            anonymous=anonymous,
            status=initial_status
        )
        db.session.add(donation)
        db.session.commit()
        return jsonify({'message': 'Donation recorded', 'donation_id': donation.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Could not record donation: {str(e)}'}), 500

@app.route('/admin/donations')
@login_required
@admin_required
def admin_donations():
    # Filters
    status = request.args.get('status')
    ngo_id = request.args.get('ngo_id', type=int)
    q = Donation.query
    if status:
        q = q.filter(Donation.status == status)
    if ngo_id:
        q = q.filter(Donation.ngo_id == ngo_id)
    q = q.order_by(Donation.created_at.desc())
    donations = q.all()

    if request.args.get('export') == 'csv':
        import csv
        from io import StringIO
        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(['id','donor_id','ngo_id','amount_inr','amount_crypto','currency','network','tx_hash','anonymous','status','created_at'])
        for d in donations:
            writer.writerow([d.id, d.donor_id, d.ngo_id, d.amount_inr, d.amount_crypto, d.currency, d.network, d.tx_hash, d.anonymous, d.status, d.created_at.isoformat()])
        output = make_response(si.getvalue())
        output.headers['Content-Type'] = 'text/csv'
        output.headers['Content-Disposition'] = 'attachment; filename=donations.csv'
        return output

    ngos = NGO.query.order_by(NGO.organization_name.asc()).all()
    return render_template('admin/donations.html', donations=donations, ngos=ngos, selected_status=status, selected_ngo_id=ngo_id)

@app.route('/admin/donations/<int:donation_id>/set-status', methods=['POST'])
@login_required
@admin_required
def admin_set_donation_status(donation_id: int):
    new_status = request.form.get('status')
    if new_status not in ('pending','pending_verification','confirmed','failed'):
        flash('Invalid status', 'error')
        return redirect(url_for('admin_donations'))
    try:
        d = Donation.query.get_or_404(donation_id)
        d.status = new_status
        db.session.commit()
        flash('Donation status updated', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to update status: {str(e)}', 'error')
    return redirect(url_for('admin_donations'))

@app.route('/ngos')
def ngos_directory():
    search_term = request.args.get('q', '')
    category = request.args.get('category') or None
    city = request.args.get('city') or None
    ngos = queries.search_ngos(search_term, category=category, city=city)
    return render_template('ngos.html', ngos=ngos, q=search_term, category=category, city=city)

@app.route('/ngos/<int:ngo_id>/opportunities')
def ngo_opportunities(ngo_id: int):
    ngo = NGO.query.get_or_404(ngo_id)
    events = Event.query.filter_by(ngo_id=ngo.id, is_active=True).order_by(Event.start_date.asc()).all()
    return render_template('ngo/opportunities.html', ngo=ngo, events=events)

@app.route('/volunteer/events/<int:event_id>')
def volunteer_event_detail(event_id: int):
    event = Event.query.get_or_404(event_id)
    ngo = db.session.get(NGO, event.ngo_id)
    time_slots = TimeSlot.query.filter_by(event_id=event.id, is_available=True).order_by(TimeSlot.start_time.asc()).all()
    return render_template('volunteer/event_detail.html', event=event, ngo=ngo, time_slots=time_slots)


# NGO Event Management Routes
@app.route('/ngo/events')
@login_required
def ngo_events():
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    events = Event.query.filter_by(ngo_id=ngo.id).order_by(Event.created_at.desc()).all()
    return render_template('ngo/events.html', events=events, ngo=ngo)

# ===== QR Attendance: NGO QR Page, Token APIs, Volunteer Check-in =====
def _now_utc():
    try:
        return datetime.now(UTC)
    except Exception:
        return datetime.utcnow()

@app.route('/ngo/events/<int:event_id>/attendance', methods=['GET'])
@login_required
def ngo_attendance_qr(event_id: int):
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    event = Event.query.get_or_404(event_id)
    if event.ngo_id != ngo.id:
        flash('Access denied. You can only view your own events.', 'error')
        return redirect(url_for('ngo_events'))
    # Optionally limit to a specific time slot via query param
    time_slot_id = request.args.get('time_slot_id', type=int)
    ts = TimeSlot.query.get(time_slot_id) if time_slot_id else None
    if ts and ts.event_id != event.id:
        flash('Invalid time slot selected.', 'error')
        return redirect(url_for('ngo_view_event', event_id=event.id))
    return render_template('ngo/attendance_qr.html', ngo=ngo, event=event, time_slot=ts)

@app.route('/api/attendance/token', methods=['POST'])
@login_required
@csrf.exempt
def api_attendance_token():
    # Only NGO users can generate tokens
    if current_user.role != 'ngo':
        return jsonify({'error': 'Only NGO users can generate attendance tokens'}), 403
    try:
        data = request.get_json(force=True)
        event_id = int(data.get('event_id'))
        time_slot_id = data.get('time_slot_id')
        ts_id = int(time_slot_id) if time_slot_id else None
        event = Event.query.get_or_404(event_id)
        ngo = NGO.query.filter_by(user_id=current_user.id).first()
        if not ngo or event.ngo_id != ngo.id:
            return jsonify({'error': 'Access denied'}), 403
        if ts_id:
            ts = TimeSlot.query.get_or_404(ts_id)
            if ts.event_id != event.id:
                return jsonify({'error': 'Invalid time slot'}), 400
        # Deactivate existing active tokens for this scope
        AttendanceToken.query.filter_by(ngo_id=ngo.id, event_id=event.id, time_slot_id=ts_id, is_active=True).update({'is_active': False})
        # Create new token, expire in N minutes
        ttl_minutes = int(os.environ.get('ATTENDANCE_QR_TTL_MINUTES', '2'))
        tok = AttendanceToken(
            ngo_id=ngo.id,
            event_id=event.id,
            time_slot_id=ts_id,
            token=token_hex(24),
            expires_at=_now_utc() + timedelta(minutes=ttl_minutes),
            is_active=True
        )
        db.session.add(tok)
        db.session.commit()
        return jsonify({
            'token': tok.token,
            'expires_at': tok.expires_at.isoformat(),
            'ttl_minutes': ttl_minutes
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to generate token: {str(e)}'}), 500

@app.route('/attend', methods=['GET'])
@login_required
def attend_page():
    # Volunteers land here after scanning the QR
    tok = request.args.get('t') or request.args.get('token')
    if not tok:
        flash('Invalid or missing token.', 'error')
        return redirect(url_for('dashboard'))
    at = AttendanceToken.query.filter_by(token=tok, is_active=True).first()
    if not at:
        flash('This attendance token is invalid or expired.', 'error')
        return redirect(url_for('dashboard'))
    event = Event.query.get(at.event_id)
    ts = TimeSlot.query.get(at.time_slot_id) if at.time_slot_id else None
    return render_template('volunteer/attend_scan.html', token=tok, event=event, time_slot=ts)

@app.route('/api/attendance/checkin', methods=['POST'])
@login_required
@csrf.exempt
def api_attendance_checkin():
    # Only volunteers can check in
    if current_user.role != 'volunteer':
        return jsonify({'error': 'Only volunteers can check in'}), 403
    try:
        data = request.get_json(force=True)
        tok = data.get('token')
        if not tok:
            return jsonify({'error': 'Missing token'}), 400
        at = AttendanceToken.query.filter_by(token=tok, is_active=True).first()
        if not at:
            return jsonify({'error': 'Invalid or expired token'}), 400
        # Expiry check
        if at.expires_at < _now_utc():
            at.is_active = False
            db.session.commit()
            return jsonify({'error': 'Token expired'}), 400
        # Find volunteer booking
        volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
        if not volunteer:
            return jsonify({'error': 'Volunteer profile not found'}), 400
        q = Booking.query.filter_by(volunteer_id=volunteer.id, event_id=at.event_id)
        if at.time_slot_id:
            q = q.filter(Booking.time_slot_id == at.time_slot_id)
        booking = q.first()
        if not booking:
            return jsonify({'error': 'No matching booking found for this event/time slot'}), 404
        # Mark check-in
        booking.check_in_at = _now_utc()
        booking.attendance_status = 'present'
        db.session.commit()
        return jsonify({'message': 'Check-in recorded', 'booking_id': booking.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to record attendance: {str(e)}'}), 500

@app.route('/ngo/events/new', methods=['GET', 'POST'])
@login_required
def ngo_create_event():
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            # Parse required skills from form
            required_skills = request.form.getlist('required_skills')
            
            event = Event(
                ngo_id=ngo.id,
                title=request.form['title'],
                description=request.form['description'],
                location=request.form['location'],
                start_date=datetime.strptime(request.form['start_date'], '%Y-%m-%d'),
                end_date=datetime.strptime(request.form['end_date'], '%Y-%m-%d'),
                category=request.form['category'],
                max_volunteers=int(request.form['max_volunteers']),
                required_skills=json.dumps(required_skills),
                is_active=True
            )
            
            db.session.add(event)
            db.session.commit()
            
            # Create manual time slots from form arrays
            slot_dates = request.form.getlist('slot_date[]')
            slot_starts = request.form.getlist('slot_start[]')
            slot_ends = request.form.getlist('slot_end[]')
            slot_caps = request.form.getlist('slot_capacity[]')

            if not slot_dates or not slot_starts or not slot_ends or not slot_caps:
                raise ValueError('Please add at least one time slot.')
            if not (len(slot_dates) == len(slot_starts) == len(slot_ends) == len(slot_caps)):
                raise ValueError('Time slot inputs are inconsistent. Please review your slots.')

            for i in range(len(slot_dates)):
                d = slot_dates[i]
                s = slot_starts[i]
                e = slot_ends[i]
                cap_str = slot_caps[i]
                try:
                    cap = int(cap_str)
                except Exception:
                    cap = event.max_volunteers or 1
                if cap < 1:
                    cap = 1

                # Parse datetimes
                day = datetime.strptime(d, '%Y-%m-%d')
                start_dt = datetime.strptime(f"{d} {s}", '%Y-%m-%d %H:%M')
                end_dt = datetime.strptime(f"{d} {e}", '%Y-%m-%d %H:%M')

                # Validate range and scope
                if end_dt <= start_dt:
                    raise ValueError('Each slot end time must be after the start time.')
                if day.date() < event.start_date.date() or day.date() > event.end_date.date():
                    raise ValueError('Slot dates must be within the event start and end dates.')

                slot = TimeSlot(
                    event_id=event.id,
                    start_time=start_dt,
                    end_time=end_dt,
                    max_volunteers=cap,
                    current_volunteers=0,
                    is_available=True
                )
                db.session.add(slot)
            
            db.session.commit()
            flash('Event created successfully!', 'success')
            return redirect(url_for('ngo_events'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating event: {str(e)}', 'error')
    
    return render_template('ngo/create_event.html', ngo=ngo)

@app.route('/ngo/events/<int:event_id>')
@login_required
def ngo_view_event(event_id):
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    if event.ngo_id != ngo.id:
        flash('Access denied. You can only view your own events.', 'error')
        return redirect(url_for('ngo_events'))
    
    time_slots = TimeSlot.query.filter_by(event_id=event.id).order_by(TimeSlot.start_time).all()
    bookings = Booking.query.filter_by(event_id=event.id).all()
    
    return render_template('ngo/view_event.html', event=event, time_slots=time_slots, bookings=bookings, ngo=ngo)

@app.route('/ngo/events/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
def ngo_edit_event(event_id):
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    if event.ngo_id != ngo.id:
        flash('Access denied. You can only edit your own events.', 'error')
        return redirect(url_for('ngo_events'))
    
    if request.method == 'POST':
        try:
            required_skills = request.form.getlist('required_skills')
            
            event.title = request.form['title']
            event.description = request.form['description']
            event.location = request.form['location']
            event.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
            event.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
            event.category = request.form['category']
            event.max_volunteers = int(request.form['max_volunteers'])
            event.required_skills = json.dumps(required_skills)
            event.updated_at = datetime.utcnow()
            # Keep timezone aware timestamp
            event.updated_at = datetime.now(UTC)
            
            db.session.commit()
            flash('Event updated successfully!', 'success')
            return redirect(url_for('ngo_view_event', event_id=event.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating event: {str(e)}', 'error')
    
    return render_template('ngo/edit_event.html', event=event, ngo=ngo)

@app.route('/ngo/events/<int:event_id>/delete', methods=['POST'])
@login_required
def ngo_delete_event(event_id):
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    if event.ngo_id != ngo.id:
        flash('Access denied. You can only delete your own events.', 'error')
        return redirect(url_for('ngo_events'))
    
    try:
        # Delete related bookings and time slots first
        Booking.query.filter_by(event_id=event.id).delete()
        TimeSlot.query.filter_by(event_id=event.id).delete()
        
        # Delete the event
        db.session.delete(event)
        db.session.commit()
        
        flash('Event deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting event: {str(e)}', 'error')
    
    return redirect(url_for('ngo_events'))

@app.route('/ngo/events/<int:event_id>/toggle-status', methods=['POST'])
@login_required
def ngo_toggle_event_status(event_id):
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    if event.ngo_id != ngo.id:
        flash('Access denied. You can only modify your own events.', 'error')
        return redirect(url_for('ngo_events'))
    
    try:
        event.is_active = not event.is_active
        db.session.commit()
        
        status = 'activated' if event.is_active else 'deactivated'
        flash(f'Event {status} successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating event status: {str(e)}', 'error')
    
    return redirect(url_for('ngo_view_event', event_id=event.id))

# API Routes
@app.route('/api/events')
def get_events():
    events = Event.query.filter_by(is_active=True).all()
    return jsonify([{
        'id': event.id,
        'title': event.title,
        'description': event.description,
        'location': event.location,
        'start_date': event.start_date.isoformat(),
        'end_date': event.end_date.isoformat(),
        'ngo_name': db.session.get(NGO, event.ngo_id).organization_name
    } for event in events])

@app.route('/api/events/<int:event_id>/slots')
def get_event_slots(event_id):
    slots = TimeSlot.query.filter_by(event_id=event_id, is_available=True).all()
    return jsonify([{
        'id': slot.id,
        'start_time': slot.start_time.isoformat(),
        'end_time': slot.end_time.isoformat(),
        'available_spots': slot.max_volunteers - slot.current_volunteers
    } for slot in slots])

@app.route('/api/book-slot', methods=['POST'])
@login_required
def book_slot():
    if current_user.role != 'volunteer':
        return jsonify({'error': 'Only volunteers can book slots'}), 403
    
    try:
        data = request.json
        slot_id = data.get('slot_id')
        event_id = data.get('event_id')
        
        if not slot_id or not event_id:
            return jsonify({'error': 'Missing slot_id or event_id'}), 400
        
        volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
        if not volunteer:
            return jsonify({'error': 'Volunteer profile not found'}), 400
        
        # Check if already booked
        existing_booking = Booking.query.filter_by(
            volunteer_id=volunteer.id,
            time_slot_id=slot_id
        ).first()
        
        if existing_booking:
            return jsonify({'error': 'You have already booked this slot'}), 400
        
        # Use database transaction to prevent race condition
        # Fix: Don't use nested transaction, use explicit commit/rollback
        slot = TimeSlot.query.filter_by(id=slot_id).with_for_update().first()
        
        if not slot or not slot.is_available:
            return jsonify({'error': 'Slot not available'}), 400
        
        if slot.current_volunteers >= slot.max_volunteers:
            return jsonify({'error': 'Slot is full'}), 400
        
        # Create booking
        booking = Booking(
            volunteer_id=volunteer.id,
            time_slot_id=slot_id,
            event_id=event_id,
            status='confirmed'
        )
        
        # Update slot
        slot.current_volunteers += 1
        if slot.current_volunteers >= slot.max_volunteers:
            slot.is_available = False
        
        # Add booking to session and commit
        db.session.add(booking)
        db.session.commit()
        
        return jsonify({'message': 'Slot booked successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Booking failed: {str(e)}'}), 500


@app.route('/volunteer/bookings/<int:booking_id>/cancel', methods=['POST'])
@login_required
def cancel_booking(booking_id: int):
    if current_user.role != 'volunteer':
        return jsonify({'error': 'Only volunteers can cancel bookings'}), 403
    try:
        volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
        if not volunteer:
            return jsonify({'error': 'Volunteer profile not found'}), 400

        booking = Booking.query.get_or_404(booking_id)
        if booking.volunteer_id != volunteer.id:
            return jsonify({'error': 'You can only cancel your own bookings'}), 403

        if booking.status == 'cancelled':
            return jsonify({'message': 'Booking already cancelled'}), 200

        # Update slot availability
        slot = TimeSlot.query.get(booking.time_slot_id)
        if slot:
            if slot.current_volunteers and slot.current_volunteers > 0:
                slot.current_volunteers -= 1
            if slot.current_volunteers < slot.max_volunteers:
                slot.is_available = True

        booking.status = 'cancelled'
        db.session.commit()

        # Support both AJAX and form submissions
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({'message': 'Booking cancelled successfully'})
        else:
            flash('Booking cancelled successfully', 'success')
            return redirect(url_for('volunteer_dashboard'))
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Cancellation failed: {str(e)}'}), 500

# Socket.IO events
@socketio.on('join_room')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'User has joined the room: {room}'}, room=room)

@socketio.on('send_message')
def handle_message(data):
    room = data['room']
    try:
        message = Message(
            sender_id=current_user.id,
            receiver_id=data['receiver_id'],
            content=data['message']
        )
        db.session.add(message)
        db.session.commit()
        
        emit('receive_message', {
            'sender': current_user.first_name + ' ' + current_user.last_name,
            'message': data['message'],
            'timestamp': datetime.utcnow().isoformat()
        }, room=room)
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': f'Failed to send message: {str(e)}'}, room=room)

# Search API Routes
@app.route('/api/search/ngos')
def search_ngos_api():
    """API endpoint for searching NGOs"""
    try:
        search_term = request.args.get('q', '')
        category = request.args.get('category', '') or None
        city = request.args.get('city', '') or None
        
        ngos = queries.search_ngos(search_term, category=category, city=city)
        
        return jsonify([{
            'id': ngo.id,
            'organization_name': ngo.organization_name,
            'description': ngo.description,
            'mission': ngo.mission,
            'category': ngo.category,
            'city': ngo.city,
            'state': ngo.state,
            'rating': getattr(ngo, 'rating', 0) or 0,
            'total_donations': getattr(ngo, 'total_donations', 0) or 0,
            'volunteers_count': getattr(ngo, 'volunteers_count', 0) or 0,
            'contact_email': ngo.email,
            'contact_phone': ngo.phone if hasattr(ngo, 'phone') else '',
            'website': ngo.website,
            'logo_url': ngo.logo or '',
            'is_verified': ngo.is_verified
        } for ngo in ngos])
    except Exception as e:
        return jsonify({'error': f'Search failed: {str(e)}'}), 500

@app.route('/api/search/events')
def search_events_api():
    """API endpoint for searching events"""
    try:
        search_term = request.args.get('q', '')
        category = request.args.get('category', '') or None
        location = request.args.get('location', '') or None
        
        events = queries.search_events(search_term, category=category, location=location)
        
        return jsonify([{
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'location': event.location,
            'start_date': event.start_date.isoformat(),
            'end_date': event.end_date.isoformat(),
            'category': event.category,
            'max_volunteers': event.max_volunteers,
            'required_skills': json.loads(event.required_skills) if event.required_skills else [],
            'is_active': event.is_active,
            'ngo_id': event.ngo_id,
            'ngo_name': db.session.get(NGO, event.ngo_id).organization_name,
            'ngo_logo': (db.session.get(NGO, event.ngo_id).logo or '')
        } for event in events])
    except Exception as e:
        return jsonify({'error': f'Search failed: {str(e)}'}), 500

@app.route('/api/ngos/categories')
def get_ngo_categories():
    """Get unique NGO categories"""
    try:
        categories = db.session.query(NGO.category).distinct().filter(
            NGO.category.isnot(None),
            NGO.is_verified == True
        ).order_by(NGO.category).all()
        
        return jsonify([cat[0] for cat in categories if cat[0]])
    except Exception as e:
        return jsonify({'error': f'Failed to get categories: {str(e)}'}), 500

@app.route('/api/events/categories')
def get_event_categories():
    """Get unique event categories"""
    try:
        categories = db.session.query(Event.category).distinct().filter(
            Event.category.isnot(None),
            Event.is_active == True
        ).order_by(Event.category).all()
        
        return jsonify([cat[0] for cat in categories if cat[0]])
    except Exception as e:
        return jsonify({'error': f'Failed to get categories: {str(e)}'}), 500

# Admin dashboard route removed

@app.route('/admin/users')
@admin_required
@admin_permission_required('manage_users')
@rate_limit_admin_requests(max_requests=50, window_minutes=60)
def admin_users():
    """Admin user management page"""
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '')
        role_filter = request.args.get('role', '')
        status_filter = request.args.get('status', '')
        
        # Build query
        query = User.query
        
        if search:
            query = query.filter(
                or_(
                    User.first_name.ilike(f'%{search}%'),
                    User.last_name.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%')
                )
            )
        
        if role_filter:
            query = query.filter(User.role == role_filter)
        
        if status_filter:
            if status_filter == 'verified':
                query = query.filter(User.is_verified == True)
            elif status_filter == 'unverified':
                query = query.filter(User.is_verified == False)
            elif status_filter == 'active':
                query = query.filter(User.is_active == True)
            elif status_filter == 'inactive':
                query = query.filter(User.is_active == False)
        
        users = query.paginate(page=page, per_page=20, error_out=False)
        
        log_admin_action(
            action='VIEW_USERS_LIST',
            resource_type='USER_MANAGEMENT',
            success=True
        )
        
        return render_template('admin/users.html', users=users, 
                             search=search, role_filter=role_filter, 
                             status_filter=status_filter)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_USERS_ERROR',
            resource_type='USER_MANAGEMENT',
            success=False,
            error_message=str(e)
        )
        flash('Error loading users', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/content/update', methods=['POST'])
@admin_required
@admin_permission_required('manage_content')
def update_admin_content():
    """Stub endpoint to handle content management form submissions."""
    try:
        # In a future iteration, persist content to the database or CMS.
        # For now, just acknowledge receipt and redirect back.
        section = request.form.get('section', 'content')
        flash(f'Content for {section} saved successfully', 'success')
        return redirect(url_for('admin_content'))
    except Exception as e:
        flash(f'Error saving content: {str(e)}', 'error')
        return redirect(url_for('admin_content'))

@app.route('/admin/users/export')
@admin_required
@admin_permission_required('manage_users')
def export_users():
    """Export filtered users to CSV using same filters as admin_users"""
    try:
        import csv, io
        page = request.args.get('page', 1, type=int)  # unused, but accepted
        search = request.args.get('search', '')
        role_filter = request.args.get('role', '')
        status_filter = request.args.get('status', '')

        query = User.query
        if search:
            query = query.filter(
                or_(
                    User.first_name.ilike(f'%{search}%'),
                    User.last_name.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%')
                )
            )
        if role_filter:
            query = query.filter(User.role == role_filter)
        if status_filter:
            if status_filter == 'verified':
                query = query.filter(User.is_verified == True)
            elif status_filter == 'unverified':
                query = query.filter(User.is_verified == False)
            elif status_filter == 'active':
                query = query.filter(User.is_active == True)
            elif status_filter == 'inactive':
                query = query.filter(User.is_active == False)

        users = query.order_by(User.created_at.desc()).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['First Name', 'Last Name', 'Email', 'Role', 'Verified', 'Active', 'Registered', 'Last Login'])
        for u in users:
            writer.writerow([
                u.first_name or '',
                u.last_name or '',
                u.email,
                u.role,
                'Yes' if u.is_verified else 'No',
                'Yes' if u.is_active else 'No',
                (u.created_at.strftime('%Y-%m-%d') if getattr(u, 'created_at', None) else ''),
                (u.last_login.strftime('%Y-%m-%d %H:%M') if getattr(u, 'last_login', None) else '')
            ])

        output.seek(0)
        csv_content = output.getvalue()
        response = make_response(csv_content)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=users_export.csv'
        return response
    except Exception as e:
        flash(f'Error exporting users: {str(e)}', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/home')
@admin_required
def admin_home():
    """Admin home page (landing) with quick links only"""
    try:
        perms = get_admin_permissions(current_user)
        return render_template('admin/home.html', admin_permissions=perms)
    except Exception as e:
        flash('Error loading admin home', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@csrf.exempt
@admin_required
@admin_permission_required('manage_users')
@rate_limit_admin_requests(max_requests=20, window_minutes=60)
@validate_admin_input({
    'user_id': {'type': 'integer', 'required': True}
})
def toggle_user_status(user_id):
    """Toggle user active status"""
    form = AdminActionForm()
    if form.validate_on_submit():
        try:
            user = User.query.get_or_404(user_id)
            user.is_active = not user.is_active
            db.session.commit()
            action = 'ACTIVATE_USER' if user.is_active else 'DEACTIVATE_USER'
            log_admin_action(
                action=action,
                resource_type='USER',
                resource_id=user_id,
                details={'user_email': user.email, 'new_status': user.is_active}
            )
            flash(f'User {action.lower().replace("_", " ")}d successfully.', 'success')
        except Exception as e:
            log_admin_action(
                action='TOGGLE_USER_STATUS_ERROR',
                resource_type='USER',
                resource_id=user_id,
                success=False,
                error_message=str(e)
            )
            flash(f'Error updating user status: {str(e)}', 'error')
    else:
        if form.errors.get('csrf_token'):
            flash(f'Form security check failed: {form.errors["csrf_token"][0]}', 'error')
        else:
            flash('An unexpected error occurred with the form submission.', 'error')
    return redirect(request.referrer or url_for('admin_user_profile', user_id=user_id))

@app.route('/admin/users/<int:user_id>/verify', methods=['POST'])
@csrf.exempt
@admin_required
@admin_permission_required('manage_users')
@rate_limit_admin_requests(max_requests=20, window_minutes=60)
@validate_admin_input({
    'user_id': {'type': 'integer', 'required': True}
})
def verify_user(user_id):
    """Verify a user account"""
    form = AdminActionForm()
    if form.validate_on_submit():
        try:
            user = User.query.get_or_404(user_id)
            user.is_verified = True
            db.session.commit()
            log_admin_action(
                action='VERIFY_USER',
                resource_type='USER',
                resource_id=user_id,
                details={'user_email': user.email}
            )
            flash('User verified successfully.', 'success')
        except Exception as e:
            log_admin_action(
                action='VERIFY_USER_ERROR',
                resource_type='USER',
                resource_id=user_id,
                success=False,
                error_message=str(e)
            )
            flash(f'Error verifying user: {str(e)}', 'error')
    else:
        if form.errors.get('csrf_token'):
            flash(f'Form security check failed: {form.errors["csrf_token"][0]}', 'error')
        else:
            flash('An unexpected error occurred with the form submission.', 'error')
    return redirect(request.referrer or url_for('admin_user_profile', user_id=user_id))

@app.route('/admin/audit-logs')
@admin_required
@admin_permission_required('view_audit_logs')
def admin_audit_logs():
    """Admin audit logs page"""
    try:
        page = request.args.get('page', 1, type=int)
        admin_filter = request.args.get('admin', '')
        action_filter = request.args.get('action', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        
        # Build query
        query = AdminAuditLog.query
        
        if admin_filter:
            query = query.filter(AdminAuditLog.admin_user_id == admin_filter)
        
        if action_filter:
            query = query.filter(AdminAuditLog.action == action_filter)
        
        if date_from:
            query = query.filter(AdminAuditLog.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
        
        if date_to:
            query = query.filter(AdminAuditLog.timestamp <= datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1))
        
        logs = query.order_by(AdminAuditLog.timestamp.desc()).paginate(
            page=page, per_page=50, error_out=False
        )
        
        # Get unique actions for filter
        actions = db.session.query(AdminAuditLog.action).distinct().order_by(AdminAuditLog.action).all()
        actions = [action[0] for action in actions]
        
        # Get admin users for filter
        admin_users = User.query.filter_by(role='admin').all()
        
        log_admin_action(
            action='VIEW_AUDIT_LOGS',
            resource_type='AUDIT_LOG',
            success=True
        )
        
        return render_template('admin/audit_logs.html', logs=logs, actions=actions,
                             admin_users=admin_users, admin_filter=admin_filter,
                             action_filter=action_filter, date_from=date_from,
                             date_to=date_to)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_AUDIT_LOGS_ERROR',
            resource_type='AUDIT_LOG',
            success=False,
            error_message=str(e)
        )
        flash('Error loading audit logs', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/ngos')
@admin_required
@admin_permission_required('manage_ngos')
def admin_ngos():
    """Admin NGOs management page"""
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '')
        status_filter = request.args.get('status', '')
        
        # Build query
        query = NGO.query
        
        if search:
            # Match against organization_name and description
            query = query.filter(
                or_(
                    NGO.organization_name.ilike(f'%{search}%'),
                    NGO.description.ilike(f'%{search}%')
                )
            )
        
        # Map status_filter to available fields (is_verified)
        if status_filter:
            if status_filter == 'verified':
                query = query.filter(NGO.is_verified == True)
            elif status_filter == 'unverified':
                query = query.filter(NGO.is_verified == False)
        
        ngos = query.paginate(page=page, per_page=20, error_out=False)
        
        log_admin_action(
            action='VIEW_NGOS',
            resource_type='NGO',
            success=True
        )
        
        return render_template('admin/ngos.html', ngos=ngos, search=search, status_filter=status_filter)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_NGOS_ERROR',
            resource_type='NGO',
            success=False,
            error_message=str(e)
        )
        flash('Error loading NGOs', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/ngos/export')
@admin_required
@admin_permission_required('manage_ngos')
def export_ngos():
    """Export filtered NGOs to CSV using same filters as admin_ngos"""
    try:
        import csv, io
        search = request.args.get('search', '')
        status_filter = request.args.get('status', '')

        query = NGO.query
        if search:
            query = query.filter(
                or_(
                    NGO.organization_name.ilike(f'%{search}%'),
                    NGO.description.ilike(f'%{search}%')
                )
            )
        if status_filter:
            if status_filter == 'verified':
                query = query.filter(NGO.is_verified == True)
            elif status_filter == 'unverified':
                query = query.filter(NGO.is_verified == False)

        ngos = query.order_by(NGO.created_at.desc()).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Organization Name', 'Category', 'Verified', 'Created At', 'Email', 'Website', 'City', 'State'])
        for n in ngos:
            writer.writerow([
                n.organization_name or '',
                n.category or '',
                'Yes' if n.is_verified else 'No',
                (n.created_at.strftime('%Y-%m-%d') if getattr(n, 'created_at', None) else ''),
                n.email or '',
                n.website or '',
                n.city or '',
                n.state or ''
            ])

        output.seek(0)
        csv_content = output.getvalue()
        response = make_response(csv_content)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=ngos_export.csv'
        return response
    except Exception as e:
        flash(f'Error exporting NGOs: {str(e)}', 'error')
        return redirect(url_for('admin_ngos'))

@app.route('/admin/events')
@admin_required
@admin_permission_required('manage_events')
def admin_events():
    """Admin events management page"""
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '')
        status_filter = request.args.get('status', '')
        
        # Build query
        query = Event.query
        
        if search:
            query = query.filter(Event.title.contains(search))
        
        if status_filter:
            query = query.filter(Event.status == status_filter)
        
        events = query.paginate(page=page, per_page=20, error_out=False)
        
        log_admin_action(
            action='VIEW_EVENTS',
            resource_type='EVENT',
            success=True
        )
        
        return render_template('admin/events.html', events=events, search=search, status_filter=status_filter)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_EVENTS_ERROR',
            resource_type='EVENT',
            success=False,
            error_message=str(e)
        )
        flash('Error loading events', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/content')
@admin_required
@admin_permission_required('manage_content')
def admin_content():
    """Admin content management page"""
    try:
        log_admin_action(
            action='VIEW_CONTENT',
            resource_type='CONTENT',
            success=True
        )
        
        return render_template('admin/content.html')
    
    except Exception as e:
        log_admin_action(
            action='VIEW_CONTENT_ERROR',
            resource_type='CONTENT',
            success=False,
            error_message=str(e)
        )
        flash('Error loading content management', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/roles')
@admin_required
@admin_permission_required('manage_roles')
def admin_roles():
    """Admin role management page"""
    try:
        roles = AdminRole.query.all()
        
        log_admin_action(
            action='VIEW_ROLES',
            resource_type='ROLE',
            success=True
        )
        
        return render_template('admin/roles.html', roles=roles)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_ROLES_ERROR',
            resource_type='ROLE',
            success=False,
            error_message=str(e)
        )
        flash('Error loading roles', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/profile')
@admin_required
def admin_profile():
    """Admin profile page"""
    try:
        log_admin_action(
            action='VIEW_PROFILE',
            resource_type='PROFILE',
            success=True
        )
        
        return render_template('admin/profile.html')
    
    except Exception as e:
        log_admin_action(
            action='VIEW_PROFILE_ERROR',
            resource_type='PROFILE',
            success=False,
            error_message=str(e)
        )
        flash('Error loading profile', 'error')
        return redirect(url_for('admin_users'))

## Admin analytics routes removed

# Analytics helper functions
def get_analytics_data():
    """Get analytics data for admin dashboard"""
    try:
        # Basic counts
        total_users = User.query.count()
        total_ngos = NGO.query.count()
        total_events = Event.query.count()
        total_donations = db.session.query(db.func.sum(Donor.donation_amount)).scalar() or 0
        
        # User growth (last 30 days)
        from datetime import datetime, timedelta
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_users = User.query.filter(User.created_at >= thirty_days_ago).count()
        user_growth_rate = (recent_users / total_users * 100) if total_users > 0 else 0
        
        # Event participation rate
        total_volunteers = Volunteer.query.count()
        event_participation_rate = (total_volunteers / total_users * 100) if total_users > 0 else 0
        
        # Donation conversion rate
        donors = Donor.query.distinct(Donor.user_id).count()
        donation_conversion_rate = (donors / total_users * 100) if total_users > 0 else 0
        
        # Volunteer retention rate (simplified)
        volunteer_retention_rate = 85.0  # Placeholder
        
        # User roles distribution
        from sqlalchemy import func
        role_counts = db.session.query(User.role, func.count(User.id)).group_by(User.role).all()
        role_labels = [role.title() for role, _ in role_counts]
        role_data = [count for _, count in role_counts]
        
        # Registration trends (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        registration_data = []
        registration_labels = []
        for i in range(7):
            date = seven_days_ago + timedelta(days=i)
            next_date = date + timedelta(days=1)
            day_users = User.query.filter(User.created_at >= date, User.created_at < next_date).count()
            registration_data.append(day_users)
            registration_labels.append(date.strftime('%a'))
        
        # Activity data (last 7 days)
        login_activity = []
        event_activity = []
        donation_activity = []
        activity_labels = []
        
        for i in range(7):
            date = seven_days_ago + timedelta(days=i)
            next_date = date + timedelta(days=1)
            
            # Logins (approximated by users with last_login in this period)
            day_logins = User.query.filter(User.last_login >= date, User.last_login < next_date).count()
            login_activity.append(day_logins)
            
            # Events created
            day_events = Event.query.filter(Event.created_at >= date, Event.created_at < next_date).count()
            event_activity.append(day_events)
            
            # Donations
            day_donations = Donor.query.filter(Donor.created_at >= date, Donor.created_at < next_date).count()
            donation_activity.append(day_donations)
            
            activity_labels.append(date.strftime('%a'))
        
        # Top NGOs by activity
        top_ngos_data = db.session.query(
            NGO.organization_name,
            func.count(Event.id).label('event_count'),
            func.avg(Event.max_volunteers).label('volunteer_count'),
            func.avg(Event.rating).label('avg_rating')
        ).join(Event, NGO.id == Event.ngo_id).group_by(NGO.id).order_by(func.desc('event_count')).limit(5).all()
        
        top_ngos = []
        for ngo in top_ngos_data:
            top_ngos.append({
                'name': ngo.organization_name,
                'event_count': ngo.event_count,
                'volunteer_count': int(ngo.volunteer_count or 0),
                'avg_rating': float(ngo.avg_rating or 0)
            })
        
        # Recent activities
        recent_activities = AdminAuditLog.query.order_by(AdminAuditLog.timestamp.desc()).limit(10).all()
        activities = []
        for activity in recent_activities:
            activities.append({
                'description': f"{activity.action.replace('_', ' ').title()}",
                'user_name': f"{activity.admin.first_name} {activity.admin.last_name}",
                'timestamp': activity.timestamp,
                'icon': 'user' if 'user' in activity.action else 'cog' if 'setting' in activity.action else 'chart-bar'
            })
        
        return {
            'total_users': total_users,
            'total_ngos': total_ngos,
            'total_events': total_events,
            'total_donations': total_donations,
            'user_growth_rate': user_growth_rate,
            'event_participation_rate': event_participation_rate,
            'donation_conversion_rate': donation_conversion_rate,
            'volunteer_retention_rate': volunteer_retention_rate,
            'role_labels': role_labels,
            'role_data': role_data,
            'registration_labels': registration_labels,
            'registration_data': registration_data,
            'activity_labels': activity_labels,
            'login_activity': login_activity,
            'event_activity': event_activity,
            'donation_activity': donation_activity,
            'top_ngos': top_ngos,
            'recent_activities': activities
        }
    except Exception as e:
        app.logger.error(f"Error getting analytics data: {str(e)}")
        return {
            'total_users': 0,
            'total_ngos': 0,
            'total_events': 0,
            'total_donations': 0,
            'user_growth_rate': 0,
            'event_participation_rate': 0,
            'donation_conversion_rate': 0,
            'volunteer_retention_rate': 0,
            'role_labels': [],
            'role_data': [],
            'registration_labels': [],
            'registration_data': [],
            'activity_labels': [],
            'login_activity': [],
            'event_activity': [],
            'donation_activity': [],
            'top_ngos': [],
            'recent_activities': []
        }

def get_user_growth_data():
    """Get user growth data for charts"""
    from sqlalchemy import func
    
    # Get user registrations by month for the last 12 months
    user_data = db.session.query(
        func.date_format(User.created_at, '%Y-%m').label('month'),
        func.count(User.id).label('count')
    ).filter(
        User.created_at >= datetime.utcnow() - timedelta(days=365)
    ).group_by('month').order_by('month').all()
    
    return [{'month': item.month, 'count': item.count} for item in user_data]

def get_ngo_categories_data():
    """Get NGO categories distribution"""
    from sqlalchemy import func
    
    category_data = db.session.query(
        NGO.category,
        func.count(NGO.id).label('count')
    ).group_by(NGO.category).all()
    
    return [{'category': item.category or 'Unknown', 'count': item.count} for item in category_data]

def get_event_types_data():
    """Get event types distribution"""
    from sqlalchemy import func
    
    type_data = db.session.query(
        Event.category,
        func.count(Event.id).label('count')
    ).group_by(Event.category).all()
    
    return [{'type': item.category, 'count': item.count} for item in type_data]

def get_donation_trends_data():
    """Get donation trends data"""
    from sqlalchemy import func
    
    donation_data = db.session.query(
        func.date_format(Donor.created_at, '%Y-%m').label('month'),
        func.count(Donor.id).label('count'),
        func.sum(Donor.donation_amount).label('total')
    ).filter(
        Donor.created_at >= datetime.utcnow() - timedelta(days=365)
    ).group_by('month').order_by('month').all()
    
    return [{'month': item.month, 'count': item.count, 'total': float(item.total or 0)} for item in donation_data]

def get_user_roles_distribution():
    """Get user roles distribution"""
    from sqlalchemy import func
    
    role_data = db.session.query(
        User.role,
        func.count(User.id).label('count')
    ).group_by(User.role).all()
    
    return [{'role': item.role, 'count': item.count} for item in role_data]

def get_platform_usage_data():
    """Get platform usage statistics"""
    return {
        'total_page_views': 0,  # Will implement with analytics
        'unique_visitors': User.query.filter(User.last_login >= datetime.utcnow() - timedelta(days=30)).count(),
        'avg_session_duration': '15:30',  # Will implement with analytics
        'bounce_rate': '45%'  # Will implement with analytics
    }

# Additional admin routes
@app.route('/admin/users/<int:user_id>/delete', methods=['DELETE'])
@admin_required
@admin_permission_required('delete_users')
@rate_limit_admin_requests(max_requests=10, window_minutes=60)
@validate_admin_input({
    'user_id': {'type': 'integer', 'required': True}
})
def delete_user(user_id):
    """Delete a user"""
    try:
        user = User.query.get_or_404(user_id)
        if user.role == 'admin':
            return jsonify({'success': False, 'message': 'Cannot delete admin users'}), 400
            
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'User {user.email} has been deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/users/<int:user_id>')
@admin_required
@admin_permission_required('manage_users')
def admin_user_profile(user_id):
    """View a user's profile (admin)"""
    try:
        user = User.query.get_or_404(user_id)
        return render_template('admin/user_profile.html', user=user)
    except Exception as e:
        flash('Error loading user profile', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/ngos/<int:ngo_id>')
@admin_required
@admin_permission_required('manage_ngos')
def admin_ngo_profile(ngo_id):
    """View NGO profile in admin panel"""
    try:
        ngo = NGO.query.get_or_404(ngo_id)
        return render_template('admin/ngo_profile.html', ngo=ngo)
    except Exception as e:
        flash('Error loading NGO profile', 'error')
        return redirect(url_for('admin_ngos'))

@app.route('/admin/ngos/<int:ngo_id>/approve', methods=['POST'])
@admin_required
@admin_permission_required('manage_ngos')
@rate_limit_admin_requests(max_requests=20, window_minutes=60)
def approve_ngo(ngo_id):
    """Approve/verify an NGO"""
    try:
        ngo = NGO.query.get_or_404(ngo_id)
        ngo.is_verified = True
        db.session.commit()
        wants_json = request.is_json or \
            request.headers.get('Content-Type', '').startswith('application/json') or \
            'application/json' in (request.headers.get('Accept', '') or '')
        if wants_json:
            return jsonify({'success': True, 'message': 'NGO verified successfully'})
        else:
            flash('NGO verified successfully', 'success')
            return redirect(url_for('admin_ngo_profile', ngo_id=ngo_id))
    except Exception as e:
        db.session.rollback()
        wants_json = request.is_json or \
            request.headers.get('Content-Type', '').startswith('application/json') or \
            'application/json' in (request.headers.get('Accept', '') or '')
        if wants_json:
            return jsonify({'success': False, 'message': str(e)}), 500
        else:
            flash('Error approving NGO', 'error')
            return redirect(url_for('admin_ngo_profile', ngo_id=ngo_id))

@app.route('/admin/ngos/<int:ngo_id>/toggle-status', methods=['POST'])
@admin_required
@admin_permission_required('manage_ngos')
@rate_limit_admin_requests(max_requests=20, window_minutes=60)
def toggle_ngo_status(ngo_id):
    """Toggle NGO verification status"""
    try:
        ngo = NGO.query.get_or_404(ngo_id)
        # Ignore incoming status; simply flip verification flag for simplicity
        ngo.is_verified = not bool(ngo.is_verified)
        db.session.commit()
        state = 'verified' if ngo.is_verified else 'unverified'
        wants_json = request.is_json or \
            request.headers.get('Content-Type', '').startswith('application/json') or \
            'application/json' in (request.headers.get('Accept', '') or '')
        if wants_json:
            return jsonify({'success': True, 'message': f'NGO is now {state}', 'is_verified': bool(ngo.is_verified)})
        else:
            flash(f'NGO is now {state}', 'success')
            return redirect(url_for('admin_ngo_profile', ngo_id=ngo_id))
    except Exception as e:
        db.session.rollback()
        wants_json = request.is_json or \
            request.headers.get('Content-Type', '').startswith('application/json') or \
            'application/json' in (request.headers.get('Accept', '') or '')
        if wants_json:
            return jsonify({'success': False, 'message': str(e)}), 500
        else:
            flash('Error updating NGO status', 'error')
            return redirect(url_for('admin_ngo_profile', ngo_id=ngo_id))

@app.route('/admin/ngos/<int:ngo_id>/delete', methods=['DELETE'])
@admin_required
@admin_permission_required('manage_ngos')
@rate_limit_admin_requests(max_requests=10, window_minutes=60)
def delete_ngo(ngo_id):
    """Delete an NGO"""
    try:
        ngo = NGO.query.get_or_404(ngo_id)
        db.session.delete(ngo)
        db.session.commit()
        wants_json = request.is_json or \
            request.headers.get('Content-Type', '').startswith('application/json') or \
            'application/json' in (request.headers.get('Accept', '') or '')
        if wants_json:
            return jsonify({'success': True, 'message': f'NGO {ngo.organization_name} has been deleted'})
        else:
            flash(f'NGO {ngo.organization_name} has been deleted', 'success')
            return redirect(url_for('admin_ngos'))
    except Exception as e:
        db.session.rollback()
        wants_json = request.is_json or \
            request.headers.get('Content-Type', '').startswith('application/json') or \
            'application/json' in (request.headers.get('Accept', '') or '')
        if wants_json:
            return jsonify({'success': False, 'message': str(e)}), 500
        else:
            flash('Error deleting NGO', 'error')
            return redirect(url_for('admin_ngos'))

@app.route('/admin/add-user', methods=['POST'])
@admin_required
@admin_permission_required('create_users')
@rate_limit_admin_requests(max_requests=15, window_minutes=60)
@validate_admin_input({
    'first_name': {'required': True, 'min_length': 1, 'max_length': 50, 'pattern': r'^[a-zA-Z\s]+$'},
    'last_name': {'required': True, 'min_length': 1, 'max_length': 50, 'pattern': r'^[a-zA-Z\s]+$'},
    'email': {'required': True, 'type': 'email', 'max_length': 120},
    'role': {'required': True, 'pattern': r'^(ngo|volunteer|donor)$'},
    'phone': {'max_length': 20, 'pattern': r'^\+?[\d\s\-\(\)]+$'}
})
def admin_add_user():
    """Create a new user"""
    try:
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        role = request.form.get('role')
        phone = request.form.get('phone')
        
        # Validate input
        if not all([first_name, last_name, email, role]):
            flash('All required fields must be filled', 'error')
            return redirect(url_for('admin_users'))
            
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User with this email already exists', 'error')
            return redirect(url_for('admin_users'))
            
        # Generate random password
        import secrets
        import string
        password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        
        # Create new user
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            role=role,
            phone=phone,
            is_verified=True,
            is_active=True
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        # Send welcome email with password (in production)
        flash(f'User created successfully. Temporary password: {password}', 'success')
        return redirect(url_for('admin_users'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating user: {str(e)}', 'error')
        return redirect(url_for('admin_users'))

 

if __name__ == '__main__':
    print("Starting NGO Connect Platform...")
    try:
        with app.app_context():
            db.create_all()
        print("Starting server on http://127.0.0.1:5000")
        # Use debug=False for production, debug=True for development
        debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        socketio.run(app, host='127.0.0.1', port=5000, debug=debug_mode)
    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()
