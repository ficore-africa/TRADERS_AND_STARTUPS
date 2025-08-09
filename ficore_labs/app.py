import os
import sys
import logging
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from flask import (
    Flask, jsonify, request, render_template, redirect, url_for, flash,
    make_response, has_request_context, session, Response, current_app, abort
)
from flask_session import Session
from flask_cors import CORS
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
from functools import wraps
from pymongo import MongoClient
import certifi
from flask_login import LoginManager, login_required, current_user, UserMixin, logout_user
from flask_wtf.csrf import CSRFProtect
from flask_babel import Babel
from flask_compress import Compress
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from users.routes import get_post_login_redirect
from utils import (
    get_mongo_db, logger, initialize_tools_with_urls, generate_tools_with_urls,
    TRADER_TOOLS, TRADER_NAV, STARTUP_TOOLS, STARTUP_NAV, ADMIN_TOOLS, ADMIN_NAV,
    _TRADER_NAV, _STARTUP_NAV, _ADMIN_NAV, _TRADER_TOOLS, _STARTUP_TOOLS, _ADMIN_TOOLS, format_date
)
from translations import register_translation, trans, get_translations, get_all_translations, get_module_translations

# Load environment variables
load_dotenv()

# Initialize extensions
login_manager = LoginManager()
flask_session = Session()
csrf = CSRFProtect()
babel = Babel()
compress = Compress()
limiter = Limiter(key_func=get_remote_address, default_limits=['200 per day', '50 per hour'], storage_uri='memory://')

# Decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            logger.warning("Unauthorized access attempt to admin route", extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return redirect(url_for('users.login'))
        if current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            logger.warning(f"Non-admin user {current_user.id} attempted access", extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def custom_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            logger.info("Redirecting unauthenticated user to login", extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return redirect(url_for('users.login', next=request.url))
        if not current_user.is_trial_active():
            logger.info(f"User {current_user.id} trial expired, redirecting to subscription", extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return redirect(url_for('subscribe_bp.subscribe'))
        return f(*args, **kwargs)
    return decorated_function

def ensure_session_id(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if 'sid' not in session or not session.get('sid'):
                session['sid'] = str(uuid.uuid4())
                session['is_anonymous'] = not current_user.is_authenticated
                session['last_activity'] = datetime.now(timezone.utc).isoformat()
                session.modified = True
                logger.info(f'New session ID generated: {session["sid"]}', extra={'session_id': session["sid"], 'ip_address': request.remote_addr})
            else:
                session_id = session.get('sid')
                db = get_mongo_db()
                mongo_session = db.sessions.find_one({'_id': session_id})
                if not mongo_session and current_user.is_authenticated:
                    logger.info(f'Invalid session {session_id} for user {current_user.id}, logging out', extra={'session_id': session_id, 'ip_address': request.remote_addr})
                    logout_user()
                    session.clear()
                    session['lang'] = session.get('lang', 'en')
                    session['sid'] = str(uuid.uuid4())
                    session['is_anonymous'] = True
                    session['last_activity'] = datetime.now(timezone.utc).isoformat()
                    flash('Your session has timed out.', 'warning')
                    response = make_response(redirect(url_for('users.login')))
                    response.set_cookie(
                        current_app.config['SESSION_COOKIE_NAME'],
                        '',
                        expires=0,
                        httponly=True,
                        secure=current_app.config.get('SESSION_COOKIE_SECURE', True)
                    )
                    return response
            session['last_activity'] = datetime.now(timezone.utc).isoformat()
            session.modified = True
        except Exception as e:
            logger.error(f'Session operation failed: {str(e)}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash('An error occurred with your session. Please log in again.', 'danger')
            response = make_response(redirect(url_for('users.login')))
            response.set_cookie(
                current_app.config['SESSION_COOKIE_NAME'],
                '',
                expires=0,
                httponly=True,
                secure=current_app.config.get('SESSION_COOKIE_SECURE', True)
            )
            return response
        return f(*args, **kwargs)
    return decorated_function

def setup_logging(app):
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s [session: %(session_id)s, role: %(user_role)s, ip: %(ip_address)s]'))
    root_logger = logging.getLogger('bizcore_app')
    root_logger.handlers = []
    root_logger.addHandler(handler)
    flask_logger = logging.getLogger('flask')
    werkzeug_logger = logging.getLogger('werkzeug')
    pymongo_logger = logging.getLogger('pymongo')
    flask_logger.handlers = []
    werkzeug_logger.handlers = []
    pymongo_logger.handlers = []
    flask_logger.addHandler(handler)
    werkzeug_logger.addHandler(handler)
    pymongo_logger.addHandler(handler)
    flask_logger.setLevel(logging.INFO)
    werkzeug_logger.setLevel(logging.INFO)
    pymongo_logger.setLevel(logging.INFO)
    logger.info('Logging setup complete', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})

def check_mongodb_connection(app):
    try:
        client = app.extensions['mongo']
        client.admin.command('ping')
        logger.info('MongoDB connection verified', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
        return True
    except Exception as e:
        logger.error(f'MongoDB connection failed: {str(e)}', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
        return False

def setup_session(app):
    try:
        with app.app_context():
            if check_mongodb_connection(app):
                app.config['SESSION_TYPE'] = 'mongodb'
                app.config['SESSION_MONGODB'] = app.extensions['mongo']
                app.config['SESSION_MONGODB_DB'] = 'bizdb'
                app.config['SESSION_MONGODB_COLLECT'] = 'sessions'
                app.config['SESSION_PERMANENT'] = False
                app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
                app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
                app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV', 'development') == 'production'
                app.config['SESSION_COOKIE_HTTPONLY'] = True
                app.config['SESSION_COOKIE_NAME'] = 'bizcore_session'
                flask_session.init_app(app)
                db = app.extensions['mongo']['bizdb']
                db.sessions.create_index("created_at", expireAfterSeconds=1800)
                logger.info(f'Session configured: type={app.config["SESSION_TYPE"]}', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
                return
            logger.error('MongoDB connection failed, falling back to filesystem session', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
            app.config['SESSION_TYPE'] = 'filesystem'
            flask_session.init_app(app)
            logger.info('Session configured with filesystem fallback', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
    except Exception as e:
        logger.error(f'Failed to configure session: {str(e)}', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
        app.config['SESSION_TYPE'] = 'filesystem'
        flask_session.init_app(app)
        logger.info('Session configured with filesystem fallback', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})

class User(UserMixin):
    def __init__(self, id, email, display_name=None, role='trader', is_trial=True, trial_start=None, trial_end=None, is_subscribed=False, subscription_plan=None, subscription_start=None, subscription_end=None):
        self.id = id
        self.email = email
        self.display_name = display_name or id
        self.role = role
        self.is_trial = is_trial
        self.trial_start = trial_start or datetime.now(timezone.utc)
        self.trial_end = trial_end or (datetime.now(timezone.utc) + timedelta(days=30))
        self.is_subscribed = is_subscribed
        self.subscription_plan = subscription_plan
        self.subscription_start = subscription_start
        self.subscription_end = subscription_end

    def get(self, key, default=None):
        try:
            with current_app.app_context():
                user = current_app.extensions['mongo']['bizdb'].users.find_one({'_id': self.id})
                return user.get(key, default) if user else default
        except Exception as e:
            logger.error(f'Error fetching user data for {self.id}: {str(e)}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return default

    @property
    def is_active(self):
        try:
            with current_app.app_context():
                user = current_app.extensions['mongo']['bizdb'].users.find_one({'_id': self.id})
                return user.get('is_active', True) if user else False
        except Exception as e:
            logger.error(f'Error checking active status for user {self.id}: {str(e)}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return False

    def get_id(self):
        return str(self.id)

    def is_trial_active(self):
        if self.is_subscribed and self.subscription_end:
            subscription_end_aware = (
                self.subscription_end.replace(tzinfo=timezone.utc)
                if self.subscription_end.tzinfo is None
                else self.subscription_end
            )
            return datetime.now(timezone.utc) <= subscription_end_aware
        if self.is_trial and self.trial_end:
            trial_end_aware = (
                self.trial_end.replace(tzinfo=timezone.utc)
                if self.trial_end.tzinfo is None
                else self.trial_end
            )
            return datetime.now(timezone.utc) <= trial_end_aware
        return False

    @property
    def is_admin(self):
        return self.role == 'admin'

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Load configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    if not app.config['SECRET_KEY']:
        logger.error('SECRET_KEY environment variable is not set', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
        raise ValueError('SECRET_KEY must be set')

    app.config['MONGO_URI'] = os.getenv('MONGO_URI')
    if not app.config['MONGO_URI']:
        logger.error('MONGO_URI environment variable is not set', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
        raise ValueError('MONGO_URI must be set')

    # Configure upload folder for KYC
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'Uploads')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Add URL generation configurations
    app.config['SERVER_NAME'] = os.getenv('SERVER_NAME', 'ficore-records.onrender.com')
    app.config['APPLICATION_ROOT'] = os.getenv('APPLICATION_ROOT', '/')
    app.config['PREFERRED_URL_SCHEME'] = os.getenv('PREFERRED_URL_SCHEME', 'https')

    # Initialize MongoDB
    try:
        client = MongoClient(
            app.config['MONGO_URI'],
            serverSelectionTimeoutMS=5000,
            tls=True,
            tlsCAFile=certifi.where(),
            maxPoolSize=50,
            minPoolSize=5
        )
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['mongo'] = client
        client.admin.command('ping')
        logger.info('MongoDB client initialized successfully', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
    except Exception as e:
        logger.error(f'MongoDB connection failed: {str(e)}', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
        raise RuntimeError(f'Failed to connect to MongoDB: {str(e)}')

    # Initialize extensions
    setup_logging(app)
    compress init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    babel.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'users.login'
    setup_session(app)

    # Register translation function
    register_translation(app)

    # User loader
    @login_manager.user_loader
    def load_user(user_id):
        try:
            with app.app_context():
                user = app.extensions['mongo']['bizdb'].users.find_one({'_id': user_id})
                if not user:
                    return None
                trial_start = user.get('trial_start')
                trial_end = user.get('trial_end')
                subscription_start = user.get('subscription_start')
                subscription_end = user.get('subscription_end')
                if trial_start and trial_start.tzinfo is None:
                    trial_start = trial_start.replace(tzinfo=ZoneInfo("UTC"))
                if trial_end and trial_end.tzinfo is None:
                    trial_end = trial_end.replace(tzinfo=ZoneInfo("UTC"))
                if subscription_start and subscription_start.tzinfo is None:
                    subscription_start = subscription_start.replace(tzinfo=ZoneInfo("UTC"))
                if subscription_end and subscription_end.tzinfo is None:
                    subscription_end = subscription_end.replace(tzinfo=ZoneInfo("UTC"))
                return User(
                    id=user['_id'],
                    email=user['email'],
                    display_name=user.get('display_name', user['_id']),
                    role=user.get('role', 'trader'),
                    is_trial=user.get('is_trial', True),
                    trial_start=trial_start,
                    trial_end=trial_end,
                    is_subscribed=user.get('is_subscribed', False),
                    subscription_plan=user.get('subscription_plan'),
                    subscription_start=subscription_start,
                    subscription_end=subscription_end
                )
        except Exception as e:
            logger.error(f"Error loading user {user_id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return None

    # Initialize database
    try:
        with app.app_context():
            from models import initialize_app_data
            initialize_app_data(app)
            logger.info('Database initialized successfully', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
    except Exception as e:
        logger.error(f'Error in database initialization: {str(e)}', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
        raise

    # Register blueprints
    from users.routes import users_bp
    from debtors.routes import debtors_bp
    from creditors.routes import creditors_bp
    from payments.routes import payments_bp
    from receipts.routes import receipts_bp
    from reports.routes import reports_bp
    from admin.routes import admin_bp
    from dashboard.routes import dashboard_bp
    from general.routes import general_bp
    from notifications.routes import notifications
    from business.routes import business
    from funds.routes import funds_bp
    from forecasts.routes import forecasts_bp
    from investor_reports.routes import investor_reports_bp
    from subscribe.routes import subscribe_bp
    from kyc.routes import kyc_bp
    from settings.routes import settings_bp

    app.register_blueprint(users_bp, url_prefix='/users')
    app.register_blueprint(debtors_bp, url_prefix='/debtors')
    app.register_blueprint(creditors_bp, url_prefix='/creditors')
    app.register_blueprint(payments_bp, url_prefix='/payments')
    app.register_blueprint(receipts_bp, url_prefix='/receipts')
    app.register_blueprint(reports_bp, url_prefix='/reports')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(funds_bp, url_prefix='/funds')
    app.register_blueprint(forecasts_bp, url_prefix='/forecasts')
    app.register_blueprint(investor_reports_bp, url_prefix='/investor-reports')
    app.register_blueprint(subscribe_bp, url_prefix='/subscribe')
    app.register_blueprint(general_bp, url_prefix='/general')
    app.register_blueprint(business, url_prefix='/business')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(notifications)
    app.register_blueprint(kyc_bp, url_prefix='/kyc')
    app.register_blueprint(settings_bp, url_prefix='/settings')
    logger.info('Registered all blueprints including KYC and Settings', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})

    # Initialize tools and navigation after blueprints
    @app.before_request
    def initialize_navigation():
        with app.app_context():
            try:
                initialize_tools_with_urls(app)
                logger.info('Navigation initialized after blueprint registration', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            except Exception as e:
                logger.error(f'Failed to initialize navigation: {str(e)}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                raise

    # Ensure session['lang'] is set early and respected
    @app.before_request
    def ensure_lang_in_session():
        if 'lang' not in session:
            session['lang'] = 'en'  # Default language

    # Define format_currency filter
    def format_currency(value):
        try:
            return "₦{:,.2f}".format(float(value))
        except (ValueError, TypeError) as e:
            logger.warning(f'Error formatting currency {value}: {str(e)}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return str(value)

    # Register format_currency filter and global
    app.jinja_env.filters['format_currency'] = format_currency
    app.jinja_env.globals['format_currency'] = format_currency

    # Define format_date filter
    @app.template_filter('format_date')
    def format_date_wrapper(value):
        try:
            return format_date(value, lang=session.get('lang', 'en'), format_type='short')
        except Exception as e:
            logger.warning(f'Error formatting date {value}: {str(e)}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return str(value)

    # Register format_date as global
    app.jinja_env.globals['format_date'] = format_date_wrapper

    # Define is_trial_expired global
    def is_trial_expired(trial_end, is_trial=True, is_subscribed=False, subscription_end=None):
        try:
            if is_subscribed and subscription_end:
                subscription_end_aware = (
                    subscription_end.replace(tzinfo=timezone.utc)
                    if subscription_end.tzinfo is None
                    else subscription_end
                )
                return datetime.now(timezone.utc) > subscription_end_aware
            if is_trial and trial_end:
                trial_end_aware = (
                    trial_end.replace(tzinfo=timezone.utc)
                    if trial_end.tzinfo is None
                    else trial_end
                )
                return datetime.now(timezone.utc) > trial_end_aware
            return True  # Default to expired if no valid trial or subscription
        except Exception as e:
            logger.error(
                f"Error checking trial expiration: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr}
            )
            return True  # Default to expired if there's an error

    # Register is_trial_expired in Jinja globals
    app.jinja_env.globals['is_trial_expired'] = is_trial_expired
    logger.info("Registered is_trial_expired Jinja global", extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})

    # Set up Jinja globals
    app.jinja_env.globals.update(
        FACEBOOK_URL=app.config.get('FACEBOOK_URL', 'https://facebook.com/ficoreafrica'),
        TWITTER_URL=app.config.get('TWITTER_URL', 'https://x.com/ficoreafrica'),
        LINKEDIN_URL=app.config.get('LINKEDIN_URL', 'https://linkedin.com/company/ficoreafrica'),
        FEEDBACK_FORM_URL=app.config.get('FEEDBACK_FORM_URL', '#'),
        WAITLIST_FORM_URL=app.config.get('WAITLIST_FORM_URL', '#'),
        CONSULTANCY_FORM_URL=app.config.get('CONSULTANCY_FORM_URL', '#'),
        trans=trans,
        get_translations=get_translations,
        is_admin=lambda: current_user.is_admin if current_user.is_authenticated else False
    )

    # Template filters and context processors
    @app.template_filter('format_number')
    def format_number(value):
        try:
            if isinstance(value, (int, float)):
                return f'{float(value):,.2f}'
            return str(value)
        except (ValueError, TypeError) as e:
            logger.warning(f'Error formatting number {value}: {str(e)}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return str(value)

    @app.template_filter('format_datetime')
    def format_datetime(value):
        try:
            locale = session.get('lang', 'en')
            format_str = '%B %d, %Y, %I:%M %p' if locale == 'en' else '%d %B %Y, %I:%M %p'
            if isinstance(value, datetime):
                value_aware = value.replace(tzinfo=ZoneInfo("UTC")) if value.tzinfo is None else value
                return value_aware.strftime(format_str)
            return str(value)
        except Exception as e:
            logger.warning(f'Error formatting datetime {value}: {str(e)}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return str(value)

    @app.context_processor
    def inject_globals():
        def build_nav(nav_template):
            try:
                return generate_tools_with_urls(nav_template)
            except Exception as e:
                logger.error(f"Error building nav: {e}")
                return []
        nav = []
        tools = []
        if current_user.is_authenticated:
            role = getattr(current_user, 'role', None)
            if role == 'admin':
                nav = build_nav(_ADMIN_NAV)
                tools = build_nav(_ADMIN_TOOLS)
            elif role == 'startup':
                nav = build_nav(_STARTUP_NAV)
                tools = build_nav(_STARTUP_TOOLS)
            elif role == 'trader':
                nav = build_nav(_TRADER_NAV)
                tools = build_nav(_TRADER_TOOLS)
            else:
                nav = build_nav(_TRADER_NAV)
                tools = build_nav(_TRADER_TOOLS)
        return {
            'current_year': datetime.now(timezone.utc).year,
            'current_lang': session.get('lang', 'en'),
            'current_user': current_user if has_request_context() else None,
            'available_languages': [
                {'code': 'en', 'name': 'English'},
                {'code': 'ha', 'name': 'Hausa'}
            ],
            'navigation': nav,
            'tools': tools,
        }

    # Routes
    @app.route('/')
    @ensure_session_id
    def index():
        try:
            current_app.logger.info(
                f"Accessing root route - User: {current_user.id if current_user.is_authenticated else 'Anonymous'}, "
                f"Authenticated: {current_user.is_authenticated}, Session: {dict(session)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr}
            )
            if current_user.is_authenticated:
                return redirect(get_post_login_redirect(current_user.role))
            return redirect(url_for('general_bp.landing'))
        except Exception as e:
            current_app.logger.error(f"Error in root route: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('general_error', default='An error occurred'), 'danger')
            return render_template('error/500.html', error_message="Unable to process request.", title="Error"), 500

    @app.route('/health')
    @limiter.limit('10 per minute')
    def health():
        logger.info('Performing health check', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        status = {'status': 'healthy'}
        try:
            with app.app_context():
                app.extensions['mongo'].admin.command('ping')
            return jsonify(status), 200
        except Exception as e:
            logger.error(f'Health check failed: {str(e)}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            status['status'] = 'unhealthy'
            status['details'] = str(e)
            return jsonify(status), 500

    @app.route('/view-data')
    @login_required
    def view_data():
        try:
            db = get_mongo_db()
            records = db.records.find({'user_id': current_user.id})
            cashflows = db.cashflows.find({'user_id': current_user.id})
            return render_template('view_data.html', 
                                 records=list(records), 
                                 cashflows=list(cashflows),
                                 is_trial_active=current_user.is_trial_active())
        except Exception as e:
            logger.error(f'Error fetching data for user {current_user.id}: {str(e)}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash('Error fetching your data.', 'danger')
            return redirect(url_for('index'))

    @app.route('/set_language/<lang>', methods=['POST'])
    @ensure_session_id
    def set_language(lang):
        valid_langs = ['en', 'ha']
        lang = lang if lang in valid_langs else 'en'
        session['lang'] = lang
        session['last_activity'] = datetime.now(timezone.utc).isoformat()
        session.modified = True
        logger.info(f"Language set to {session['lang']} for session {session.get('sid', 'no-session-id')}", extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'success': True, 'lang': session['lang']})

    @app.errorhandler(404)
    def page_not_found(e):
        logger.error(f'Not found: {request.url}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return render_template('error/404.html', error=str(e)), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        logger.error(f'Server error: {str(e)}', extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return render_template('error/500.html', error=str(e)), 500

    @app.before_request
    def check_session_timeout():
        if request.path.startswith('/static/') or request.path == url_for('subscribe_bp.subscribe'):
            return
        if current_user.is_authenticated and 'last_activity' in session:
            last_activity = session.get('last_activity')
            if isinstance(last_activity, str):
                try:
                    last_activity = datetime.fromisoformat(last_activity.replace(' ', 'T'))
                    if last_activity.tzinfo is None:
                        last_activity = last_activity.replace(tzinfo=ZoneInfo("UTC"))
                except ValueError:
                    last_activity = datetime.now(timezone.utc)
                    session['last_activity'] = last_activity.isoformat()
            if (datetime.now(timezone.utc) - last_activity).total_seconds() > 1800:
                user_id = current_user.id
                sid = session.get('sid', 'no-session-id')
                logger.info(f"Session timeout for user {user_id}", extra={'session_id': sid, 'ip_address': request.remote_addr})
                logout_user()
                if current_app.config.get('SESSION_TYPE') == 'mongodb':
                    try:
                        db = get_mongo_db()
                        db.sessions.delete_one({'_id': sid})
                        logger.info(f"Deleted MongoDB session {sid} for user {user_id}", extra={'session_id': sid, 'ip_address': request.remote_addr})
                    except Exception as e:
                        logger.error(f"Failed to delete MongoDB session {sid}: {str(e)}", extra={'session_id': sid, 'ip_address': request.remote_addr})
                session.clear()
                session['lang'] = session.get('lang', 'en')
                session['sid'] = str(uuid.uuid4())
                session['is_anonymous'] = True
                session['last_activity'] = datetime.now(timezone.utc).isoformat()
                flash('Your session has timed out.', 'warning')
                response = make_response(redirect(url_for('users.login')))
                response.set_cookie(
                    current_app.config['SESSION_COOKIE_NAME'],
                    '',
                    expires=0,
                    httponly=True,
                    secure=current_app.config.get('SESSION_COOKIE_SECURE', True)
                )
                return response
        if current_user.is_authenticated:
            session['last_activity'] = datetime.now(timezone.utc).isoformat()
            session.modified = True

    return app

app = create_app()

if __name__ == '__main__':
    logger.info('Starting Flask application', extra={'session_id': 'none', 'user_role': 'none', 'ip_address': 'none'})
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
