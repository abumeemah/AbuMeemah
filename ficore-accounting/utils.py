import re
import os
import logging
from datetime import datetime, date
from flask import flash, request, redirect, url_for, current_app, g, session
from flask_login import current_user
from functools import wraps
from translations import trans_function
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from gridfs import GridFS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mailman import Mail

logger = logging.getLogger(__name__)

# Initialize limiter and mail as singletons
_limiter = None
_mail = None

def get_limiter(app):
    """Get or initialize Flask-Limiter instance."""
    global _limiter
    if _limiter is None:
        try:
            storage_uri = app.config.get('MONGO_URI', 'memory://')
            _limiter = Limiter(
                app=app,
                key_func=get_remote_address,
                default_limits=["1000 per day", "50 per hour"],
                storage_uri=storage_uri,
                storage_options={}
            )
            logger.info(f"Flask-Limiter initialized with storage: {storage_uri}")
        except Exception as e:
            logger.error(f"Failed to initialize Flask-Limiter with MongoDB: {str(e)}")
            _limiter = Limiter(
                app=app,
                key_func=get_remote_address,
                default_limits=["1000 per day", "50 per hour"],
                storage_uri="memory://"
            )
            logger.warning("Flask-Limiter using in-memory storage as fallback")
    return _limiter

def get_mail(app):
    """Get or initialize Flask-Mailman instance."""
    global _mail
    if _mail is None:
        try:
            _mail = Mail(app)
            logger.info("Flask-Mailman initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Flask-Mailman: {str(e)}")
            raise RuntimeError(f"Flask-Mailman initialization failed: {str(e)}")
    return _mail

def get_user_query(user_id: str) -> dict:
    """Generate MongoDB query for user by ID."""
    return {'_id': user_id}

def is_admin():
    """Check if current user is an admin."""
    return current_user.is_authenticated and current_user.role == 'admin'

def is_valid_email(email):
    """Validate email address format."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def requires_role(role):
    """Decorator to restrict access to a specific role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if is_admin():
                return f(*args, **kwargs)
            if not current_user.is_authenticated:
                flash(trans_function('login_required', default='Please log in to access this page'), 'danger')
                return redirect(url_for('users_blueprint.login'))
            if current_user.role != role:
                flash(trans_function('forbidden_access', default='Access denied'), 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_coin_balance(required_coins):
    """Check if user has sufficient coin balance."""
    if is_admin():
        return True
    try:
        db = get_mongo_db()
        user = db.users.find_one({'_id': current_user.id})
        if not user:
            logger.error(f"User {current_user.id} not found")
            return False
        balance = user.get('coin_balance', 0)
        if balance < required_coins:
            logger.warning(f"Insufficient coins for user {current_user.id}: {balance} < {required_coins}")
            return False
        return True
    except Exception as e:
        logger.error(f"Error checking coin balance for user {current_user.id}: {str(e)}")
        return False

def sanitize_input(value):
    """Sanitize input to prevent XSS and injection attacks."""
    if not isinstance(value, str):
        return value
    return re.sub(r'<[^>]+>', '', value).strip()

def generate_invoice_number(user_id):
    """Generate unique invoice number based on user ID and timestamp."""
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return f"INV-{user_id[:8]}-{timestamp}"

def format_currency(value):
    """Format a value as currency with appropriate symbol and locale."""
    try:
        value = float(value)
        locale = session.get('lang', 'en')
        symbol = '₦'
        if value.is_integer():
            return f"{symbol}{int(value):,}"
        return f"{symbol}{value:,.2f}"
    except (TypeError, ValueError) as e:
        logger.warning(f"Error formatting currency {value}: {str(e)}")
        return str(value)

def format_date(value):
    """Format a date value based on locale."""
    try:
        locale = session.get('lang', 'en')
        format_str = '%Y-%m-%d' if locale == 'en' else '%d-%m-%Y'
        if isinstance(value, datetime):
            return value.strftime(format_str)
        elif isinstance(value, date):
            return value.strftime(format_str)
        elif isinstance(value, str):
            parsed = datetime.strptime(value, '%Y-%m-%d').date()
            return parsed.strftime(format_str)
        return str(value)
    except Exception as e:
        logger.warning(f"Error formatting date {value}: {str(e)}")
        return str(value)

def get_mongo_db():
    """Get MongoDB database connection for the current request."""
    if 'mongo_db' not in g:
        try:
            if 'mongo_client' not in current_app.extensions:
                logger.error("MongoDB client not initialized in application")
                raise RuntimeError("MongoDB client not initialized")
            g.mongo_client = current_app.extensions['mongo_client']
            db_name = current_app.config.get('SESSION_MONGODB_DB', 'ficore_accounting')
            g.db = g.mongo_client[db_name]
            g.gridfs = GridFS(g.db)
            current_app.extensions['pymongo'] = g.db
            current_app.extensions['gridfs'] = g.gridfs
            logger.debug(f"Using MongoClient: {g.mongo_client}")
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            raise RuntimeError(f"Cannot connect to MongoDB: {str(e)}")
        except Exception as e:
            logger.error(f"Error accessing MongoDB connection: {str(e)}")
            raise RuntimeError(f"MongoDB access failed: {str(e)}")
    return g.db

def close_mongo_db(error=None):
    """Clean up MongoDB request-specific resources."""
    g.pop('mongo_db', None)
    g.pop('gridfs', None)
    logger.debug("MongoDB request context cleaned up")
