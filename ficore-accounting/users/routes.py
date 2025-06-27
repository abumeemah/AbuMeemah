from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SubmitField, BooleanField, validators
from flask_login import login_required, current_user, login_user, logout_user
from pymongo import errors
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mailman import EmailMessage
import logging
import uuid
from datetime import datetime, timedelta
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date, is_valid_email, get_mongo_db, is_admin, get_mail, get_limiter
import re
import random
from itsdangerous import URLSafeTimedSerializer
import os

logger = logging.getLogger(__name__)

users_bp = Blueprint('users_blueprint', __name__, template_folder='templates/users')

USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,50}$')
PASSWORD_REGEX = re.compile(r'.{6,}')
PHONE_REGEX = re.compile(r'^\+?\d{10,15}$')

# Initialize limiter
limiter = get_limiter(current_app)

class LoginForm(FlaskForm):
    username = StringField(trans_function('username', default='Username'), [
        validators.DataRequired(message=trans_function('username_required', default='Username is required')),
        validators.Length(min=3, max=50, message=trans_function('username_length', default='Username must be between 3 and 50 characters')),
        validators.Regexp(USERNAME_REGEX, message=trans_function('username_format', default='Username must be alphanumeric with underscores'))
    ], render_kw={'class': 'form-control'})
    password = PasswordField(trans_function('password', default='Password'), [
        validators.DataRequired(message=trans_function('password_required', default='Password is required')),
        validators.Length(min=6, message=trans_function('password_length', default='Password must be at least 6 characters'))
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans_function('login', default='Login'), render_kw={'class': 'btn btn-primary w-100'})

class TwoFactorForm(FlaskForm):
    otp = StringField(trans_function('otp', default='One-Time Password'), [
        validators.DataRequired(message=trans_function('otp_required', default='OTP is required')),
        validators.Length(min=6, max=6, message=trans_function('otp_length', default='OTP must be 6 digits'))
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans_function('verify_otp', default='Verify OTP'), render_kw={'class': 'btn btn-primary w-100'})

class SignupForm(FlaskForm):
    username = StringField(trans_function('username', default='Username'), [
        validators.DataRequired(message=trans_function('username_required', default='Username is required')),
        validators.Length(min=3, max=50, message=trans_function('username_length', default='Username must be between 3 and 50 characters')),
        validators.Regexp(USERNAME_REGEX, message=trans_function('username_format', default='Username must be alphanumeric with underscores'))
    ], render_kw={'class': 'form-control'})
    email = StringField(trans_function('email', default='Email'), [
        validators.DataRequired(message=trans_function('email_required', default='Email is required')),
        validators.Email(message=trans_function('email_invalid', default='Invalid email address')),
        validators.Length(max=254),
        lambda form, field: is_valid_email(field.data) or validators.ValidationError(trans_function('email_domain_invalid', default='Invalid email domain'))
    ], render_kw={'class': 'form-control'})
    password = PasswordField(trans_function('password', default='Password'), [
        validators.DataRequired(message=trans_function('password_required', default='Password is required')),
        validators.Length(min=6, message=trans_function('password_length', default='Password must be at least 6 characters')),
        validators.Regexp(PASSWORD_REGEX, message=trans_function('password_format', default='Password must be at least 6 characters'))
    ], render_kw={'class': 'form-control'})
    role = SelectField(trans_function('role', default='Role'), choices=[
        ('personal', trans_function('personal', default='Personal')),
        ('trader', trans_function('trader', default='Trader')),
        ('agent', trans_function('agent', default='Agent'))
    ], validators=[validators.DataRequired(message=trans_function('role_required', default='Role is required'))], render_kw={'class': 'form-select'})
    language = SelectField(trans_function('language', default='Language'), choices=[
        ('en', trans_function('english', default='English')),
        ('ha', trans_function('hausa', default='Hausa'))
    ], validators=[validators.DataRequired(message=trans_function('language_required', default='Language is required'))], render_kw={'class': 'form-select'})
    submit = SubmitField(trans_function('signup', default='Sign Up'), render_kw={'class': 'btn btn-primary w-100'})

class ForgotPasswordForm(FlaskForm):
    email = StringField(trans_function('email', default='Email'), [
        validators.DataRequired(message=trans_function('email_required', default='Email is required')),
        validators.Email(message=trans_function('email_invalid', default='Invalid email address'))
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans_function('send_reset_link', default='Send Reset Link'), render_kw={'class': 'btn btn-primary w-100'})

class ResetPasswordForm(FlaskForm):
    password = PasswordField(trans_function('password', default='Password'), [
        validators.DataRequired(message=trans_function('password_required', default='Password is required')),
        validators.Length(min=6, message=trans_function('password_length', default='Password must be at least 6 characters')),
        validators.Regexp(PASSWORD_REGEX, message=trans_function('password_format', default='Password must be at least 6 characters'))
    ], render_kw={'class': 'form-control'})
    confirm_password = PasswordField(trans_function('confirm_password', default='Confirm Password'), [
        validators.DataRequired(message=trans_function('confirm_password_required', default='Confirm password is required')),
        validators.EqualTo('password', message=trans_function('passwords_must_match', default='Passwords must match')),
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans_function('reset_password', default='Reset Password'), render_kw={'class': 'btn btn-primary w-100'})
    
class BusinessSetupForm(FlaskForm):
    business_name = StringField(trans_function('business_name', default='Business Name'),
                               validators=[validators.DataRequired(message=trans_function('business_name_required', default='Business name is required')),
                                           validators.Length(min=1, max=255)],
                               render_kw={'class': 'form-control'})
    address = TextAreaField(trans_function('address', default='Address'),
                            validators=[validators.DataRequired(message=trans_function('address_required', default='Address is required')),
                                        validators.Length(max=500)],
                            render_kw={'class': 'form-control'})
    industry = SelectField(trans_function('industry', default='Industry'),
                          choices=[
                              ('retail', trans_function('retail', default='Retail')),
                              ('services', trans_function('services', default='Services')),
                              ('manufacturing', trans_function('manufacturing', default='Manufacturing')),
                              ('other', trans_function('other', default='Other'))
                          ],
                          validators=[validators.DataRequired(message=trans_function('industry_required', default='Industry is required'))],
                          render_kw={'class': 'form-control'})
    products_services = TextAreaField(trans_function('products_services', default='Products/Services'),
                                     validators=[validators.DataRequired(message=trans_function('products_services_required', default='Products/Services is required')),
                                                 validators.Length(max=500)],
                                     render_kw={'class': 'form-control'})
    phone_number = StringField(trans_function('phone_number', default='Phone Number'),
                              validators=[
                                  validators.DataRequired(message=trans_function('phone_number_required', default='Phone number is required')),
                                  validators.Regexp(PHONE_REGEX, message=trans_function('phone_number_format', default='Phone number must be 10-15 digits'))
                              ],
                              render_kw={'class': 'form-control'})
    language = SelectField(trans_function('language', default='Language'),
                          choices=[
                              ('en', trans_function('english', default='English')),
                              ('ha', trans_function('hausa', default='Hausa'))
                          ],
                          validators=[validators.DataRequired(message=trans_function('language_required', default='Language is required'))],
                          render_kw={'class': 'form-select'})
    terms = BooleanField(trans_function('terms', default='I accept the Terms and Conditions'),
                        validators=[validators.DataRequired(message=trans_function('terms_required', default='You must accept the terms'))],
                        render_kw={'class': 'form-check-input'})
    submit = SubmitField(trans_function('save_and_continue', default='Save and Continue'), render_kw={'class': 'btn btn-primary w-100'})
    back = SubmitField(trans_function('back', default='Back'), render_kw={'class': 'btn btn-secondary w-100 mt-2'})

class PersonalSetupForm(FlaskForm):
    first_name = StringField(trans_function('first_name', default='First Name'),
                            validators=[validators.DataRequired(message=trans_function('first_name_required', default='First name is required')),
                                        validators.Length(min=1, max=255)],
                            render_kw={'class': 'form-control'})
    last_name = StringField(trans_function('last_name', default='Last Name'),
                           validators=[validators.DataRequired(message=trans_function('last_name_required', default='Last name is required')),
                                       validators.Length(min=1, max=255)],
                           render_kw={'class': 'form-control'})
    phone_number = StringField(trans_function('phone_number', default='Phone Number'),
                              validators=[
                                  validators.DataRequired(message=trans_function('phone_number_required', default='Phone number is required')),
                                  validators.Regexp(PHONE_REGEX, message=trans_function('phone_number_format', default='Phone number must be 10-15 digits'))
                              ],
                              render_kw={'class': 'form-control'})
    address = TextAreaField(trans_function('address', default='Address'),
                           validators=[validators.DataRequired(message=trans_function('address_required', default='Address is required')),
                                       validators.Length(max=500)],
                           render_kw={'class': 'form-control'})
    language = SelectField(trans_function('language', default='Language'),
                          choices=[
                              ('en', trans_function('english', default='English')),
                              ('ha', trans_function('hausa', default='Hausa'))
                          ],
                          validators=[validators.DataRequired(message=trans_function('language_required', default='Language is required'))],
                          render_kw={'class': 'form-select'})
    terms = BooleanField(trans_function('terms', default='I accept the Terms and Conditions'),
                        validators=[validators.DataRequired(message=trans_function('terms_required', default='You must accept the terms'))],
                        render_kw={'class': 'form-check-input'})
    submit = SubmitField(trans_function('save_and_continue', default='Save and Continue'), render_kw={'class': 'btn btn-primary w-100'})
    back = SubmitField(trans_function('back', default='Back'), render_kw={'class': 'btn btn-secondary w-100 mt-2'})

class AgentSetupForm(FlaskForm):
    agent_name = StringField(trans_function('agent_name', default='Agent Name'),
                            validators=[validators.DataRequired(message=trans_function('agent_name_required', default='Agent name is required')),
                                        validators.Length(min=1, max=255)],
                            render_kw={'class': 'form-control'})
    agent_id = StringField(trans_function('agent_id', default='Agent ID'),
                          validators=[validators.DataRequired(message=trans_function('agent_id_required', default='Agent ID is required')),
                                      validators.Length(min=1, max=50)],
                          render_kw={'class': 'form-control'})
    area = StringField(trans_function('area', default='Geographic Area'),
                      validators=[validators.DataRequired(message=trans_function('area_required', default='Geographic area is required')),
                                  validators.Length(max=255)],
                      render_kw={'class': 'form-control'})
    role = SelectField(trans_function('role', default='Primary Role'),
                      choices=[
                          ('user_onboarding', trans_function('user_onboarding', default='User Onboarding')),
                          ('financial_literacy', trans_function('financial_literacy', default='Financial Literacy Educator')),
                          ('technical_support', trans_function('technical_support', default='Technical Support')),
                          ('cash_point', trans_function('cash_point', default='Cash-In/Cash-Out Point'))
                      ],
                      validators=[validators.DataRequired(message=trans_function('role_required', default='Role is required'))],
                      render_kw={'class': 'form-select'})
    email = StringField(trans_function('email', default='Email'),
                       validators=[
                           validators.DataRequired(message=trans_function('email_required', default='Email is required')),
                           validators.Email(message=trans_function('email_invalid', default='Invalid email address')),
                           validators.Length(max=254),
                           lambda form, field: is_valid_email(field.data) or validators.ValidationError(trans_function('email_domain_invalid', default='Invalid email domain'))
                       ],
                       render_kw={'class': 'form-control'})
    phone = StringField(trans_function('phone', default='Phone Number'),
                       validators=[
                           validators.DataRequired(message=trans_function('phone_required', default='Phone number is required')),
                           validators.Regexp(PHONE_REGEX, message=trans_function('phone_format', default='Phone number must be 10-15 digits'))
                       ],
                       render_kw={'class': 'form-control'})
    language = SelectField(trans_function('language', default='Language'),
                          choices=[
                              ('en', trans_function('english', default='English')),
                              ('ha', trans_function('hausa', default='Hausa'))
                          ],
                          validators=[validators.DataRequired(message=trans_function('language_required', default='Language is required'))],
                          render_kw={'class': 'form-select'})
    terms = BooleanField(trans_function('terms', default='I accept the Terms and Conditions'),
                        validators=[validators.DataRequired(message=trans_function('terms_required', default='You must accept the terms'))],
                        render_kw={'class': 'form-check-input'})
    submit = SubmitField(trans_function('save_and_continue', default='Save and Continue'), render_kw={'class': 'btn btn-primary w-100'})
    back = SubmitField(trans_function('back', default='Back'), render_kw={'class': 'btn btn-secondary w-100 mt-2'})

def log_audit_action(action, details=None):
    try:
        db = get_mongo_db()
        db.audit_logs.insert_one({
            'admin_id': str(current_user.id) if current_user.is_authenticated else 'system',
            'action': action,
            'details': details or {},
            'timestamp': datetime.utcnow(),
        })
    except Exception as e:
        logger.error(f"Error logging audit action: {str(e)}")

def get_setup_wizard_route(role):
    if role == 'personal':
        return 'users_blueprint.personal_setup_wizard'
    elif role == 'trader':
        return 'users_blueprint.setup_wizard'
    elif role == 'agent':
        return 'users_blueprint.agent_setup_wizard'
    else:
        return 'users_blueprint.setup_wizard'  # Fallback to trader setup

@users_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("50/hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_blueprint.index'))
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    form = LoginForm()
    if form.validate_on_submit():
        try:
            username = form.username.data.strip().lower()
            logger.info(f"Login attempt for username: {username}")
            if not USERNAME_REGEX.match(username):
                flash(trans_function('username_format', default='Username must be alphanumeric with underscores'), 'danger')
                logger.warning(f"Invalid username format: {username}")
                return render_template('users/login.html', form=form), 401
            db = get_mongo_db()
            user = db.users.find_one({'_id': username})
            if not user:
                flash(trans_function('username_not_found', default='Username does not exist. Please check your signup details.'), 'danger')
                logger.warning(f"Login attempt for non-existent username: {username}")
                return render_template('users/login.html', form=form), 401
            if not check_password_hash(user['password'], form.password.data):
                logger.warning(f"Failed login attempt for username: {username} (invalid password)")
                flash(trans_function('invalid_password', default='Incorrect password'), 'danger')
                return render_template('users/login.html', form=form), 401
            logger.info(f"User found: {username}, proceeding with login")
            if os.environ.get('ENABLE_2FA', 'true').lower() == 'true':
                otp = ''.join(str(random.randint(0, 9)) for _ in range(6))
                try:
                    db.users.update_one(
                        {'_id': username},
                        {'$set': {'otp': otp, 'otp_expiry': datetime.utcnow() + timedelta(minutes=5)}}
                    )
                    mail = get_mail(current_app)
                    msg = EmailMessage(
                        subject=trans_function('otp_subject', default='Your One-Time Password'),
                        body=trans_function('otp_body', default=f'Your OTP is {otp}. It expires in 5 minutes.'),
                        to=[user['email']]
                    )
                    msg.send()
                    session['pending_user_id'] = username
                    logger.info(f"OTP sent to {user['email']} for username: {username}")
                    return redirect(url_for('users_blueprint.verify_2fa'))
                except Exception as e:
                    logger.warning(f"Email delivery failed for OTP: {str(e)}. Allowing login without 2FA.")
                    from app import User
                    user_obj = User(user['_id'], user['email'], user.get('display_name'), user.get('role', 'personal'))
                    login_user(user_obj, remember=True)
                    session['lang'] = user.get('language', 'en')
                    log_audit_action('login_without_2fa', {'user_id': username, 'reason': 'email_failure'})
                    logger.info(f"User {username} logged in without 2FA due to email failure. Session: {session}")
                    if not user.get('setup_complete', False):
                        setup_route = get_setup_wizard_route(user.get('role', 'personal'))
                        return redirect(url_for(setup_route))
                    return redirect(url_for('settings_blueprint.profile'))
            from app import User
            user_obj = User(user['_id'], user['email'], user.get('display_name'), user.get('role', 'personal'))
            login_user(user_obj, remember=True)
            session['lang'] = user.get('language', 'en')
            log_audit_action('login', {'user_id': username})
            logger.info(f"User {username} logged in successfully. Session: {session}")
            if not user.get('setup_complete', False):
                setup_route = get_setup_wizard_route(user.get('role', 'personal'))
                return redirect(url_for(setup_route))
            return redirect(url_for('settings_blueprint.profile'))
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error during login: {str(e)}")
            flash(trans_function('database_error', default='An error occurred while accessing the database. Please try again later.'), 'danger')
            return render_template('users/login.html', form=form), 500
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'danger')
    return render_template('users/login.html', form=form)

@users_bp.route('/verify_2fa', methods=['GET', 'POST'])
@limiter.limit("50/hour")
def verify_2fa():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_blueprint.index'))
    if 'pending_user_id' not in session:
        flash(trans_function('invalid_2fa_session', default='Invalid 2FA session. Please log in again'), 'danger')
        return redirect(url_for('users_blueprint.login'))
    form = TwoFactorForm()
    if form.validate_on_submit():
        try:
            username = session['pending_user_id']
            logger.info(f"2FA verification attempt for username: {username}")
            db = get_mongo_db()
            user = db.users.find_one({'_id': username})
            if not user:
                flash(trans_function('user_not_found', default='User not found'), 'danger')
                logger.warning(f"2FA attempt for non-existent username: {username}")
                session.pop('pending_user_id', None)
                return redirect(url_for('users_blueprint.login'))
            if user.get('otp') == form.otp.data and user.get('otp_expiry') > datetime.utcnow():
                from app import User
                user_obj = User(user['_id'], user['email'], user.get('display_name'), user.get('role', 'personal'))
                login_user(user_obj, remember=True)
                session['lang'] = user.get('language', 'en')
                db.users.update_one(
                    {'_id': username},
                    {'$unset': {'otp': '', 'otp_expiry': ''}}
                )
                log_audit_action('verify_2fa', {'user_id': username})
                logger.info(f"User {username} verified 2FA successfully. Session: {session}")
                session.pop('pending_user_id', None)
                if not user.get('setup_complete', False):
                    setup_route = get_setup_wizard_route(user.get('role', 'personal'))
                    return redirect(url_for(setup_route))
                return redirect(url_for('settings_blueprint.profile'))
            flash(trans_function('invalid_otp', default='Invalid or expired OTP'), 'danger')
            logger.warning(f"Failed 2FA attempt for username: {username}")
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error during 2FA verification: {str(e)}")
            flash(trans_function('database_error', default='An error occurred while accessing the database. Please try again later.'), 'danger')
            return render_template('users/verify_2fa.html', form=form), 500
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'danger')
    return render_template('users/verify_2fa.html', form=form)

@users_bp.route('/signup', methods=['GET', 'POST'])
@limiter.limit("50/hour")
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_blueprint.index'))
    form = SignupForm()
    if form.validate_on_submit():
        try:
            username = form.username.data.strip().lower()
            email = form.email.data.strip().lower()
            role = form.role.data
            language = form.language.data
            logger.debug(f"Signup attempt: {username}, {email}")
            logger.info(f"Signup attempt: username={username}, email={email}, role={role}, language={language}")
            db = get_mongo_db()

            if db.users.find_one({'_id': username}):
                flash(trans_function('username_exists', default='Username already exists'), 'danger')
                logger.warning(f"Signup failed: Username {username} already exists")
                return render_template('users/signup.html', form=form)
            if db.users.find_one({'email': email}):
                flash(trans_function('email_exists', default='Email already exists'), 'danger')
                logger.warning(f"Signup failed: Email {email} already exists")
                return render_template('users/signup.html', form=form)

            user_data = {
                '_id': username,
                'email': email,
                'password': generate_password_hash(form.password.data),
                'role': role,
                'coin_balance': 10,
                'language': language,
                'dark_mode': False,
                'is_admin': False,
                'setup_complete': False,
                'display_name': username,
                'created_at': datetime.utcnow()
            }

            result = db.users.insert_one(user_data)
            if not result.inserted_id:
                flash(trans_function('database_error', default='An error occurred while creating your account. Please try again later.'), 'danger')
                logger.error(f"Failed to insert user: {username}")
                return render_template('users/signup.html', form=form)

            db.coin_transactions.insert_one({
                'user_id': username,
                'amount': 10,
                'type': 'credit',
                'ref': f"SIGNUP_BONUS_{datetime.utcnow().isoformat()}",
                'date': datetime.utcnow()
            })

            db.audit_logs.insert_one({
                'admin_id': 'system',
                'action': 'signup',
                'details': {'user_id': username, 'role': role},
                'timestamp': datetime.utcnow()
            })

            from app import User
            user_obj = User(username, email, username, role)
            login_user(user_obj, remember=True)
            session['lang'] = language
            logger.info(f"New user created and logged in: {username} (role: {role}). Session: {session}")
            setup_route = get_setup_wizard_route(role)
            return redirect(url_for(setup_route))

        except Exception as e:
            logger.error(f"Unexpected error during signup for {username}: {str(e)}")
            flash(trans_function('database_error', default='An error occurred while accessing the database. Please try again later.'), 'danger')
            return render_template('users/signup.html', form=form), 500
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'danger')
    return render_template('users/signup.html', form=form)

@users_bp.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("50/hour")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_blueprint.index'))
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        try:
            email = form.email.data.strip().lower()
            logger.info(f"Forgot password request for email: {email}")
            db = get_mongo_db()
            user = db.users.find_one({'email': email})
            if not user:
                flash(trans_function('email_not_found', default='No user found with this email'), 'danger')
                logger.warning(f"No user found with email: {email}")
                return render_template('users/forgot_password.html', form=form)
            reset_token = URLSafeTimedSerializer(current_app.config['SECRET_KEY']).dumps(email, salt='reset-salt')
            expiry = datetime.utcnow() + timedelta(minutes=15)
            db.users.update_one(
                {'_id': user['_id']},
                {'$set': {'reset_token': reset_token, 'reset_token_expiry': expiry}}
            )
            mail = get_mail(current_app)
            reset_url = url_for('users_blueprint.reset_password', token=reset_token, _external=True)
            msg = EmailMessage(
                subject=trans_function('reset_the_password_subject', default='Reset Your Password'),
                body=trans_function('reset_password_body', default=f'Click the link to reset your password: {reset_url}\nLink expires in 15 minutes.'),
                to=[email]
            )
            msg.send()
            log_audit_action('forgot_password', {'email': email})
            logger.info(f"Password reset email sent to {email}")
            flash(trans_function('reset_email_sent', default='Password reset email sent'), 'success')
            return render_template('users/forgot_password.html', form=form)
        except Exception as e:
            logger.error(f"Error during forgot password for {email}: {str(e)}")
            flash(trans_function('email_send_error', default='An error occurred while sending the reset email'), 'danger')
            return render_template('users/forgot_password.html', form=form), 500
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'danger')
    return render_template('users/forgot_password.html', form=form)

@users_bp.route('/reset_password', methods=['GET', 'POST'])
@limiter.limit("50/hour")
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_blueprint.index'))
    token = request.args.get('token')
    try:
        email = URLSafeTimedSerializer(current_app.config['SECRET_KEY']).loads(token, salt='reset-salt', max_age=900)
        logger.info(f"Password reset attempt for email: {email}")
    except Exception:
        flash(trans_function('invalid_or_expired_token', default='Invalid or expired token'), 'danger')
        logger.warning(f"Invalid or expired reset token")
        return redirect(url_for('users_blueprint.forgot_password'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            user = db.users.find_one({'email': email})
            if not user:
                flash(trans_function('invalid_email', default='No user found with this email'), 'danger')
                logger.warning(f"No user found with email: {email}")
                return render_template('users/reset_password.html', form=form, token=token)
            db.users.update_one(
                {'_id': user['_id']},
                {'$set': {'password': generate_password_hash(form.password.data)},
                 '$unset': {'reset_token': '', 'reset_token_expiry': ''}}
            )
            log_audit_action('reset_password', {'user_id': user['_id']})
            logger.info(f"Password reset successfully for user: {user['_id']}")
            flash(trans_function('reset_success', default='Password reset successfully'), 'success')
            return redirect(url_for('users_blueprint.login'))
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error during password reset for {email}: {str(e)}")
            flash(trans_function('database_error', default='An error occurred while accessing the database. Please try again later.'), 'danger')
            return render_template('users/reset_password.html', form=form, token=token), 500
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'danger')
    return render_template('users/reset_password.html', form=form, token=token)

@users_bp.route('/setup_wizard', methods=['GET', 'POST'])
@login_required
@limiter.limit("50/hour")
def setup_wizard():
    db = get_mongo_db()
    user_id = request.args.get('user_id', current_user.id) if is_admin() and request.args.get('user_id') else current_user.id
    user = db.users.find_one({'_id': user_id})
    if user.get('setup_complete', False):
        return redirect(url_for('dashboard_blueprint.index'))
    form = BusinessSetupForm()
    if form.validate_on_submit():
        try:
            if form.back.data:
                flash(trans_function('setup_canceled', default='Business setup canceled'), 'info')
                logger.info(f"Business setup canceled for user: {user_id}")
                return redirect(url_for('settings_blueprint.profile', user_id=user_id) if is_admin() else url_for('settings_blueprint.profile'))
            db.users.update_one(
                {'_id': user_id},
                {
                    '$set': {
                        'business_details': {
                            'name': form.business_name.data.strip(),
                            'address': form.address.data.strip(),
                            'industry': form.industry.data,
                            'products_services': form.products_services.data.strip(),
                            'phone_number': form.phone_number.data.strip()
                        },
                        'language': form.language.data,
                        'setup_complete': True
                    }
                }
            )
            log_audit_action('complete_setup_wizard', {'user_id': user_id, 'updated_by': current_user.id})
            logger.info(f"Business setup completed for user: {user_id} by {current_user.id}")
            flash(trans_function('business_setup_success', default='Business setup completed'), 'success')
            return redirect(url_for('settings_blueprint.profile', user_id=user_id) if is_admin() else url_for('settings_blueprint.profile'))
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error during business setup for {user_id}: {str(e)}")
            flash(trans_function('database_error', default='An error occurred while accessing the database. Please try again later.'), 'danger')
            return render_template('users/setup.html', form=form), 500
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'danger')
    return render_template('users/setup.html', form=form)

@users_bp.route('/personal_setup_wizard', methods=['GET', 'POST'])
@login_required
@limiter.limit("50/hour")
def personal_setup_wizard():
    db = get_mongo_db()
    user_id = request.args.get('user_id', current_user.id) if is_admin() and request.args.get('user_id') else current_user.id
    user = db.users.find_one({'_id': user_id})
    if user.get('setup_complete', False):
        return redirect(url_for('dashboard_blueprint.index'))
    form = PersonalSetupForm()
    if form.validate_on_submit():
        try:
            if form.back.data:
                flash(trans_function('setup_canceled', default='Personal setup canceled'), 'info')
                logger.info(f"Personal setup canceled for user: {user_id}")
                return redirect(url_for('settings_blueprint.profile', user_id=user_id) if is_admin() else url_for('settings_blueprint.profile'))
            db.users.update_one(
                {'_id': user_id},
                {
                    '$set': {
                        'personal_details': {
                            'first_name': form.first_name.data.strip(),
                            'last_name': form.last_name.data.strip(),
                            'phone_number': form.phone_number.data.strip(),
                            'address': form.address.data.strip()
                        },
                        'language': form.language.data,
                        'setup_complete': True
                    }
                }
            )
            log_audit_action('complete_personal_setup_wizard', {'user_id': user_id, 'updated_by': current_user.id})
            logger.info(f"Personal setup completed for user: {user_id} by {current_user.id}")
            flash(trans_function('personal_setup_success', default='Personal setup completed'), 'success')
            return redirect(url_for('settings_blueprint.profile', user_id=user_id) if is_admin() else url_for('settings_blueprint.profile'))
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error during personal setup for {user_id}: {str(e)}")
            flash(trans_function('database_error', default='An error occurred while accessing the database. Please try again later.'), 'danger')
            return render_template('users/personal_setup.html', form=form), 500
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'danger')
    return render_template('users/personal_setup.html', form=form)

@users_bp.route('/agent_setup_wizard', methods=['GET', 'POST'])
@login_required
@limiter.limit("50/hour")
def agent_setup_wizard():
    db = get_mongo_db()
    user_id = request.args.get('user_id', current_user.id) if is_admin() and request.args.get('user_id') else current_user.id
    user = db.users.find_one({'_id': user_id})
    if user.get('setup_complete', False):
        return redirect(url_for('dashboard_blueprint.index'))
    form = AgentSetupForm()
    if form.validate_on_submit():
        try:
            if form.back.data:
                flash(trans_function('setup_canceled', default='Agent setup canceled'), 'info')
                logger.info(f"Agent setup canceled for user: {user_id}")
                return redirect(url_for('settings_blueprint.profile', user_id=user_id) if is_admin() else url_for('settings_blueprint.profile'))
            db.users.update_one(
                {'_id': user_id},
                {
                    '$set': {
                        'agent_details': {
                            'agent_name': form.agent_name.data.strip(),
                            'agent_id': form.agent_id.data.strip(),
                            'area': form.area.data.strip(),
                            'role': form.role.data,
                            'email': form.email.data.strip().lower(),
                            'phone': form.phone.data.strip()
                        },
                        'language': form.language.data,
                        'setup_complete': True
                    }
                }
            )
            log_audit_action('complete_agent_setup_wizard', {'user_id': user_id, 'updated_by': current_user.id})
            logger.info(f"Agent setup completed for user: {user_id} by {current_user.id}")
            flash(trans_function('agent_setup_success', default='Agent setup completed'), 'success')
            return redirect(url_for('settings_blueprint.profile', user_id=user_id) if is_admin() else url_for('settings_blueprint.profile'))
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error during agent setup for {user_id}: {str(e)}")
            flash(trans_function('database_error', default='An error occurred while accessing the database. Please try again later.'), 'danger')
            return render_template('users/agent_setup.html', form=form), 500
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'danger')
    return render_template('users/agent_setup.html', form=form)

@users_bp.route('/logout')
@login_required
@limiter.limit("100/hour")
def logout():
    user_id = current_user.id
    lang = session.get('lang', 'en')
    logout_user()
    log_audit_action('logout', {'user_id': user_id})
    logger.info(f"User {user_id} logged out")
    flash(trans_function('logged_out', default='Logged out successfully'), 'success')
    session.clear()
    session['lang'] = lang
    return redirect(url_for('users_blueprint.login'))

@users_bp.route('/auth/signin')
def signin():
    return redirect(url_for('users_blueprint.login'))

@users_bp.route('/auth/signup')
def signup_redirect():
    return redirect(url_for('users_blueprint.signup'))

@users_bp.route('/auth/forgot-password')
def forgot_password_redirect():
    return redirect(url_for('users_blueprint.forgot_password'))

@users_bp.route('/auth/reset-password')
def reset_password_redirect():
    return redirect(url_for('users_blueprint.reset_password'))
