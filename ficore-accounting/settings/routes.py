from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_required, current_user
from utils import trans_function, requires_role, is_valid_email, format_currency, get_mongo_db, is_admin, get_user_query
from bson import ObjectId
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, BooleanField, SubmitField, validators
import logging

logger = logging.getLogger(__name__)

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')

class ProfileForm(FlaskForm):
    full_name = StringField(trans_function('full_name', default='Full Name'), [
        validators.DataRequired(message=trans_function('full_name_required', default='Full name is required')),
        validators.Length(min=1, max=100, message=trans_function('full_name_length', default='Full name must be between 1 and 100 characters'))
    ], render_kw={'class': 'form-control'})
    email = StringField(trans_function('email', default='Email'), [
        validators.DataRequired(message=trans_function('email_required', default='Email is required')),
        validators.Email(message=trans_function('email_invalid', default='Invalid email address'))
    ], render_kw={'class': 'form-control'})
    phone = StringField(trans_function('phone', default='Phone'), [
        validators.Optional(),
        validators.Length(max=20, message=trans_function('phone_length', default='Phone number too long'))
    ], render_kw={'class': 'form-control'})
    # Personal user fields
    first_name = StringField(trans_function('first_name', default='First Name'), [
        validators.Optional(),
        validators.Length(max=50, message=trans_function('first_name_length', default='First name too long'))
    ], render_kw={'class': 'form-control'})
    last_name = StringField(trans_function('last_name', default='Last Name'), [
        validators.Optional(),
        validators.Length(max=50, message=trans_function('last_name_length', default='Last name too long'))
    ], render_kw={'class': 'form-control'})
    personal_address = TextAreaField(trans_function('address', default='Address'), [
        validators.Optional(),
        validators.Length(max=500, message=trans_function('address_length', default='Address too long'))
    ], render_kw={'class': 'form-control'})
    # Trader user fields
    business_name = StringField(trans_function('business_name', default='Business Name'), [
        validators.Optional(),
        validators.Length(max=100, message=trans_function('business_name_length', default='Business name too long'))
    ], render_kw={'class': 'form-control'})
    business_address = TextAreaField(trans_function('business_address', default='Business Address'), [
        validators.Optional(),
        validators.Length(max=500, message=trans_function('business_address_length', default='Business address too long'))
    ], render_kw={'class': 'form-control'})
    industry = StringField(trans_function('industry', default='Industry'), [
        validators.Optional(),
        validators.Length(max=50, message=trans_function('industry_length', default='Industry name too long'))
    ], render_kw={'class': 'form-control'})
    products_services = StringField(trans_function('products_services', default='Products/Services'), [
        validators.Optional(),
        validators.Length(max=200, message=trans_function('products_services_length', default='Products/Services description too long'))
    ], render_kw={'class': 'form-control'})
    # Agent user fields
    agent_name = StringField(trans_function('agent_name', default='Agent Name'), [
        validators.Optional(),
        validators.Length(max=100, message=trans_function('agent_name_length', default='Agent name too long'))
    ], render_kw={'class': 'form-control'})
    agent_id = StringField(trans_function('agent_id', default='Agent ID'), [
        validators.Optional(),
        validators.Length(max=50, message=trans_function('agent_id_length', default='Agent ID too long'))
    ], render_kw={'class': 'form-control'})
    area = StringField(trans_function('area', default='Area'), [
        validators.Optional(),
        validators.Length(max=100, message=trans_function('area_length', default='Area too long'))
    ], render_kw={'class': 'form-control'})
    agent_role = StringField(trans_function('agent_role', default='Role'), [
        validators.Optional(),
        validators.Length(max=50, message=trans_function('agent_role_length', default='Role too long'))
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans_function('save_changes', default='Save Changes'), render_kw={'class': 'btn btn-primary w-100'})

class NotificationForm(FlaskForm):
    email_notifications = BooleanField(trans_function('email_notifications', default='Email Notifications'))
    sms_notifications = BooleanField(trans_function('sms_notifications', default='SMS Notifications'))
    submit = SubmitField(trans_function('save', default='Save'), render_kw={'class': 'btn btn-primary w-100'})

class LanguageForm(FlaskForm):
    language = SelectField(trans_function('language', default='Language'), choices=[
        ('en', trans_function('english', default='English')),
        ('ha', trans_function('hausa', default='Hausa'))
    ], validators=[validators.DataRequired(message=trans_function('language_required', default='Language is required'))], render_kw={'class': 'form-select'})
    submit = SubmitField(trans_function('save', default='Save'), render_kw={'class': 'btn btn-primary w-100'})

@settings_bp.route('/')
@login_required
def index():
    """Display settings overview."""
    try:
        return render_template('settings/index.html', user=current_user)
    except Exception as e:
        logger.error(f"Error loading settings for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard_blueprint.index'))

@settings_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Unified profile management page."""
    try:
        db = get_mongo_db()
        user_id = request.args.get('user_id', current_user.id) if is_admin() and request.args.get('user_id') else current_user.id
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        
        if not user:
            flash(trans_function('user_not_found', default='User not found'), 'danger')
            return redirect(url_for('dashboard_blueprint.index'))
        
        form = ProfileForm()
        
        # Pre-populate form with current user data on GET request
        if request.method == 'GET':
            form.full_name.data = user.get('display_name', user.get('_id', ''))
            form.email.data = user.get('email', '')
            form.phone.data = user.get('phone', '')
            if user.get('personal_details') and user.get('role') == 'personal':
                form.first_name.data = user['personal_details'].get('first_name', '')
                form.last_name.data = user['personal_details'].get('last_name', '')
                form.personal_address.data = user['personal_details'].get('address', '')
            if user.get('business_details') and user.get('role') == 'trader':
                form.business_name.data = user['business_details'].get('name', '')
                form.business_address.data = user['business_details'].get('address', '')
                form.industry.data = user['business_details'].get('industry', '')
                form.products_services.data = user['business_details'].get('products_services', '')
            if user.get('agent_details') and user.get('role') == 'agent':
                form.agent_name.data = user['agent_details'].get('agent_name', '')
                form.agent_id.data = user['agent_details'].get('agent_id', '')
                form.area.data = user['agent_details'].get('area', '')
                form.agent_role.data = user['agent_details'].get('role', '')
        
        if form.validate_on_submit():
            try:
                # Check if email already exists for another user
                if form.email.data != user['email'] and db.users.find_one({'email': form.email.data}):
                    flash(trans_function('email_exists', default='Email already in use'), 'danger')
                    return render_template('settings/profile.html', form=form, user=user)
                
                # Prepare update data
                update_data = {
                    'display_name': form.full_name.data,
                    'email': form.email.data,
                    'phone': form.phone.data,
                    'updated_at': datetime.utcnow(),
                    'setup_complete': True
                }
                
                # Update details based on user role
                if user.get('role') == 'personal' and (form.first_name.data or form.last_name.data or form.personal_address.data):
                    update_data['personal_details'] = {
                        'first_name': form.first_name.data or '',
                        'last_name': form.last_name.data or '',
                        'address': form.personal_address.data or '',
                        'phone_number': form.phone.data or ''
                    }
                elif user.get('role') == 'trader' and (form.business_name.data or form.business_address.data or form.industry.data or form.products_services.data):
                    update_data['business_details'] = {
                        'name': form.business_name.data or '',
                        'address': form.business_address.data or '',
                        'industry': form.industry.data or '',
                        'products_services': form.products_services.data or '',
                        'phone_number': form.phone.data or ''
                    }
                elif user.get('role') == 'agent' and (form.agent_name.data or form.agent_id.data or form.area.data or form.agent_role.data):
                    update_data['agent_details'] = {
                        'agent_name': form.agent_name.data or '',
                        'agent_id': form.agent_id.data or '',
                        'area': form.area.data or '',
                        'role': form.agent_role.data or '',
                        'phone': form.phone.data or '',
                        'email': form.email.data or ''
                    }
                
                db.users.update_one(user_query, {'$set': update_data})
                
                flash(trans_function('profile_updated', default='Profile updated successfully'), 'success')
                logger.info(f"Profile updated for user: {user_id}")
                return redirect(url_for('settings_blueprint.profile'))
                
            except Exception as e:
                logger.error(f"Error updating profile for user {user_id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        
        # Prepare user data for template
        user_display = {
            '_id': str(user['_id']),
            'email': user.get('email', ''),
            'display_name': user.get('display_name', ''),
            'phone': user.get('phone', ''),
            'coin_balance': user.get('coin_balance', 0),
            'role': user.get('role', 'personal'),
            'language': user.get('language', 'en'),
            'dark_mode': user.get('dark_mode', False),
            'personal_details': user.get('personal_details', {}),
            'business_details': user.get('business_details', {}),
            'agent_details': user.get('agent_details', {}),
            'settings': user.get('settings', {}),
            'security_settings': user.get('security_settings', {})
        }
        
        return render_template('settings/profile.html', form=form, user=user_display)
        
    except Exception as e:
        logger.error(f"Error in profile settings for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('settings_blueprint.index'))

@settings_bp.route('/notifications', methods=['GET', 'POST'])
@login_required
def notifications():
    """Update notification preferences."""
    try:
        db = get_mongo_db()
        user_id = request.args.get('user_id', current_user.id) if is_admin() and request.args.get('user_id') else current_user.id
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        
        form = NotificationForm(data={
            'email_notifications': user.get('email_notifications', True),
            'sms_notifications': user.get('sms_notifications', False)
        })
        
        if form.validate_on_submit():
            try:
                update_data = {
                    'email_notifications': form.email_notifications.data,
                    'sms_notifications': form.sms_notifications.data,
                    'updated_at': datetime.utcnow()
                }
                db.users.update_one(user_query, {'$set': update_data})
                flash(trans_function('notifications_updated', default='Notification preferences updated successfully'), 'success')
                return redirect(url_for('settings_blueprint.index'))
            except Exception as e:
                logger.error(f"Error updating notifications for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return render_template('settings/notifications.html', form=form)
    except Exception as e:
        logger.error(f"Error in notification settings for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('settings_blueprint.index'))

@settings_bp.route('/language', methods=['GET', 'POST'])
@login_required
def language():
    """Update language preference."""
    try:
        db = get_mongo_db()
        user_id = request.args.get('user_id', current_user.id) if is_admin() and request.args.get('user_id') else current_user.id
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        
        form = LanguageForm(data={'language': user.get('language', 'en')})
        
        if form.validate_on_submit():
            try:
                session['lang'] = form.language.data
                db.users.update_one(
                    user_query,
                    {'$set': {'language': form.language.data, 'updated_at': datetime.utcnow()}}
                )
                flash(trans_function('language_updated', default='Language updated successfully'), 'success')
                return redirect(url_for('settings_blueprint.index'))
            except Exception as e:
                logger.error(f"Error updating language for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return render_template('settings/language.html', form=form)
    except Exception as e:
        logger.error(f"Error in language settings for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('settings_blueprint.index'))

@settings_bp.route('/api/update-user-setting', methods=['POST'])
@login_required
def update_user_setting():
    """API endpoint to update user settings via AJAX."""
    try:
        data = request.get_json()
        setting_name = data.get('setting')
        value = data.get('value')
        
        if setting_name not in ['showKoboToggle', 'incognitoModeToggle', 'appSoundsToggle', 
                               'fingerprintPasswordToggle', 'fingerprintPinToggle', 'hideSensitiveDataToggle']:
            return jsonify({"success": False, "message": "Invalid setting name."}), 400
        
        db = get_mongo_db()
        user_query = get_user_query(str(current_user.id))
        user = db.users.find_one(user_query)
        
        if not user:
            return jsonify({"success": False, "message": "User not found."}), 404
        
        # Initialize settings if they don't exist
        settings = user.get('settings', {})
        security_settings = user.get('security_settings', {})
        
        # Map toggle IDs to actual settings
        if setting_name == 'showKoboToggle':
            settings['show_kobo'] = value
        elif setting_name == 'incognitoModeToggle':
            settings['incognito_mode'] = value
        elif setting_name == 'appSoundsToggle':
            settings['app_sounds'] = value
        elif setting_name == 'fingerprintPasswordToggle':
            security_settings['fingerprint_password'] = value
        elif setting_name == 'fingerprintPinToggle':
            security_settings['fingerprint_pin'] = value
        elif setting_name == 'hideSensitiveDataToggle':
            security_settings['hide_sensitive_data'] = value
        
        # Update user document
        update_data = {
            'settings': settings,
            'security_settings': security_settings,
            'updated_at': datetime.utcnow()
        }
        
        db.users.update_one(user_query, {'$set': update_data})
        
        return jsonify({"success": True, "message": "Setting updated successfully."})
        
    except Exception as e:
        logger.error(f"Error updating user setting: {str(e)}")
        return jsonify({"success": False, "message": "An error occurred while updating the setting."}), 500
