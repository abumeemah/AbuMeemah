from flask import Blueprint, render_template, redirect, url_for, flash, current_app, request
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, validators, SubmitField
from datetime import datetime
from utils import trans_function, requires_role, get_mongo_db, is_admin, get_user_query
from bson import ObjectId
from app import limiter
import logging

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, template_folder='templates/admin')

class CreditForm(FlaskForm):
    user_id = StringField(trans_function('user_id', default='User ID'), [
        validators.DataRequired(message=trans_function('user_id_required', default='User ID is required')),
        validators.Length(min=3, max=50, message=trans_function('user_id_length', default='User ID must be between 3 and 50 characters'))
    ], render_kw={'class': 'form-control'})
    amount = FloatField(trans_function('coin_amount', default='Coin Amount'), [
        validators.DataRequired(message=trans_function('coin_amount_required', default='Coin amount is required')),
        validators.NumberRange(min=1, message=trans_function('coin_amount_min', default='Coin amount must be at least 1'))
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans_function('credit_coins', default='Credit Coins'), render_kw={'class': 'btn btn-primary w-100'})

def log_audit_action(action, details=None):
    """Log an admin action to audit_logs collection."""
    try:
        db = get_mongo_db()
        db.audit_logs.insert_one({
            'admin_id': str(current_user.id),
            'action': action,
            'details': details or {},
            'timestamp': datetime.utcnow()
        })
    except Exception as e:
        logger.error(f"Error logging audit action: {str(e)}")

@admin_bp.route('/dashboard', methods=['GET'])
@login_required
@requires_role('admin')
@limiter.limit("100 per hour")
def dashboard():
    """Admin dashboard with system stats."""
    try:
        db = get_mongo_db()
        user_count = db.users.count_documents({'role': {'$ne': 'admin'}} if not is_admin() else {})
        records_count = db.records.count_documents({})
        cashflows_count = db.cashflows.count_documents({})
        inventory_count = db.inventory.count_documents({})
        coin_tx_count = db.coin_transactions.count_documents({})
        audit_log_count = db.audit_logs.count_documents({})
        # TEMPORARY: Remove user_id filter for admin during testing
        # TODO: Restore original filter {'role': {'$ne': 'admin'}} for production
        recent_users = list(db.users.find({} if is_admin() else {'role': {'$ne': 'admin'}}).sort('created_at', -1).limit(10))
        for user in recent_users:
            user['_id'] = str(user['_id'])
        return render_template(
            'admin/dashboard.html',
            stats={
                'users': user_count,
                'records': records_count,
                'cashflows': cashflows_count,
                'inventory': inventory_count,
                'coin_transactions': coin_tx_count,
                'audit_logs': audit_log_count
            },
            recent_users=recent_users
        )
    except Exception as e:
        logger.error(f"Error loading admin dashboard: {str(e)}")
        flash(trans_function('database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('500.html', error=str(e)), 500

@admin_bp.route('/users', methods=['GET'])
@login_required
@requires_role('admin')
@limiter.limit("50 per hour")
def manage_users():
    """View and manage users."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Remove user_id filter for admin during testing
        # TODO: Restore original filter {'role': {'$ne': 'admin'}} for production
        users = list(db.users.find({} if is_admin() else {'role': {'$ne': 'admin'}}).sort('created_at', -1))
        for user in users:
            user['_id'] = str(user['_id'])
        return render_template('admin/users.html', users=users)
    except Exception as e:
        logger.error(f"Error fetching users for admin: {str(e)}")
        flash(trans_function('database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('admin/users.html', users=[]), 500

@admin_bp.route('/users/suspend/<user_id>', methods=['POST'])
@login_required
@requires_role('admin')
@limiter.limit("10 per hour")
def suspend_user(user_id):
    """Suspend a user account."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to suspend any user during testing
        # TODO: Restore original filter {'_id': user_id, 'role': {'$ne': 'admin'}} for production
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            flash(trans_function('user_not_found', default='User not found'), 'danger')
            return redirect(url_for('admin_blueprint.manage_users'))
        result = db.users.update_one(
            user_query,
            {'$set': {'suspended': True, 'updated_at': datetime.utcnow()}}
        )
        if result.modified_count == 0:
            flash(trans_function('user_not_updated', default='User could not be suspended'), 'danger')
        else:
            flash(trans_function('user_suspended', default='User suspended successfully'), 'success')
            logger.info(f"Admin {current_user.id} suspended user {user_id}")
            log_audit_action('suspend_user', {'user_id': user_id})
        return redirect(url_for('admin_blueprint.manage_users'))
    except Exception as e:
        logger.error(f"Error suspending user {user_id}: {str(e)}")
        flash(trans_function('database_error', default='An error occurred while accessing the database'), 'danger')
        return redirect(url_for('admin_blueprint.manage_users')), 500

@admin_bp.route('/users/delete/<user_id>', methods=['POST'])
@login_required
@requires_role('admin')
@limiter.limit("5 per hour")
def delete_user(user_id):
    """Delete a user and their data."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to delete any user during testing
        # TODO: Restore original filter {'_id': user_id, 'role': {'$ne': 'admin'}} for production
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            flash(trans_function('user_not_found', default='User not found'), 'danger')
            return redirect(url_for('admin_blueprint.manage_users'))
        db.records.delete_many({'user_id': user_id})
        db.cashflows.delete_many({'user_id': user_id})
        db.inventory.delete_many({'user_id': user_id})
        db.coin_transactions.delete_many({'user_id': user_id})
        db.audit_logs.delete_many({'details.user_id': user_id})
        result = db.users.delete_one(user_query)
        if result.deleted_count == 0:
            flash(trans_function('user_not_deleted', default='User could not be deleted'), 'danger')
        else:
            flash(trans_function('user_deleted', default='User deleted successfully'), 'success')
            logger.info(f"Admin {current_user.id} deleted user {user_id}")
            log_audit_action('delete_user', {'user_id': user_id})
        return redirect(url_for('admin_blueprint.manage_users'))
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        flash(trans_function('database_error', default='An error occurred while accessing the database'), 'danger')
        return redirect(url_for('admin_blueprint.manage_users')), 500

@admin_bp.route('/data/delete/<collection>/<item_id>', methods=['POST'])
@login_required
@requires_role('admin')
@limiter.limit("10 per hour")
def delete_item(collection, item_id):
    """Delete an item from a collection."""
    valid_collections = ['records', 'cashflows', 'inventory']
    if collection not in valid_collections:
        flash(trans_function('invalid_collection', default='Invalid collection selected'), 'danger')
        return redirect(url_for('admin_blueprint.dashboard'))
    try:
        db = get_mongo_db()
        result = db[collection].delete_one({'_id': ObjectId(item_id)})
        if result.deleted_count == 0:
            flash(trans_function('item_not_found', default='Item not found'), 'danger')
        else:
            flash(trans_function('item_deleted', default='Item deleted successfully'), 'success')
            logger.info(f"Admin {current_user.id} deleted {collection} item {item_id}")
            log_audit_action(f'delete_{collection}_item', {'item_id': item_id, 'collection': collection})
        return redirect(url_for('admin_blueprint.dashboard'))
    except Exception as e:
        logger.error(f"Error deleting {collection} item {item_id}: {str(e)}")
        flash(trans_function('database_error', default='An error occurred while accessing the database'), 'danger')
        return redirect(url_for('admin_blueprint.dashboard')), 500

@admin_bp.route('/coins/credit', methods=['GET', 'POST'])
@login_required
@requires_role('admin')
@limiter.limit("10 per hour")
def credit_coins():
    """Manually credit coins to a user."""
    form = CreditForm()
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            user_id = form.user_id.data.strip().lower()
            user_query = get_user_query(user_id)
            user = db.users.find_one(user_query)
            if not user:
                flash(trans_function('user_not_found', default='User not found'), 'danger')
                return render_template('admin/reset.html', form=form)
            amount = int(form.amount.data)
            db.users.update_one(
                user_query,
                {'$inc': {'coin_balance': amount}}
            )
            ref = f"ADMIN_CREDIT_{datetime.utcnow().isoformat()}"
            db.coin_transactions.insert_one({
                'user_id': user_id,
                'amount': amount,
                'type': 'admin_credit',
                'ref': ref,
                'date': datetime.utcnow()
            })
            flash(trans_function('credit_success', default='Coins credited successfully'), 'success')
            logger.info(f"Admin {current_user.id} credited {amount} coins to user {user_id}")
            log_audit_action('credit_coins', {'user_id': user_id, 'amount': amount, 'ref': ref})
            return redirect(url_for('admin_blueprint.dashboard'))
        except Exception as e:
            logger.error(f"Error crediting coins by admin {current_user.id}: {str(e)}")
            flash(trans_function('database_error', default='An error occurred while accessing the database'), 'danger')
            return render_template('admin/reset.html', form=form), 500
    return render_template('admin/reset.html', form=form)

@admin_bp.route('/audit', methods=['GET'])
@login_required
@requires_role('admin')
@limiter.limit("50 per hour")
def audit():
    """View audit logs of admin actions."""
    try:
        db = get_mongo_db()
        logs = list(db.audit_logs.find().sort('timestamp', -1).limit(100))
        for log in logs:
            log['_id'] = str(log['_id'])
        return render_template('admin/audit.html', logs=logs)
    except Exception as e:
        logger.error(f"Error fetching audit logs for admin {current_user.id}: {str(e)}")
        flash(trans_function('database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('admin/audit.html', logs=[]), 500
