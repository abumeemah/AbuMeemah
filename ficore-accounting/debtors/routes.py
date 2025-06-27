from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, Response
from flask_login import login_required, current_user
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date, get_mongo_db, is_admin, get_user_query
from bson import ObjectId
from datetime import datetime, timedelta
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional
import logging
import io
import os
import requests
import re
import urllib.parse

logger = logging.getLogger(__name__)

class DebtorForm(FlaskForm):
    name = StringField('Debtor Name', validators=[DataRequired()])
    contact = StringField('Contact', validators=[Optional()])
    amount_owed = FloatField('Amount Owed', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    submit = SubmitField('Add Debtor')

debtors_bp = Blueprint('debtors', __name__, url_prefix='/debtors')

@debtors_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """List all debtor records for the current user."""
    try:
        db = get_mongo_db()
        query = {'type': 'debtor'} if is_admin() else {'user_id': str(current_user.id), 'type': 'debtor'}
        debtors = list(db.records.find(query).sort('created_at', -1))
        return render_template('debtors/index.html', debtors=debtors, format_currency=format_currency, format_date=format_date)
    except Exception as e:
        logger.error(f"Error fetching debtors for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard_blueprint.index'))

@debtors_bp.route('/view/<id>')
@login_required
@requires_role('trader')
def view(id):
    """View detailed information about a specific debtor (JSON API)."""
    try:
        db = get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            return jsonify({'error': trans_function('record_not_found', default='Record not found')}), 404
        
        debtor['_id'] = str(debtor['_id'])
        debtor['created_at'] = debtor['created_at'].isoformat() if debtor.get('created_at') else None
        debtor['reminder_count'] = debtor.get('reminder_count', 0)
        
        return jsonify(debtor)
    except Exception as e:
        logger.error(f"Error fetching debtor {id} for user {current_user.id}: {str(e)}")
        return jsonify({'error': trans_function('something_went_wrong', default='An error occurred')}), 500

@debtors_bp.route('/view_page/<id>')
@login_required
@requires_role('trader')
def view_page(id):
    """Render a detailed view page for a specific debtor."""
    try:
        db = get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            flash(trans_function('record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors_blueprint.index'))
        return render_template('debtors/view.html', debtor=debtor, format_currency=format_currency, format_date=format_date)
    except Exception as e:
        logger.error(f"Error rendering debtor view page {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('debtors_blueprint.index'))

@debtors_bp.route('/share/<id>')
@login_required
@requires_role('trader')
def share(id):
    """Generate a WhatsApp link to share IOU details."""
    try:
        db = get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            return jsonify({'success': False, 'message': trans_function('record_not_found', default='Record not found')}), 404
        if not debtor.get('contact'):
            return jsonify({'success': False, 'message': trans_function('no_contact', default='No contact provided for sharing')}), 400
        if not is_admin() and not check_coin_balance(1):
            return jsonify({'success': False, 'message': trans_function('insufficient_coins', default='Insufficient coins to share IOU')}), 400
        
        contact = re.sub(r'\D', '', debtor['contact'])
        if contact.startswith('0'):
            contact = '234' + contact[1:]
        elif not contact.startswith('+'):
            contact = '234' + contact
        
        message = f"Hi {debtor['name']}, this is an IOU for {format_currency(debtor['amount_owed'])} recorded on FiCore Records on {format_date(debtor['created_at'])}. Details: {debtor.get('description', 'No description provided')}."
        whatsapp_link = f"https://wa.me/{contact}?text={urllib.parse.quote(message)}"
        
        if not is_admin():
            user_query = get_user_query(str(current_user.id))
            db.users.update_one(user_query, {'$inc': {'coin_balance': -1}})
            db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"IOU shared for {debtor['name']}"
            })
        
        return jsonify({'success': True, 'whatsapp_link': whatsapp_link})
    except Exception as e:
        logger.error(f"Error sharing IOU for debtor {id}: {str(e)}")
        return jsonify({'success': False, 'message': trans_function('something_went_wrong', default='An error occurred')}), 500

@debtors_bp.route('/send_reminder', methods=['POST'])
@login_required
@requires_role('trader')
def send_reminder():
    """Send reminder to debtor via SMS/WhatsApp or set snooze."""
    try:
        data = request.get_json()
        debt_id = data.get('debtId')
        recipient = data.get('recipient')
        message = data.get('message')
        send_type = data.get('type', 'sms')
        snooze_days = data.get('snooze_days', 0)
        
        if not debt_id or (not recipient and not snooze_days):
            return jsonify({'success': False, 'message': trans_function('missing_required_fields', default='Missing required fields')}), 400
        
        db = get_mongo_db()
        query = {'_id': ObjectId(debt_id), 'type': 'debtor'} if is_admin() else {'_id': ObjectId(debt_id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        
        if not debtor:
            return jsonify({'success': False, 'message': trans_function('record_not_found', default='Record not found')}), 404
        
        coin_cost = 2 if recipient else 1
        if not is_admin() and not check_coin_balance(coin_cost):
            return jsonify({'success': False, 'message': trans_function('insufficient_coins', default='Insufficient coins to send reminder')}), 400
        
        update_data = {'$inc': {'reminder_count': 1}}
        if snooze_days:
            update_data['$set'] = {'reminder_date': datetime.utcnow() + timedelta(days=snooze_days)}
        
        success = True
        api_response = {}
        
        if recipient:
            if send_type == 'sms':
                success, api_response = send_sms_reminder(recipient, message)
            elif send_type == 'whatsapp':
                success, api_response = send_whatsapp_reminder(recipient, message)
        
        if success:
            db.records.update_one({'_id': ObjectId(debt_id)}, update_data)
            
            if not is_admin():
                user_query = get_user_query(str(current_user.id))
                db.users.update_one(user_query, {'$inc': {'coin_balance': -coin_cost}})
                db.coin_transactions.insert_one({
                    'user_id': str(current_user.id),
                    'amount': -coin_cost,
                    'type': 'spend',
                    'date': datetime.utcnow(),
                    'ref': f"{'Reminder sent' if recipient else 'Snooze set'} for {debtor['name']}"
                })
            
            db.reminder_logs.insert_one({
                'user_id': str(current_user.id),
                'debt_id': debt_id,
                'recipient': recipient or 'N/A',
                'message': message or 'Snooze',
                'type': send_type if recipient else 'snooze',
                'sent_at': datetime.utcnow(),
                'api_response': api_response if recipient else {'status': f'Snoozed for {snooze_days} days'}
            })
            
            return jsonify({'success': True, 'message': trans_function('reminder_sent' if recipient else 'snooze_set', default='Reminder sent successfully' if recipient else 'Snooze set successfully')})
        else:
            return jsonify({'success': False, 'message': trans_function('reminder_failed', default='Failed to send reminder'), 'details': api_response}), 500
            
    except Exception as e:
        logger.error(f"Error sending reminder: {str(e)}")
        return jsonify({'success': False, 'message': trans_function('something_went_wrong', default='An error occurred')}), 500

@debtors_bp.route('/generate_iou/<id>')
@login_required
@requires_role('trader')
def generate_iou(id):
    """Generate PDF IOU for a debtor."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import inch
        
        db = get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        
        if not debtor:
            flash(trans_function('record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors_blueprint.index'))
        
        if not is_admin() and not check_coin_balance(1):
            flash(trans_function('insufficient_coins', default='Insufficient coins to generate IOU'), 'danger')
            return redirect(url_for('coins_blueprint.purchase'))
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, height - inch, "FiCore Records - IOU")
        
        p.setFont("Helvetica", 12)
        y_position = height - inch - 0.5 * inch
        p.drawString(inch, y_position, f"Debtor: {debtor['name']}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Amount Owed: {format_currency(debtor['amount_owed'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Contact: {debtor.get('contact', 'N/A')}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Description: {debtor.get('description', 'No description provided')}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Date Recorded: {format_date(debtor['created_at'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Reminders Sent: {debtor.get('reminder_count', 0)}")
        
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, "This document serves as an IOU recorded on FiCore Records.")
        
        p.showPage()
        p.save()
        
        if not is_admin():
            user_query = get_user_query(str(current_user.id))
            db.users.update_one(user_query, {'$inc': {'coin_balance': -1}})
            db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"IOU generated for {debtor['name']}"
            })
        
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_IOU_{debtor["name"]}.pdf'
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating IOU for debtor {id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('debtors_blueprint.index'))

@debtors_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def add():
    """Add a new debtor record."""
    form = DebtorForm()
    if not is_admin() and not check_coin_balance(1):
        flash(trans_function('insufficient_coins', default='Insufficient coins to create a debtor. Purchase more coins.'), 'danger')
        return redirect(url_for('coins_blueprint.purchase'))
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            record = {
                'user_id': str(current_user.id),
                'type': 'debtor',
                'name': form.name.data,
                'contact': form.contact.data,
                'amount_owed': form.amount_owed.data,
                'description': form.description.data,
                'reminder_count': 0,
                'created_at': datetime.utcnow()
            }
            db.records.insert_one(record)
            if not is_admin():
                user_query = get_user_query(str(current_user.id))
                db.users.update_one(
                    user_query,
                    {'$inc': {'coin_balance': -1}}
                )
                db.coin_transactions.insert_one({
                    'user_id': str(current_user.id),
                    'amount': -1,
                    'type': 'spend',
                    'date': datetime.utcnow(),
                    'ref': f"Debtor creation: {record['name']}"
                })
            flash(trans_function('create_debtor_success', default='Debtor created successfully'), 'success')
            return redirect(url_for('debtors_blueprint.index'))
        except Exception as e:
            logger.error(f"Error creating debtor for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return render_template('debtors/add.html', form=form)

@debtors_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def edit(id):
    """Edit an existing debtor record."""
    try:
        db = get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            flash(trans_function('record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors_blueprint.index'))
        form = DebtorForm(data={
            'name': debtor['name'],
            'contact': debtor['contact'],
            'amount_owed': debtor['amount_owed'],
            'description': debtor['description']
        })
        if form.validate_on_submit():
            try:
                updated_record = {
                    'name': form.name.data,
                    'contact': form.contact.data,
                    'amount_owed': form.amount_owed.data,
                    'description': form.description.data,
                    'updated_at': datetime.utcnow()
                }
                db.records.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_record}
                )
                flash(trans_function('edit_debtor_success', default='Debtor updated successfully'), 'success')
                return redirect(url_for('debtors_blueprint.index'))
            except Exception as e:
                logger.error(f"Error updating debtor {id} for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return render_template('debtors/edit.html', form=form, debtor=debtor)
    except Exception as e:
        logger.error(f"Error fetching debtor {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('record_not_found', default='Record not found'), 'danger')
        return redirect(url_for('debtors_blueprint.index'))

@debtors_bp.route('/delete/<id>', methods=['POST'])
@login_required
@requires_role('trader')
def delete(id):
    """Delete a debtor record."""
    try:
        db = get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        result = db.records.delete_one(query)
        if result.deleted_count:
            flash(trans_function('delete_debtor_success', default='Debtor deleted successfully'), 'success')
        else:
            flash(trans_function('record_not_found', default='Record not found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting debtor {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return redirect(url_for('debtors_blueprint.index'))

def send_sms_reminder(recipient, message):
    """Send SMS reminder using Africa's Talking API."""
    try:
        api_key = os.getenv('AFRICAS_TALKING_API_KEY')
        username = os.getenv('AFRICAS_TALKING_USERNAME', 'sandbox')
        
        if not api_key:
            logger.warning("Africa's Talking API key not configured")
            return False, {'error': 'SMS service not configured'}
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "apikey": api_key
        }
        
        if not recipient.startswith('+') and not recipient.startswith('234'):
            if recipient.startswith('0'):
                recipient = '234' + recipient[1:]
            else:
                recipient = '234' + recipient
        
        payload = {
            "username": username,
            "to": recipient,
            "message": message
        }
        
        response = requests.post(
            "https://api.africastalking.com/version1/messaging",
            headers=headers,
            data=payload,
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        if result and result.get('SMSMessageData', {}).get('Recipients'):
            recipients = result['SMSMessageData']['Recipients']
            if recipients and recipients[0].get('status') == 'Success':
                return True, result
        
        return False, result
        
    except Exception as e:
        logger.error(f"Error sending SMS: {str(e)}")
        return False, {'error': str(e)}

def send_whatsapp_reminder(recipient, message):
    """Send WhatsApp reminder (placeholder for future implementation)."""
    logger.info(f"WhatsApp reminder would be sent to {recipient}: {message}")
    return True, {'status': 'WhatsApp integration pending'}
