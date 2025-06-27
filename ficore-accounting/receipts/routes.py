from flask import Blueprint, render_template, redirect, url_for, flash, request, Response, jsonify
from flask_login import login_required, current_user
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date, get_mongo_db, is_admin, get_user_query
from bson import ObjectId
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, FloatField, SelectField, SubmitField
from wtforms.validators import DataRequired, Optional
import logging
import io

logger = logging.getLogger(__name__)

class ReceiptForm(FlaskForm):
    party_name = StringField('Payer Name', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired()])
    method = SelectField('Payment Method', choices=[
        ('cash', 'Cash'),
        ('card', 'Card'),
        ('bank', 'Bank Transfer')
    ], validators=[Optional()])
    category = StringField('Category', validators=[Optional()])
    submit = SubmitField('Add Receipt')

receipts_bp = Blueprint('receipts', __name__, url_prefix='/receipts')

@receipts_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """List all receipt cashflows for the current user."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to view all receipt cashflows during testing
        # TODO: Restore original user_id filter for production
        query = {'type': 'receipt'} if is_admin() else {'user_id': str(current_user.id), 'type': 'receipt'}
        receipts = list(db.cashflows.find(query).sort('created_at', -1))
        return render_template('receipts/index.html', receipts=receipts, format_currency=format_currency, format_date=format_date)
    except Exception as e:
        logger.error(f"Error fetching receipts for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard_blueprint.index'))

@receipts_bp.route('/view/<id>')
@login_required
@requires_role('trader')
def view(id):
    """View detailed information about a specific receipt."""
    try:
        db = get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'receipt'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        receipt = db.cashflows.find_one(query)
        if not receipt:
            return jsonify({'error': trans_function('record_not_found', default='Record not found')}), 404
        
        # Convert ObjectId to string for JSON serialization
        receipt['_id'] = str(receipt['_id'])
        receipt['created_at'] = receipt['created_at'].isoformat() if receipt.get('created_at') else None
        
        return jsonify(receipt)
    except Exception as e:
        logger.error(f"Error fetching receipt {id} for user {current_user.id}: {str(e)}")
        return jsonify({'error': trans_function('something_went_wrong', default='An error occurred')}), 500

@receipts_bp.route('/generate_pdf/<id>')
@login_required
@requires_role('trader')
def generate_pdf(id):
    """Generate PDF receipt for a receipt transaction."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import inch
        
        db = get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'receipt'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        receipt = db.cashflows.find_one(query)
        
        if not receipt:
            flash(trans_function('record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('receipts_blueprint.index'))
        
        # Check coin balance for non-admin users
        if not is_admin() and not check_coin_balance(1):
            flash(trans_function('insufficient_coins', default='Insufficient coins to generate receipt'), 'danger')
            return redirect(url_for('coins_blueprint.purchase'))
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        # Header
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, height - inch, "FiCore Records - Money In Receipt")
        
        # Content
        p.setFont("Helvetica", 12)
        y_position = height - inch - 0.5 * inch
        p.drawString(inch, y_position, f"Payer: {receipt['party_name']}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Amount Received: {format_currency(receipt['amount'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Payment Method: {receipt.get('method', 'N/A')}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Category: {receipt.get('category', 'No category provided')}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Date: {format_date(receipt['created_at'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Receipt ID: {str(receipt['_id'])}")
        
        # Footer
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, "This document serves as an official receipt generated by FiCore Records.")
        
        p.showPage()
        p.save()
        
        # Deduct coins for non-admin users
        if not is_admin():
            user_query = get_user_query(str(current_user.id))
            db.users.update_one(user_query, {'$inc': {'coin_balance': -1}})
            db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"Receipt PDF generated for {receipt['party_name']}"
            })
        
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=receipt_{receipt["party_name"]}_{str(receipt["_id"])}.pdf'
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating PDF for receipt {id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('receipts_blueprint.index'))

@receipts_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def add():
    """Add a new receipt cashflow."""
    form = ReceiptForm()
    # TEMPORARY: Bypass coin check for admin during testing
    # TODO: Restore original check_coin_balance(1) for production
    if not is_admin() and not check_coin_balance(1):
        flash(trans_function('insufficient_coins', default='Insufficient coins to add a receipt. Purchase more coins.'), 'danger')
        return redirect(url_for('coins_blueprint.purchase'))
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            # Convert datetime.date to datetime.datetime
            receipt_date = datetime(form.date.data.year, form.date.data.month, form.date.data.day)
            cashflow = {
                'user_id': str(current_user.id),
                'type': 'receipt',
                'party_name': form.party_name.data,
                'amount': form.amount.data,
                'method': form.method.data,
                'category': form.category.data,
                'created_at': receipt_date,
                'updated_at': datetime.utcnow()
            }
            db.cashflows.insert_one(cashflow)
            # TEMPORARY: Skip coin deduction for admin during testing
            # TODO: Restore original coin deduction for production
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
                    'ref': f"Receipt creation: {cashflow['party_name']}"
                })
            flash(trans_function('add_receipt_success', default='Receipt added successfully'), 'success')
            return redirect(url_for('receipts_blueprint.index'))
        except Exception as e:
            logger.error(f"Error adding receipt for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return render_template('receipts/add.html', form=form)

@receipts_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def edit(id):
    """Edit an existing receipt cashflow."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to edit any receipt cashflow during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'receipt'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        receipt = db.cashflows.find_one(query)
        if not receipt:
            flash(trans_function('cashflow_not_found', default='Cashflow not found'), 'danger')
            return redirect(url_for('receipts_blueprint.index'))
        form = ReceiptForm(data={
            'party_name': receipt['party_name'],
            'date': receipt['created_at'],  # This is already a datetime.datetime object from MongoDB
            'amount': receipt['amount'],
            'method': receipt.get('method'),
            'category': receipt.get('category')
        })
        if form.validate_on_submit():
            try:
                # Convert datetime.date to datetime.datetime
                receipt_date = datetime(form.date.data.year, form.date.data.month, form.date.data.day)
                updated_cashflow = {
                    'party_name': form.party_name.data,
                    'amount': form.amount.data,
                    'method': form.method.data,
                    'category': form.category.data,
                    'created_at': receipt_date,
                    'updated_at': datetime.utcnow()
                }
                db.cashflows.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_cashflow}
                )
                flash(trans_function('edit_receipt_success', default='Receipt updated successfully'), 'success')
                return redirect(url_for('receipts_blueprint.index'))
            except Exception as e:
                logger.error(f"Error updating receipt {id} for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return render_template('receipts/edit.html', form=form, receipt=receipt)
    except Exception as e:
        logger.error(f"Error fetching receipt {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('cashflow_not_found', default='Cashflow not found'), 'danger')
        return redirect(url_for('receipts_blueprint.index'))

@receipts_bp.route('/delete/<id>', methods=['POST'])
@login_required
@requires_role('trader')
def delete(id):
    """Delete a receipt cashflow."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to delete any receipt cashflow during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'receipt'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        result = db.cashflows.delete_one(query)
        if result.deleted_count:
            flash(trans_function('delete_receipt_success', default='Receipt deleted successfully'), 'success')
        else:
            flash(trans_function('cashflow_not_found', default='Cashflow not found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting receipt {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return redirect(url_for('receipts_blueprint.index'))
