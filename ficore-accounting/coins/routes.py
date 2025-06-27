from datetime import datetime
from logging import getLogger
from bson import ObjectId
from bson.errors import InvalidId
from flask import Blueprint, request, render_template, redirect, url_for, flash, current_app, jsonify
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from gridfs import GridFS
from wtforms import FloatField, StringField, SelectField, SubmitField, validators
from app import limiter
from utils import trans_function, requires_role, check_coin_balance, get_mongo_db, is_admin, get_user_query
from pymongo import errors

logger = getLogger(__name__)

coins_bp = Blueprint('coins', __name__, template_folder='templates/coins')

class PurchaseForm(FlaskForm):
    amount = SelectField(
        trans_function('coin_amount', default='Coin Amount'),
        choices=[
            ('10', '10 Coins'),
            ('50', '50 Coins'),
            ('100', '100 Coins')
        ],
        validators=[validators.DataRequired()]
    )
    payment_method = SelectField(
        trans_function('payment_method', default='Payment Method'),
        choices=[
            ('card', trans_function('card', default='Credit/Debit Card')),
            ('bank', trans_function('bank', default='Bank Transfer'))
        ],
        validators=[validators.DataRequired()]
    )
    submit = SubmitField(trans_function('purchase', default='Purchase'))

class ReceiptUploadForm(FlaskForm):
    receipt = FileField(
        trans_function('receipt', default='Receipt'),
        validators=[
            FileAllowed(['jpg', 'png', 'pdf'], trans_function('invalid_file_type', default='Only JPG, PNG, or PDF files are allowed'))
        ]
    )
    submit = SubmitField(trans_function('upload_receipt', default='Upload Receipt'))

def credit_coins(user_id: str, amount: int, ref: str, type: str = 'purchase') -> None:
    """Credit coins to a user and log transaction using MongoDB transaction."""
    db = get_mongo_db()
    client = db.client  # Get MongoDB client for session
    user_query = get_user_query(user_id)
    
    with client.start_session() as session:
        with session.start_transaction():
            try:
                # Update user coin balance
                result = db.users.update_one(
                    user_query,
                    {'$inc': {'coin_balance': amount}},
                    session=session
                )
                if result.matched_count == 0:
                    logger.error(f"No user found for ID {user_id} to credit coins")
                    raise ValueError(f"No user found for ID {user_id}")
                
                # Insert coin transaction
                db.coin_transactions.insert_one({
                    'user_id': user_id,
                    'amount': amount,
                    'type': type,
                    'ref': ref,
                    'date': datetime.utcnow()
                }, session=session)
                
                # Insert audit log
                db.audit_logs.insert_one({
                    'admin_id': 'system' if type == 'purchase' else str(current_user.id),
                    'action': f'credit_coins_{type}',
                    'details': {'user_id': user_id, 'amount': amount, 'ref': ref},
                    'timestamp': datetime.utcnow()
                }, session=session)
                
            except ValueError as e:
                logger.error(f"Transaction aborted: {str(e)}")
                session.abort_transaction()
                raise
            except errors.PyMongoError as e:
                logger.error(f"MongoDB error during coin credit transaction for user {user_id}: {str(e)}")
                session.abort_transaction()
                raise

@coins_bp.route('/purchase', methods=['GET', 'POST'])
@login_required
@requires_role(['trader', 'personal'])
@limiter.limit("50 per hour")
def purchase():
    """Handle coin purchase requests."""
    form = PurchaseForm()
    if form.validate_on_submit():
        try:
            amount = int(form.amount.data)
            payment_method = form.payment_method.data
            payment_ref = f"PAY_{datetime.utcnow().isoformat()}"
            credit_coins(str(current_user.id), amount, payment_ref, 'purchase')
            flash(trans_function('purchase_success', default='Coins purchased successfully'), 'success')
            logger.info(f"User {current_user.id} purchased {amount} coins via {payment_method}")
            return redirect(url_for('coins_blueprint.history'))
        except ValueError as e:
            logger.error(f"User not found for coin purchase: {str(e)}")
            flash(trans_function('user_not_found', default='User not found'), 'danger')
            return render_template('coins/purchase.html', form=form), 404
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error purchasing coins for user {current_user.id}: {str(e)}")
            flash(trans_function('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('coins/purchase.html', form=form), 500
        except Exception as e:
            logger.error(f"Unexpected error purchasing coins for user {current_user.id}: {str(e)}")
            flash(trans_function('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('coins/purchase.html', form=form), 500
    return render_template('coins/purchase.html', form=form)

@coins_bp.route('/history', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def history():
    """View coin transaction history."""
    try:
        db = get_mongo_db()
        user_query = get_user_query(str(current_user.id))
        user = db.users.find_one(user_query)
        # TEMPORARY: Allow admin to view all transactions during testing
        # TODO: Restore original query {'user_id': str(current_user.id)} for production
        query = {} if is_admin() else {'user_id': str(current_user.id)}
        transactions = list(db.coin_transactions.find(query).sort('date', -1).limit(50))
        for tx in transactions:
            tx['_id'] = str(tx['_id'])
        return render_template(
            'coins/history.html',
            transactions=transactions,
            coin_balance=user.get('coin_balance', 0) if user else 0
        )
    except Exception as e:
        logger.error(f"Error fetching coin history for user {current_user.id}: {str(e)}")
        flash(trans_function('core_something_went_wrong', default='An error occurred'), 'danger')
        return render_template('coins/history.html', transactions=[], coin_balance=0), 500

@coins_bp.route('/receipt_upload', methods=['GET', 'POST'])
@login_required
@requires_role(['trader', 'personal'])
@limiter.limit("10 per hour")
def receipt_upload():
    """Handle payment receipt uploads with transaction for coin deduction."""
    form = ReceiptUploadForm()
    # TEMPORARY: Bypass coin check for admin during testing
    # TODO: Restore original check_coin_balance(1) for production
    if not is_admin() and not check_coin_balance(1):
        flash(
            trans_function('insufficient_coins', default='Insufficient coins to upload receipt. Purchase more coins.'),
            'danger'
        )
        return redirect(url_for('coins_blueprint.purchase'))
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            client = db.client  # Get MongoDB client for session
            fs = GridFS(db)
            receipt_file = form.receipt.data
            ref = f"RECEIPT_UPLOAD_{datetime.utcnow().isoformat()}"
            
            with client.start_session() as session:
                with session.start_transaction():
                    # Store receipt file
                    file_id = fs.put(
                        receipt_file,
                        filename=receipt_file.filename,
                        user_id=str(current_user.id),
                        upload_date=datetime.utcnow(),
                        session=session
                    )
                    
                    # Deduct coins and log transaction (non-admin only)
                    if not is_admin():
                        user_query = get_user_query(str(current_user.id))
                        result = db.users.update_one(
                            user_query,
                            {'$inc': {'coin_balance': -1}},
                            session=session
                        )
                        if result.matched_count == 0:
                            logger.error(f"No user found for ID {current_user.id} to deduct coins")
                            raise ValueError(f"No user found for ID {current_user.id}")
                        
                        db.coin_transactions.insert_one({
                            'user_id': str(current_user.id),
                            'amount': -1,
                            'type': 'spend',
                            'ref': ref,
                            'date': datetime.utcnow()
                        }, session=session)
                    
                    # Insert audit log
                    db.audit_logs.insert_one({
                        'admin_id': 'system',
                        'action': 'receipt_upload',
                        'details': {'user_id': str(current_user.id), 'file_id': str(file_id), 'ref': ref},
                        'timestamp': datetime.utcnow()
                    }, session=session)
            
            flash(trans_function('receipt_uploaded', default='Receipt uploaded successfully'), 'success')
            logger.info(f"User {current_user.id} uploaded receipt {file_id}")
            return redirect(url_for('coins_blueprint.history'))
        except ValueError as e:
            logger.error(f"User not found for receipt upload: {str(e)}")
            flash(trans_function('user_not_found', default='User not found'), 'danger')
            return render_template('coins/receipt_upload.html', form=form), 404
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error uploading receipt for user {current_user.id}: {str(e)}")
            flash(trans_function('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('coins/receipt_upload.html', form=form), 500
        except Exception as e:
            logger.error(f"Unexpected error uploading receipt for user {current_user.id}: {str(e)}")
            flash(trans_function('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('coins/receipt_upload.html', form=form), 500
    return render_template('coins/receipt_upload.html', form=form)

@coins_bp.route('/balance', methods=['GET'])
@login_required
@limiter.limit("100 per minute")
def get_balance():
    """API endpoint to fetch current coin balance."""
    try:
        if not current_user.is_authenticated or not current_user.id:
            logger.warning("Unauthorized access attempt to /coins/balance")
            return jsonify({'error': trans_function('unauthorized', default='Unauthorized access')}), 401
        user_id = str(current_user.id)
        db = get_mongo_db()
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            logger.error(f"User not found: {user_id}")
            return jsonify({'error': trans_function('user_not_found', default='User not found')}), 404
        coin_balance = user.get('coin_balance', 0)
        logger.info(f"Fetched coin balance for user {user_id}: {coin_balance}")
        return jsonify({'coin_balance': coin_balance}), 200
    except Exception as e:
        logger.error(f"Error fetching coin balance for user {user_id}: {str(e)}")
        return jsonify({'error': trans_function('core_something_went_wrong', default='An error occurred')}), 500
