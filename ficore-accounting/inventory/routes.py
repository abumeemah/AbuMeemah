from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date, get_mongo_db, is_admin, get_user_query
from bson import ObjectId
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, FloatField, SubmitField
from wtforms.validators import DataRequired, Optional
import logging

logger = logging.getLogger(__name__)

class InventoryForm(FlaskForm):
    item_name = StringField('Item Name', validators=[DataRequired()])
    qty = IntegerField('Quantity', validators=[DataRequired()])
    unit = StringField('Unit', validators=[DataRequired()])
    buying_price = FloatField('Buying Price', validators=[DataRequired()])
    selling_price = FloatField('Selling Price', validators=[DataRequired()])
    threshold = IntegerField('Low Stock Threshold', validators=[Optional()])
    submit = SubmitField('Add Item')

inventory_bp = Blueprint('inventory', __name__, url_prefix='/inventory')

@inventory_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """List all inventory items for the current user."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to view all inventory items during testing
        # TODO: Restore original user_id filter {'user_id': str(current_user.id)} for production
        query = {} if is_admin() else {'user_id': str(current_user.id)}
        items = list(db.inventory.find(query).sort('created_at', -1))
        return render_template('inventory/index.html', items=items, format_currency=format_currency)
    except Exception as e:
        logger.error(f"Error fetching inventory for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard_blueprint.index'))

@inventory_bp.route('/low_stock')
@login_required
@requires_role('trader')
def low_stock():
    """List inventory items with low stock."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to view all low stock items during testing
        # TODO: Restore original user_id filter for production
        base_query = {} if is_admin() else {'user_id': str(current_user.id)}
        # Use $expr to compare qty with threshold field
        query = {**base_query, '$expr': {'$lte': ['$qty', '$threshold']}}
        low_stock_items = list(db.inventory.find(query).sort('qty', 1))
        return render_template('inventory/low_stock.html', items=low_stock_items, format_currency=format_currency)
    except Exception as e:
        logger.error(f"Error fetching low stock items for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('inventory_blueprint.index'))

@inventory_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def add():
    """Add a new inventory item."""
    form = InventoryForm()
    # TEMPORARY: Bypass coin check for admin during testing
    # TODO: Restore original check_coin_balance(1) for production
    if not is_admin() and not check_coin_balance(1):
        flash(trans_function('insufficient_coins', default='Insufficient coins to add an item. Purchase more coins.'), 'danger')
        return redirect(url_for('coins_blueprint.purchase'))
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            item = {
                'user_id': str(current_user.id),
                'item_name': form.item_name.data,
                'qty': form.qty.data,
                'unit': form.unit.data,
                'buying_price': form.buying_price.data,
                'selling_price': form.selling_price.data,
                'threshold': form.threshold.data or 5,  # Default threshold
                'created_at': datetime.utcnow()
            }
            db.inventory.insert_one(item)
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
                    'ref': f"Inventory item creation: {item['item_name']}"
                })
            flash(trans_function('add_item_success', default='Inventory item added successfully'), 'success')
            return redirect(url_for('inventory_blueprint.index'))
        except Exception as e:
            logger.error(f"Error adding inventory item for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return render_template('inventory/add.html', form=form)

@inventory_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def edit(id):
    """Edit an existing inventory item."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to edit any inventory item during testing
        # TODO: Restore original user_id filter {'_id': ObjectId(id), 'user_id': str(current_user.id)} for production
        query = {'_id': ObjectId(id)} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id)}
        item = db.inventory.find_one(query)
        if not item:
            flash(trans_function('item_not_found', default='Item not found'), 'danger')
            return redirect(url_for('inventory_blueprint.index'))
        form = InventoryForm(data={
            'item_name': item['item_name'],
            'qty': item['qty'],
            'unit': item['unit'],
            'buying_price': item['buying_price'],
            'selling_price': item['selling_price'],
            'threshold': item.get('threshold', 5)
        })
        if form.validate_on_submit():
            try:
                updated_item = {
                    'item_name': form.item_name.data,
                    'qty': form.qty.data,
                    'unit': form.unit.data,
                    'buying_price': form.buying_price.data,
                    'selling_price': form.selling_price.data,
                    'threshold': form.threshold.data or 5,
                    'updated_at': datetime.utcnow()
                }
                db.inventory.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_item}
                )
                flash(trans_function('edit_item_success', default='Inventory item updated successfully'), 'success')
                return redirect(url_for('inventory_blueprint.index'))
            except Exception as e:
                logger.error(f"Error updating inventory item {id} for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return render_template('inventory/edit.html', form=form, item=item)
    except Exception as e:
        logger.error(f"Error fetching inventory item {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('item_not_found', default='Item not found'), 'danger')
        return redirect(url_for('inventory_blueprint.index'))

@inventory_bp.route('/delete/<id>', methods=['POST'])
@login_required
@requires_role('trader')
def delete(id):
    """Delete an inventory item."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to delete any inventory item during testing
        # TODO: Restore original user_id filter {'_id': ObjectId(id), 'user_id': str(current_user.id)} for production
        query = {'_id': ObjectId(id)} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id)}
        result = db.inventory.delete_one(query)
        if result.deleted_count:
            flash(trans_function('delete_item_success', default='Inventory item deleted successfully'), 'success')
        else:
            flash(trans_function('item_not_found', default='Item not found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting inventory item {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return redirect(url_for('inventory_blueprint.index'))
