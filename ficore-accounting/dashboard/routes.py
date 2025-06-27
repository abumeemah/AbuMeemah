from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from utils import trans_function, requires_role, format_currency, format_date, get_mongo_db, is_admin
from bson import ObjectId
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

@dashboard_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """Display the user's dashboard with recent activity."""
    try:
        db = get_mongo_db()
        # Determine query based on user role
        query = {} if is_admin() else {'user_id': str(current_user.id)}
        low_stock_query = {'qty': {'$lte': 5}} if is_admin() else {'user_id': str(current_user.id), 'qty': {'$lte': 5}}  # Assume threshold=5 for simplicity

        # Fetch recent data using new schema
        recent_creditors = list(db.records.find({**query, 'type': 'creditor'}).sort('created_at', -1).limit(5))
        recent_debtors = list(db.records.find({**query, 'type': 'debtor'}).sort('created_at', -1).limit(5))
        recent_payments = list(db.cashflows.find({**query, 'type': 'payment'}).sort('created_at', -1).limit(5))
        recent_receipts = list(db.cashflows.find({**query, 'type': 'receipt'}).sort('created_at', -1).limit(5))
        low_stock_items = list(db.inventory.find(low_stock_query).sort('qty', 1).limit(5))

        # Convert ObjectIds to strings for template rendering
        for item in recent_creditors + recent_debtors + recent_payments + recent_receipts + low_stock_items:
            item['_id'] = str(item['_id'])

        return render_template(
            'dashboard/index.html',
            recent_creditors=recent_creditors,
            recent_debtors=recent_debtors,
            recent_payments=recent_payments,
            recent_receipts=recent_receipts,
            low_stock_items=low_stock_items,
            format_currency=format_currency,
            format_date=format_date
        )
    except Exception as e:
        logger.error(f"Error fetching dashboard data for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred while loading the dashboard'), 'danger')
        return redirect(url_for('index'))
