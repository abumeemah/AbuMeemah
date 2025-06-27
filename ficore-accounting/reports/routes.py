from flask import Blueprint, render_template, Response, flash, request
from flask_login import login_required, current_user
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date, get_mongo_db, is_admin, get_user_query
from bson import ObjectId
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
from flask_wtf import FlaskForm
from wtforms import DateField, StringField, SubmitField
from wtforms.validators import Optional
import csv
import logging

logger = logging.getLogger(__name__)

class ReportForm(FlaskForm):
    start_date = DateField('Start Date', validators=[Optional()])
    end_date = DateField('End Date', validators=[Optional()])
    category = StringField('Category', validators=[Optional()])
    submit = SubmitField('Generate Report')

class InventoryReportForm(FlaskForm):
    item_name = StringField('Item Name', validators=[Optional()])
    submit = SubmitField('Generate Report')

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')

@reports_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """Display report selection page."""
    try:
        return render_template('reports/index.html')
    except Exception as e:
        logger.error(f"Error loading reports index for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard_blueprint.index'))

@reports_bp.route('/profit_loss', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def profit_loss():
    """Generate profit/loss report with filters."""
    form = ReportForm()
    # TEMPORARY: Bypass coin check for admin during testing
    # TODO: Restore original check_coin_balance(1) for production
    if not is_admin() and not check_coin_balance(1):
        flash(trans_function('insufficient_coins', default='Insufficient coins to generate a report. Purchase more coins.'), 'danger')
        return redirect(url_for('coins_blueprint.purchase'))
    cashflows = []
    # TEMPORARY: Allow admin to view all cashflows during testing
    # TODO: Restore original user_id filter {'user_id': str(current_user.id)} for production
    query = {} if is_admin() else {'user_id': str(current_user.id)}
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            if form.start_date.data:
                query['created_at'] = {'$gte': form.start_date.data}
            if form.end_date.data:
                query['created_at'] = query.get('created_at', {}) | {'$lte': form.end_date.data}
            if form.category.data:
                query['category'] = form.category.data
            cashflows = list(db.cashflows.find(query).sort('created_at', -1))
            output_format = request.form.get('format', 'html')
            if output_format == 'pdf':
                return generate_profit_loss_pdf(cashflows)
            elif output_format == 'csv':
                return generate_profit_loss_csv(cashflows)
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
                    'ref': 'Profit/Loss report generation'
                })
        except Exception as e:
            logger.error(f"Error generating profit/loss report for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    else:
        db = get_mongo_db()
        cashflows = list(db.cashflows.find(query).sort('created_at', -1))
    return render_template('reports/profit_loss.html', form=form, cashflows=cashflows, format_currency=format_currency, format_date=format_date)

@reports_bp.route('/inventory', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def inventory():
    """Generate inventory report with filters."""
    form = InventoryReportForm()
    # TEMPORARY: Bypass coin check for admin during testing
    # TODO: Restore original check_coin_balance(1) for production
    if not is_admin() and not check_coin_balance(1):
        flash(trans_function('insufficient_coins', default='Insufficient coins to generate a report. Purchase more coins.'), 'danger')
        return redirect(url_for('coins_blueprint.purchase'))
    items = []
    # TEMPORARY: Allow admin to view all inventory items during testing
    # TODO: Restore original user_id filter {'user_id': str(current_user.id)} for production
    query = {} if is_admin() else {'user_id': str(current_user.id)}
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            if form.item_name.data:
                query['item_name'] = {'$regex': form.item_name.data, '$options': 'i'}
            items = list(db.inventory.find(query).sort('item_name', 1))
            output_format = request.form.get('format', 'html')
            if output_format == 'pdf':
                return generate_inventory_pdf(items)
            elif output_format == 'csv':
                return generate_inventory_csv(items)
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
                    'ref': 'Inventory report generation'
                })
        except Exception as e:
            logger.error(f"Error generating inventory report for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    else:
        db = get_mongo_db()
        items = list(db.inventory.find(query).sort('item_name', 1))
    return render_template('reports/inventory.html', form=form, items=items, format_currency=format_currency)

def generate_profit_loss_pdf(cashflows):
    """Generate PDF for profit/loss report."""
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    p.setFont("Helvetica", 12)
    p.drawString(1 * inch, 10.5 * inch, trans_function('profit_loss_report', default='Profit/Loss Report'))
    p.drawString(1 * inch, 10.2 * inch, f"{trans_function('generated_on', default='Generated on')}: {format_date(datetime.utcnow())}")
    y = 9.5 * inch
    p.setFillColor(colors.black)
    p.drawString(1 * inch, y, trans_function('date', default='Date'))
    p.drawString(2.5 * inch, y, trans_function('party_name', default='Party Name'))
    p.drawString(4 * inch, y, trans_function('type', default='Type'))
    p.drawString(5 * inch, y, trans_function('amount', default='Amount'))
    p.drawString(6.5 * inch, y, trans_function('category', default='Category'))
    y -= 0.3 * inch
    total_income = 0
    total_expense = 0
    for t in cashflows:
        p.drawString(1 * inch, y, format_date(t['created_at']))
        p.drawString(2.5 * inch, y, t['party_name'])
        p.drawString(4 * inch, y, trans_function(t['type'], default=t['type']))
        p.drawString(5 * inch, y, format_currency(t['amount']))
        p.drawString(6.5 * inch, y, trans_function(t.get('category', ''), default=t.get('category', '')))
        if t['type'] == 'receipt':
            total_income += t['amount']
        else:
            total_expense += t['amount']
        y -= 0.3 * inch
        if y < 1 * inch:
            p.showPage()
            y = 10.5 * inch
    y -= 0.3 * inch
    p.drawString(1 * inch, y, f"{trans_function('total_income', default='Total Income')}: {format_currency(total_income)}")
    y -= 0.3 * inch
    p.drawString(1 * inch, y, f"{trans_function('total_expense', default='Total Expense')}: {format_currency(total_expense)}")
    y -= 0.3 * inch
    p.drawString(1 * inch, y, f"{trans_function('net_profit', default='Net Profit')}: {format_currency(total_income - total_expense)}")
    p.showPage()
    p.save()
    buffer.seek(0)
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=profit_loss.pdf'})

def generate_profit_loss_csv(cashflows):
    """Generate CSV for profit/loss report."""
    output = []
    output.append([trans_function('date', default='Date'), trans_function('party_name', default='Party Name'), trans_function('type', default='Type'), trans_function('amount', default='Amount'), trans_function('category', default='Category')])
    total_income = 0
    total_expense = 0
    for t in cashflows:
        output.append([format_date(t['created_at']), t['party_name'], trans_function(t['type'], default=t['type']), format_currency(t['amount']), trans_function(t.get('category', ''), default=t.get('category', ''))])
        if t['type'] == 'receipt':
            total_income += t['amount']
        else:
            total_expense += t['amount']
    output.append(['', '', '', f"{trans_function('total_income', default='Total Income')}: {format_currency(total_income)}", ''])
    output.append(['', '', '', f"{trans_function('total_expense', default='Total Expense')}: {format_currency(total_expense)}", ''])
    output.append(['', '', '', f"{trans_function('net_profit', default='Net Profit')}: {format_currency(total_income - total_expense)}", ''])
    buffer = BytesIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(output)
    buffer.seek(0)
    return Response(buffer, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=profit_loss.csv'})

def generate_inventory_pdf(items):
    """Generate PDF for inventory report."""
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    p.setFont("Helvetica", 12)
    p.drawString(1 * inch, 10.5 * inch, trans_function('inventory_report', default='Inventory Report'))
    p.drawString(1 * inch, 10.2 * inch, f"{trans_function('generated_on', default='Generated on')}: {format_date(datetime.utcnow())}")
    y = 9.5 * inch
    p.setFillColor(colors.black)
    p.drawString(1 * inch, y, trans_function('item_name', default='Item Name'))
    p.drawString(2.5 * inch, y, trans_function('quantity', default='Quantity'))
    p.drawString(3.5 * inch, y, trans_function('unit', default='Unit'))
    p.drawString(4.5 * inch, y, trans_function('buying_price', default='Buying Price'))
    p.drawString(5.5 * inch, y, trans_function('selling_price', default='Selling Price'))
    p.drawString(6.5 * inch, y, trans_function('threshold', default='Threshold'))
    y -= 0.3 * inch
    for item in items:
        p.drawString(1 * inch, y, item['item_name'])
        p.drawString(2.5 * inch, y, str(item['qty']))
        p.drawString(3.5 * inch, y, trans_function(item['unit'], default=item['unit']))
        p.drawString(4.5 * inch, y, format_currency(item['buying_price']))
        p.drawString(5.5 * inch, y, format_currency(item['selling_price']))
        p.drawString(6.5 * inch, y, str(item.get('threshold', 5)))
        y -= 0.3 * inch
        if y < 1 * inch:
            p.showPage()
            y = 10.5 * inch
    p.showPage()
    p.save()
    buffer.seek(0)
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=inventory.pdf'})

def generate_inventory_csv(items):
    """Generate CSV for inventory report."""
    output = []
    output.append([trans_function('item_name', default='Item Name'), trans_function('quantity', default='Quantity'), trans_function('unit', default='Unit'), trans_function('buying_price', default='Buying Price'), trans_function('selling_price', default='Selling Price'), trans_function('threshold', default='Threshold')])
    for item in items:
        output.append([item['item_name'], item['qty'], trans_function(item['unit'], default=item['unit']), format_currency(item['buying_price']), format_currency(item['selling_price']), item.get('threshold', 5)])
    buffer = BytesIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(output)
    buffer.seek(0)
    return Response(buffer, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=inventory.csv'})
