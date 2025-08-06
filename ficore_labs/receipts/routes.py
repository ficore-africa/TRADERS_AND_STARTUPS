from flask import Blueprint, render_template, redirect, url_for, flash, request, Response, jsonify, session
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFError
from translations import trans
import utils
from bson import ObjectId
from datetime import datetime, timezone, date
from zoneinfo import ZoneInfo
from wtforms import StringField, DateField, FloatField, SelectField, SubmitField
from wtforms.validators import DataRequired, Optional, Length, NumberRange
import logging
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

logger = logging.getLogger(__name__)

class ReceiptForm(FlaskForm):
    party_name = StringField(trans('receipts_party_name', default='Customer Name'), validators=[DataRequired(), Length(max=100)])
    date = DateField(trans('general_date', default='Date'), validators=[DataRequired()])
    amount = FloatField(trans('general_amount', default='Sale Amount'), validators=[DataRequired(), NumberRange(min=0.01)])
    method = SelectField(trans('general_payment_method', default='Payment Method'), choices=[
        ('cash', trans('general_cash', default='Cash')),
        ('card', trans('general_card', default='Card')),
        ('bank', trans('general_bank_transfer', default='Bank Transfer'))
    ], validators=[Optional()])
    category = StringField(trans('general_category', default='Category'), validators=[Optional(), Length(max=50)])
    contact = StringField(trans('general_contact', default='Contact'), validators=[Optional(), Length(max=100)])
    description = StringField(trans('general_description', default='Description'), validators=[Optional(), Length(max=1000)])
    submit = SubmitField(trans('receipts_add_receipt', default='Record Sale'))

receipts_bp = Blueprint('receipts', __name__, url_prefix='/receipts')

@receipts_bp.route('/')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def index():
    """List all sales income cashflows for the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'user_id': str(current_user.id), 'type': 'receipt'}
        receipts = list(db.cashflows.find(query).sort('created_at', -1))
        
        # Convert naive datetimes to timezone-aware
        for receipt in receipts:
            if receipt.get('created_at') and receipt['created_at'].tzinfo is None:
                receipt['created_at'] = receipt['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        logger.info(
            f"Fetched receipts for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return render_template(
            'receipts/index.html',
            receipts=receipts,
            format_currency=utils.format_currency,
            format_date=utils.format_date,
            title=trans('receipts_title', default='Money In', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        )
    except Exception as e:
        logger.error(
            f"Error fetching receipts for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('receipts_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@receipts_bp.route('/manage')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def manage():
    """Manage all receipt cashflows for the current user (edit/delete)."""
    try:
        db = utils.get_mongo_db()
        query = {'user_id': str(current_user.id), 'type': 'receipt'}
        receipts = list(db.cashflows.find(query).sort('created_at', -1))
        
        # Convert naive datetimes to timezone-aware
        for receipt in receipts:
            if receipt.get('created_at') and receipt['created_at'].tzinfo is None:
                receipt['created_at'] = receipt['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        logger.info(
            f"Fetched receipts for manage page for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return render_template(
            'receipts/manage.html',
            receipts=receipts,
            format_currency=utils.format_currency,
            format_date=utils.format_date,
            title=trans('receipts_manage', default='Manage Receipts', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        )
    except Exception as e:
        logger.error(
            f"Error fetching receipts for manage page for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('receipts_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('receipts.index'))

@receipts_bp.route('/view/<id>')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def view(id):
    """View detailed information about a specific receipt."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        receipt = db.cashflows.find_one(query)
        if not receipt:
            logger.warning(
                f"Receipt {id} not found for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({'error': trans('receipts_record_not_found', default='Record not found')}), 404
        
        # Convert naive datetimes to timezone-aware
        if receipt.get('created_at') and receipt['created_at'].tzinfo is None:
            receipt['created_at'] = receipt['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        receipt['_id'] = str(receipt['_id'])
        receipt['created_at'] = receipt['created_at'].isoformat() if receipt.get('created_at') else None
        logger.info(
            f"Fetched receipt {id} for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify(receipt)
    except ValueError:
        logger.error(
            f"Invalid receipt ID {id} for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({'error': trans('receipts_invalid_id', default='Invalid receipt ID')}), 404
    except Exception as e:
        logger.error(
            f"Error fetching receipt {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({'error': trans('receipts_fetch_error', default='An error occurred')}), 500

@receipts_bp.route('/generate_pdf/<id>')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def generate_pdf(id):
    """Generate PDF receipt for a receipt transaction."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('receipts_subscription_required', default='Your trial has expired or you do not have an active subscription. Please subscribe to generate a PDF receipt.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        receipt = db.cashflows.find_one(query)
        if not receipt:
            logger.warning(
                f"Receipt {id} not found for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('receipts_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('receipts.index'))
        
        # Convert naive datetimes to timezone-aware
        if receipt.get('created_at') and receipt['created_at'].tzinfo is None:
            receipt['created_at'] = receipt['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        # Sanitize inputs for PDF generation
        receipt['party_name'] = utils.sanitize_input(receipt['party_name'], max_length=100)
        receipt['category'] = utils.sanitize_input(receipt.get('category', 'No category provided'), max_length=50)
        receipt['contact'] = utils.sanitize_input(receipt.get('contact', ''), max_length=100) if receipt.get('contact') else ''
        receipt['description'] = utils.sanitize_input(receipt.get('description', ''), max_length=1000) if receipt.get('description') else ''
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, height - inch, trans('receipts_pdf_title', default='FiCore Records - Money In Receipt'))
        p.setFont("Helvetica", 12)
        y_position = height - inch - 0.5 * inch
        p.drawString(inch, y_position, f"{trans('receipts_party_name', default='Payer')}: {receipt['party_name']}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"{trans('general_amount', default='Amount Received')}: {utils.format_currency(receipt['amount'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"{trans('general_payment_method', default='Payment Method')}: {receipt.get('method', 'N/A')}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"{trans('general_category', default='Category')}: {receipt['category']}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"{trans('general_date', default='Date')}: {utils.format_date(receipt['created_at'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"{trans('receipts_id', default='Receipt ID')}: {str(receipt['_id'])}")
        y_position -= 0.3 * inch
        if receipt['contact']:
            p.drawString(inch, y_position, f"{trans('general_contact', default='Contact')}: {receipt['contact']}")
            y_position -= 0.3 * inch
        if receipt['description']:
            p.drawString(inch, y_position, f"{trans('general_description', default='Description')}: {receipt['description']}")
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, trans('receipts_pdf_footer', default='This document serves as an official receipt generated by FiCore Records.'))
        p.showPage()
        p.save()
        buffer.seek(0)
        logger.info(
            f"Generated PDF for receipt {id} for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=receipt_{utils.sanitize_input(receipt["party_name"], max_length=50)}_{str(receipt["_id"])}.pdf'
            }
        )
    except ValueError:
        logger.error(
            f"Invalid receipt ID {id} for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('receipts_invalid_id', default='Invalid receipt ID'), 'danger')
        return redirect(url_for('receipts.index'))
    except Exception as e:
        logger.error(
            f"Error generating PDF for receipt {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('receipts_pdf_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('receipts.index'))

@receipts_bp.route('/add', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
@utils.limiter.limit('10 per minute')
def add():
    """Add a new receipt cashflow."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('receipts_subscription_required', default='Your trial has expired or you do not have an active subscription. Please subscribe to add a receipt.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        form = ReceiptForm()
        if form.validate_on_submit():
            try:
                db = utils.get_mongo_db()
                # Convert date to datetime with UTC timezone
                receipt_date = datetime.combine(form.date.data, datetime.min.time(), tzinfo=ZoneInfo("UTC"))
                cashflow = {
                    'user_id': str(current_user.id),
                    'type': 'receipt',
                    'party_name': utils.sanitize_input(form.party_name.data, max_length=100),
                    'amount': form.amount.data,
                    'method': form.method.data,
                    'category': utils.sanitize_input(form.category.data, max_length=50) if form.category.data else None,
                    'contact': utils.sanitize_input(form.contact.data, max_length=100) if form.contact.data else None,
                    'description': utils.sanitize_input(form.description.data, max_length=1000) if form.description.data else None,
                    'created_at': receipt_date,
                    'updated_at': datetime.now(timezone.utc)
                }
                db.cashflows.insert_one(cashflow)
                logger.info(
                    f"Receipt added for user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('receipts_add_success', default='Receipt added successfully'), 'success')
                return redirect(url_for('receipts.index'))
            except Exception as e:
                logger.error(
                    f"Error adding receipt for user {current_user.id}: {str(e)}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('receipts_add_error', default='An error occurred'), 'danger')
        return render_template(
            'receipts/add.html',
            form=form,
            title=trans('receipts_add_title', default='Add Money In', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        )
    except CSRFError as e:
        logger.error(
            f"CSRF error in adding receipt for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('receipts_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return render_template(
            'receipts/add.html',
            form=form,
            title=trans('receipts_add_title', default='Add Money In', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        ), 400

@receipts_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
@utils.limiter.limit('10 per minute')
def edit(id):
    """Edit an existing receipt cashflow."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('receipts_subscription_required', default='Your trial has expired or you do not have an active subscription. Please subscribe to edit receipts.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        receipt = db.cashflows.find_one(query)
        if not receipt:
            logger.warning(
                f"Receipt {id} not found for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('receipts_record_not_found', default='Cashflow not found'), 'danger')
            return redirect(url_for('receipts.index'))
        
        # Convert naive datetimes to timezone-aware
        if receipt.get('created_at') and receipt['created_at'].tzinfo is None:
            receipt['created_at'] = receipt['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        form = ReceiptForm(data={
            'party_name': receipt['party_name'],
            'date': receipt['created_at'].date(),  # Extract date part for form
            'amount': receipt['amount'],
            'method': receipt.get('method'),
            'category': receipt.get('category'),
            'contact': receipt.get('contact'),
            'description': receipt.get('description')
        })
        if form.validate_on_submit():
            try:
                # Convert date to datetime with UTC timezone
                receipt_date = datetime.combine(form.date.data, datetime.min.time(), tzinfo=ZoneInfo("UTC"))
                updated_cashflow = {
                    'party_name': utils.sanitize_input(form.party_name.data, max_length=100),
                    'amount': form.amount.data,
                    'method': form.method.data,
                    'category': utils.sanitize_input(form.category.data, max_length=50) if form.category.data else None,
                    'contact': utils.sanitize_input(form.contact.data, max_length=100) if form.contact.data else None,
                    'description': utils.sanitize_input(form.description.data, max_length=1000) if form.description.data else None,
                    'created_at': receipt_date,
                    'updated_at': datetime.now(timezone.utc)
                }
                db.cashflows.update_one({'_id': ObjectId(id)}, {'$set': updated_cashflow})
                logger.info(
                    f"Receipt {id} updated for user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('receipts_edit_success', default='Receipt updated successfully'), 'success')
                return redirect(url_for('receipts.index'))
            except Exception as e:
                logger.error(
                    f"Error updating receipt {id} for user {current_user.id}: {str(e)}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('receipts_edit_error', default='An error occurred'), 'danger')
        return render_template(
            'receipts/edit.html',
            form=form,
            receipt=receipt,
            title=trans('receipts_edit_title', default='Edit Receipt', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        )
    except ValueError:
        logger.error(
            f"Invalid receipt ID {id} for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('receipts_invalid_id', default='Invalid receipt ID'), 'danger')
        return redirect(url_for('receipts.index'))
    except CSRFError as e:
        logger.error(
            f"CSRF error in editing receipt {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('receipts_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return render_template(
            'receipts/edit.html',
            form=form,
            receipt=receipt,
            title=trans('receipts_edit_title', default='Edit Receipt', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        ), 400
    except Exception as e:
        logger.error(
            f"Error fetching receipt {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('receipts_record_not_found', default='Cashflow not found'), 'danger')
        return redirect(url_for('receipts.index'))

@receipts_bp.route('/delete/<id>', methods=['POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
@utils.limiter.limit('10 per minute')
def delete(id):
    """Delete a receipt cashflow."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('receipts_subscription_required', default='Your trial has expired or you do not have an active subscription. Please subscribe to delete receipts.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        result = db.cashflows.delete_one(query)
        if result.deleted_count:
            logger.info(
                f"Receipt {id} deleted for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('receipts_delete_success', default='Receipt deleted successfully'), 'success')
        else:
            logger.warning(
                f"Receipt {id} not found for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('receipts_record_not_found', default='Cashflow not found'), 'danger')
        return redirect(url_for('receipts.index'))
    except ValueError:
        logger.error(
            f"Invalid receipt ID {id} for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('receipts_invalid_id', default='Invalid receipt ID'), 'danger')
        return redirect(url_for('receipts.index'))
    except CSRFError as e:
        logger.error(
            f"CSRF error in deleting receipt {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('receipts_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return redirect(url_for('receipts.index'))
    except Exception as e:
        logger.error(
            f"Error deleting receipt {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('receipts_delete_error', default='An error occurred'), 'danger')
        return redirect(url_for('receipts.index'))

@receipts_bp.route('/share', methods=['POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
@utils.limiter.limit('10 per minute')
def share():
    """Share a receipt via SMS or WhatsApp."""
    try:
        if not utils.can_user_interact(current_user):
            return jsonify({
                'success': False,
                'message': trans('receipts_subscription_required', default='Your trial has expired or you do not have an active subscription. Please subscribe to share receipts.')
            }), 403
        
        data = request.get_json()
        receipt_id = data.get('receiptId')
        recipient = utils.sanitize_input(data.get('recipient'), max_length=100)
        message = utils.sanitize_input(data.get('message'), max_length=1000)
        share_type = data.get('type')
        
        if not all([receipt_id, recipient, message, share_type]):
            logger.error(
                f"Missing fields in share receipt request for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({
                'success': False,
                'message': trans('receipts_missing_fields', default='Missing required fields')
            }), 400
        
        valid_share_types = ['sms', 'whatsapp']
        if share_type not in valid_share_types:
            logger.error(
                f"Invalid share type {share_type} in share receipt request for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({
                'success': False,
                'message': trans('receipts_invalid_share_type', default='Invalid share type')
            }), 400
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(receipt_id), 'user_id': str(current_user.id), 'type': 'receipt'}
        receipt = db.cashflows.find_one(query)
        if not receipt:
            logger.warning(
                f"Receipt {receipt_id} not found for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({
                'success': False,
                'message': trans('receipts_record_not_found', default='Receipt not found')
            }), 404
        
        success = utils.send_message(recipient=recipient, message=message, type=share_type)
        if success:
            logger.info(
                f"Receipt {receipt_id} shared via {share_type} for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({'success': True})
        else:
            logger.error(
                f"Failed to share receipt {receipt_id} via {share_type} for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({
                'success': False,
                'message': trans('receipts_share_failed', default='Failed to share receipt')
            }), 500
    except ValueError:
        logger.error(
            f"Invalid receipt ID {receipt_id} for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({
            'success': False,
            'message': trans('receipts_invalid_id', default='Invalid receipt ID')
        }), 404
    except CSRFError as e:
        logger.error(
            f"CSRF error in sharing receipt {receipt_id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({
            'success': False,
            'message': trans('receipts_csrf_error', default='Invalid CSRF token. Please try again.')
        }), 400
    except Exception as e:
        logger.error(
            f"Error sharing receipt {receipt_id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({
            'success': False,
            'message': trans('receipts_share_error', default='Error sharing receipt')
        }), 500
