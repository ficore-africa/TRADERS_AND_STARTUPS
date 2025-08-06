from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, Response, session
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional
from bson import ObjectId
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import logging
import io
import re
import urllib.parse
import utils
from translations import trans
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from helpers.branding_helpers import draw_ficore_pdf_header, ficore_csv_header
import csv

logger = logging.getLogger(__name__)

# Placeholder functions for SMS/WhatsApp reminders (implement in utils.py or with external API)
def send_sms_reminder(recipient, message):
    """Placeholder for sending SMS reminder."""
    logger.info(f"Simulating SMS to {recipient}: {message}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'none'})
    return True, {'status': 'SMS sent successfully'}  # Replace with actual API call

def send_whatsapp_reminder(recipient, message):
    """Placeholder for sending WhatsApp reminder."""
    logger.info(f"Simulating WhatsApp to {recipient}: {message}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'none'})
    return True, {'status': 'WhatsApp sent successfully'}  # Replace with actual API call

class DebtorForm(FlaskForm):
    name = StringField(trans('debtors_debtor_name', default="Debtor's Name"), validators=[DataRequired()])
    phone_number = StringField(trans('debtors_phone_number', default="Debtor's Phone Number"), validators=[DataRequired()])
    email = StringField(trans('debtors_email', default='Email'), validators=[Optional()])
    amount_owed = FloatField(trans('debtors_amount_owed', default='Amount Owed'), validators=[DataRequired()])
    description = TextAreaField(trans('debtors_description', default='Description of Transaction'), validators=[Optional()])
    submit = SubmitField(trans('debtors_add_debtor', default='Add Debtor'))

debtors_bp = Blueprint('debtors', __name__, url_prefix='/debtors')

@debtors_bp.route('/')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def index():
    """List all debtor records for the current user (view-only post-trial)."""
    try:
        db = utils.get_mongo_db()
        query = {'user_id': str(current_user.id), 'type': 'debtor'}
        debtors = list(db.records.find(query).sort('created_at', -1))
        
        # Convert naive datetimes to timezone-aware
        for debtor in debtors:
            if debtor.get('created_at') and debtor['created_at'].tzinfo is None:
                debtor['created_at'] = debtor['created_at'].replace(tzinfo=ZoneInfo("UTC"))
            if debtor.get('reminder_date') and debtor['reminder_date'].tzinfo is None:
                debtor['reminder_date'] = debtor['reminder_date'].replace(tzinfo=ZoneInfo("UTC"))
        
        can_interact = utils.can_user_interact(current_user)
        if not can_interact:
            flash(trans('debtors_subscription_required', default='Your trial or subscription has expired. Subscribe to manage your debtors.'), 'warning')
        
        return render_template(
            'debtors/index.html',
            debtors=debtors,
            can_interact=can_interact,
            title=trans('debtors_index', default='Debtors', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching debtors for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@debtors_bp.route('/manage')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def manage():
    """List all debtor records for management (view-only post-trial)."""
    try:
        db = utils.get_mongo_db()
        query = {'user_id': str(current_user.id), 'type': 'debtor'}
        debtors = list(db.records.find(query).sort('created_at', -1))
        
        # Convert naive datetimes to timezone-aware
        for debtor in debtors:
            if debtor.get('created_at') and debtor['created_at'].tzinfo is None:
                debtor['created_at'] = debtor['created_at'].replace(tzinfo=ZoneInfo("UTC"))
            if debtor.get('reminder_date') and debtor['reminder_date'].tzinfo is None:
                debtor['reminder_date'] = debtor['reminder_date'].replace(tzinfo=ZoneInfo("UTC"))
        
        can_interact = utils.can_user_interact(current_user)
        if not can_interact:
            flash(trans('debtors_subscription_required', default='Your trial or subscription has expired. Subscribe to manage your debtors.'), 'warning')
        
        return render_template(
            'debtors/manage_debtors.html',
            debtors=debtors,
            format_currency=utils.format_currency,
            can_interact=can_interact,
            title=trans('debtors_manage', default='Manage Debtors', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching debtors for manage page for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('debtors.index'))

@debtors_bp.route('/view/<id>')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def view(id):
    """View detailed information about a specific debtor (JSON API, view-only post-trial)."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            return jsonify({'error': trans('debtors_record_not_found', default='Record not found')}), 404
        
        # Convert naive datetimes to timezone-aware
        if debtor.get('created_at') and debtor['created_at'].tzinfo is None:
            debtor['created_at'] = debtor['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        if debtor.get('reminder_date') and debtor['reminder_date'].tzinfo is None:
            debtor['reminder_date'] = debtor['reminder_date'].replace(tzinfo=ZoneInfo("UTC"))
        
        debtor['_id'] = str(debtor['_id'])
        debtor['created_at'] = debtor['created_at'].isoformat() if debtor.get('created_at') else None
        debtor['reminder_date'] = debtor['reminder_date'].isoformat() if debtor.get('reminder_date') else None
        debtor['reminder_count'] = debtor.get('reminder_count', 0)
        debtor['can_interact'] = utils.can_user_interact(current_user)
        
        return jsonify(debtor)
    except ValueError:
        logger.error(f"Invalid debtor ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return jsonify({'error': trans('debtors_invalid_id', default='Invalid debtor ID')}), 404
    except Exception as e:
        logger.error(f"Error fetching debtor {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return jsonify({'error': trans('debtors_fetch_error', default='An error occurred')}), 500

@debtors_bp.route('/view_page/<id>')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def view_page(id):
    """Render a detailed view page for a specific debtor (view-only post-trial)."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors.index'))
        
        # Convert naive datetimes to timezone-aware
        if debtor.get('created_at') and debtor['created_at'].tzinfo is None:
            debtor['created_at'] = debtor['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        if debtor.get('reminder_date') and debtor['reminder_date'].tzinfo is None:
            debtor['reminder_date'] = debtor['reminder_date'].replace(tzinfo=ZoneInfo("UTC"))
        
        can_interact = utils.can_user_interact(current_user)
        if not can_interact:
            flash(trans('debtors_subscription_required', default='Your trial or subscription has expired. Subscribe to manage your debtors.'), 'warning')
        
        return render_template(
            'debtors/view.html',
            debtor=debtor,
            can_interact=can_interact,
            title=trans('debtors_debt_details', default='Debt Details', lang=session.get('lang', 'en'))
        )
    except ValueError:
        logger.error(f"Invalid debtor ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_invalid_id', default='Invalid debtor ID'), 'danger')
        return redirect(url_for('debtors.index'))
    except Exception as e:
        logger.error(f"Error rendering debtor view page {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_view_error', default='An error occurred'), 'danger')
        return redirect(url_for('debtors.index'))

@debtors_bp.route('/share/<id>')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def share(id):
    """Generate a WhatsApp link to share IOU details (requires active trial/subscription)."""
    try:
        if not utils.can_user_interact(current_user):
            return jsonify({'success': False, 'message': trans('debtors_subscription_required', default='Your trial or subscription has expired. Please subscribe to share IOUs.')}), 403
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            return jsonify({'success': False, 'message': trans('debtors_record_not_found', default='Record not found')}), 404
        if not debtor.get('phone_number'):
            return jsonify({'success': False, 'message': trans('debtors_no_contact', default='No contact provided for sharing')}), 400
        
        # Convert naive datetimes to timezone-aware
        if debtor.get('created_at') and debtor['created_at'].tzinfo is None:
            debtor['created_at'] = debtor['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        contact = re.sub(r'\D', '', debtor['phone_number'])
        if contact.startswith('0'):
            contact = '234' + contact[1:]
        elif not contact.startswith('+'):
            contact = '234' + contact
        if not re.match(r'^\+?\d{10,15}$', contact):
            return jsonify({'success': False, 'message': trans('debtors_invalid_contact', default='Invalid contact number format')}), 400
        
        message = f"Hi {utils.sanitize_input(debtor['name'], max_length=100)}, this is an IOU for {utils.format_currency(debtor['amount_owed'])} recorded on FiCore Records on {utils.format_date(debtor['created_at'])}. Details: {utils.sanitize_input(debtor.get('description', 'No description provided'), max_length=500)}."
        whatsapp_link = f"https://wa.me/{contact}?text={urllib.parse.quote(message)}"
        
        return jsonify({'success': True, 'whatsapp_link': whatsapp_link})
    except ValueError:
        logger.error(f"Invalid debtor ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return jsonify({'error': trans('debtors_invalid_id', default='Invalid debtor ID')}), 404
    except Exception as e:
        logger.error(f"Error sharing IOU for debtor {id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return jsonify({'success': False, 'message': trans('debtors_share_error', default='An error occurred')}), 500

@debtors_bp.route('/send_reminder', methods=['POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def send_reminder():
    """Send reminder to debtor via SMS/WhatsApp or set snooze (requires active trial/subscription)."""
    try:
        if not utils.can_user_interact(current_user):
            return jsonify({'success': False, 'message': trans('debtors_subscription_required', default='Your trial or subscription has expired. Please subscribe to send reminders.')}), 403
        
        data = request.get_json()
        debt_id = data.get('debtId')
        recipient = data.get('recipient')
        message = data.get('message')
        send_type = data.get('type', 'sms')
        snooze_days = data.get('snooze_days', 0)
        
        if not debt_id or (not recipient and not snooze_days):
            return jsonify({'success': False, 'message': trans('debtors_missing_fields', default='Missing required fields')}), 400
        
        if snooze_days:
            try:
                snooze_days = int(snooze_days)
                if snooze_days < 1 or snooze_days > 30:
                    raise ValueError("Snooze days must be between 1 and 30")
            except ValueError:
                return jsonify({'success': False, 'message': trans('debtors_invalid_snooze', default='Invalid snooze duration')}), 400
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(debt_id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        
        if not debtor:
            return jsonify({'success': False, 'message': trans('debtors_record_not_found', default='Record not found')}), 404
        
        update_data = {'$inc': {'reminder_count': 1}}
        if snooze_days:
            update_data['$set'] = {'reminder_date': datetime.now(timezone.utc) + timedelta(days=snooze_days)}
        
        success = True
        api_response = {}
        
        if recipient:
            if send_type == 'sms':
                success, api_response = send_sms_reminder(recipient, message)
            elif send_type == 'whatsapp':
                success, api_response = send_whatsapp_reminder(recipient, message)
        
        if success:
            db.records.update_one({'_id': ObjectId(debt_id)}, update_data)
            
            db.reminder_logs.insert_one({
                'user_id': str(current_user.id),
                'debt_id': debt_id,
                'recipient': recipient or 'N/A',
                'message': message or 'Snooze',
                'type': send_type if recipient else 'snooze',
                'sent_at': datetime.now(timezone.utc),
                'api_response': api_response if recipient else {'status': f'Snoozed for {snooze_days} days'}
            })
            
            return jsonify({'success': True, 'message': trans('debtors_reminder_sent' if recipient else 'debtors_snooze_set', default='Reminder sent successfully' if recipient else 'Snooze set successfully')})
        else:
            return jsonify({'success': False, 'message': trans('debtors_reminder_failed', default='Failed to send reminder'), 'details': api_response}), 500
            
    except ValueError:
        logger.error(f"Invalid debtor ID {debt_id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return jsonify({'error': trans('debtors_invalid_id', default='Invalid debtor ID')}), 404
    except Exception as e:
        logger.error(f"Error sending reminder for debtor {debt_id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return jsonify({'success': False, 'message': trans('debtors_reminder_error', default='An error occurred')}), 500

@debtors_bp.route('/generate_iou/<id>')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def generate_iou(id):
    """Generate PDF IOU for a debtor (requires active trial/subscription)."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('debtors_subscription_required', default='Your trial or subscription has expired. Please subscribe to generate IOUs.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        
        if not debtor:
            flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors.index'))
        
        # Convert naive datetimes to timezone-aware
        if debtor.get('created_at') and debtor['created_at'].tzinfo is None:
            debtor['created_at'] = debtor['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        if debtor.get('reminder_date') and debtor['reminder_date'].tzinfo is None:
            debtor['reminder_date'] = debtor['reminder_date'].replace(tzinfo=ZoneInfo("UTC"))
        
        # Sanitize inputs for PDF generation
        debtor['name'] = utils.sanitize_input(debtor['name'], max_length=100)
        debtor['description'] = utils.sanitize_input(debtor.get('description', 'No description provided'), max_length=500)
        debtor['phone_number'] = utils.sanitize_input(debtor.get('phone_number', 'N/A'), max_length=50)
        debtor['email'] = utils.sanitize_input(debtor.get('email', 'N/A'), max_length=100)
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        draw_ficore_pdf_header(p, current_user, y_start=10.5 * inch)
        
        # Calculate the Y position for the title
        header_height = 0.7  # From draw_ficore_pdf_header
        extra_space = 0.2  # Additional space below the header
        title_y = 10.5 - header_height - extra_space
        
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, title_y * inch, trans('debtors_iou_title', default='FiCore Records - IOU'))
        
        p.setFont("Helvetica", 12)
        y_position = title_y - 0.5
        p.drawString(inch, y_position * inch, f"{trans('debtors_debtor_name', default='Debtor')}: {debtor['name']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('debtors_amount_owed', default='Amount Owed')}: {utils.format_currency(debtor['amount_owed'])}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('debtors_phone_number', default='Phone Number')}: {debtor['phone_number']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('debtors_email', default='Email')}: {debtor['email']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('debtors_description', default='Description of Transaction')}: {debtor['description']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('debtors_date_recorded', default='Date Recorded')}: {utils.format_date(debtor['created_at'])}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('debtors_reminders_sent', default='Reminders Sent')}: {debtor.get('reminder_count', 0)}")
        
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, trans('debtors_iou_footer', default='This document serves as an IOU recorded on FiCore Records.'))
        
        p.showPage()
        p.save()
        
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_IOU_{utils.sanitize_input(debtor["name"], max_length=50)}.pdf'
            }
        )
        
    except ValueError:
        logger.error(f"Invalid debtor ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_invalid_id', default='Invalid debtor ID'), 'danger')
        return redirect(url_for('debtors.index'))
    except Exception as e:
        logger.error(f"Error generating IOU for debtor {id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_iou_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('debtors.index'))

@debtors_bp.route('/generate_iou_csv/<id>')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def generate_iou_csv(id):
    """Generate CSV IOU for a debtor (requires active trial/subscription)."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('debtors_subscription_required', default='Your trial or subscription has expired. Please subscribe to generate IOUs.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        
        if not debtor:
            flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors.index'))
        
        # Convert naive datetimes to timezone-aware
        if debtor.get('created_at') and debtor['created_at'].tzinfo is None:
            debtor['created_at'] = debtor['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        if debtor.get('reminder_date') and debtor['reminder_date'].tzinfo is None:
            debtor['reminder_date'] = debtor['reminder_date'].replace(tzinfo=ZoneInfo("UTC"))
        
        # Sanitize inputs for CSV generation
        debtor['name'] = utils.sanitize_input(debtor['name'], max_length=100)
        debtor['description'] = utils.sanitize_input(debtor.get('description', 'No description provided'), max_length=500)
        debtor['phone_number'] = utils.sanitize_input(debtor.get('phone_number', 'N/A'), max_length=50)
        debtor['email'] = utils.sanitize_input(debtor.get('email', 'N/A'), max_length=100)
        
        output = []
        output.extend(ficore_csv_header(current_user))
        output.append([trans('debtors_iou_title', default='FiCore Records - IOU')])
        output.append([''])
        output.append([trans('debtors_debtor_name', default='Debtor'), debtor['name']])
        output.append([trans('debtors_amount_owed', default='Amount Owed'), utils.format_currency(debtor['amount_owed'])])
        output.append([trans('debtors_phone_number', default='Phone Number'), debtor['phone_number']])
        output.append([trans('debtors_email', default='Email'), debtor['email']])
        output.append([trans('debtors_description', default='Description of Transaction'), debtor['description']])
        output.append([trans('debtors_date_recorded', default='Date Recorded'), utils.format_date(debtor['created_at'])])
        output.append([trans('debtors_reminders_sent', default='Reminders Sent'), debtor.get('reminder_count', 0)])
        output.append([''])
        output.append([trans('debtors_iou_footer', default='This document serves as an IOU recorded on FiCore Records.')])
        
        buffer = io.BytesIO()
        writer = csv.writer(buffer, lineterminator='\n')
        writer.writerows(output)
        buffer.seek(0)
        
        return Response(
            buffer,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_IOU_{utils.sanitize_input(debtor["name"], max_length=50)}.csv'
            }
        )
        
    except ValueError:
        logger.error(f"Invalid debtor ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_invalid_id', default='Invalid debtor ID'), 'danger')
        return redirect(url_for('debtors.index'))
    except Exception as e:
        logger.error(f"Error generating IOU CSV for debtor {id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_iou_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('debtors.index'))

@debtors_bp.route('/add', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def add():
    """Add a new debtor record (requires active trial/subscription)."""
    if not utils.can_user_interact(current_user):
        flash(trans('debtors_subscription_required', default='Your trial or subscription has expired. Please subscribe to create debtors.'), 'warning')
        return redirect(url_for('subscribe_bp.subscribe'))

    form = DebtorForm()
    if form.validate_on_submit():
        try:
            db = utils.get_mongo_db()
            debtor_data = {
                'user_id': str(current_user.id),
                'type': 'debtor',
                'name': utils.sanitize_input(form.name.data, max_length=100),
                'phone_number': utils.sanitize_input(form.phone_number.data, max_length=50),
                'email': utils.sanitize_input(form.email.data, max_length=100) if form.email.data else None,
                'amount_owed': utils.clean_currency(form.amount_owed.data),
                'description': utils.sanitize_input(form.description.data, max_length=500) if form.description.data else None,
                'created_at': datetime.now(timezone.utc),
                'reminder_count': 0
            }
            db.records.insert_one(debtor_data)
            
            flash(trans('debtors_add_success', default='Debtor added successfully'), 'success')
            return redirect(url_for('debtors.index'))
        except Exception as e:
            logger.error(f"Error adding debtor for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('debtors_add_error', default='An error occurred while adding debtor'), 'danger')

    return render_template(
        'debtors/add.html',
        form=form,
        can_interact=utils.can_user_interact(current_user),
        title=trans('debtors_add_debtor', default='Add Debtor', lang=session.get('lang', 'en'))
    )

@debtors_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def edit(id):
    """Edit an existing debtor record (requires active trial/subscription for POST)."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        
        if not debtor:
            flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors.index'))
        
        # Convert naive datetimes to timezone-aware
        if debtor.get('created_at') and debtor['created_at'].tzinfo is None:
            debtor['created_at'] = debtor['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        if debtor.get('reminder_date') and debtor['reminder_date'].tzinfo is None:
            debtor['reminder_date'] = debtor['reminder_date'].replace(tzinfo=ZoneInfo("UTC"))
        
        form = DebtorForm(data={
            'name': debtor['name'],
            'phone_number': debtor.get('phone_number', ''),
            'email': debtor.get('email', ''),
            'amount_owed': debtor['amount_owed'],
            'description': debtor.get('description', '')
        })

        if request.method == 'POST':
            if not utils.can_user_interact(current_user):
                flash(trans('debtors_subscription_required', default='Your trial or subscription has expired. Please subscribe to edit debtors.'), 'warning')
                return redirect(url_for('subscribe_bp.subscribe'))

        if form.validate_on_submit():
            try:
                updated_record = {
                    'name': utils.sanitize_input(form.name.data, max_length=100),
                    'phone_number': utils.sanitize_input(form.phone_number.data, max_length=50),
                    'email': utils.sanitize_input(form.email.data, max_length=100) if form.email.data else None,
                    'amount_owed': utils.clean_currency(form.amount_owed.data),
                    'description': utils.sanitize_input(form.description.data, max_length=500) if form.description.data else None,
                    'updated_at': datetime.now(timezone.utc)
                }
                db.records.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_record}
                )
                flash(trans('debtors_edit_success', default='Debtor updated successfully'), 'success')
                return redirect(url_for('debtors.index'))
            except Exception as e:
                logger.error(f"Error updating debtor {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                flash(trans('debtors_edit_error', default='An error occurred'), 'danger')

        can_interact = utils.can_user_interact(current_user)
        if not can_interact:
            flash(trans('debtors_subscription_required', default='Your trial or subscription has expired. Subscribe to manage your debtors.'), 'warning')
        
        return render_template(
            'debtors/edit.html',
            form=form,
            debtor=debtor,
            can_interact=can_interact,
            title=trans('debtors_edit_debtor', default='Edit Debtor', lang=session.get('lang', 'en'))
        )
    except ValueError:
        logger.error(f"Invalid debtor ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_invalid_id', default='Invalid debtor ID'), 'danger')
        return redirect(url_for('debtors.index'))
    except Exception as e:
        logger.error(f"Error fetching debtor {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
        return redirect(url_for('debtors.index'))

@debtors_bp.route('/delete/<id>', methods=['POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def delete(id):
    """Delete a debtor record (requires active trial/subscription)."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('debtors_subscription_required', default='Your trial or subscription has expired. Please subscribe to delete debtors.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors.index'))
        result = db.records.delete_one(query)
        if result.deleted_count:
            flash(trans('debtors_delete_success', default='Debtor deleted successfully'), 'success')
        else:
            flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
    except ValueError:
        logger.error(f"Invalid debtor ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_invalid_id', default='Invalid debtor ID'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting debtor {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('debtors_delete_error', default='An error occurred'), 'danger')
    return redirect(url_for('debtors.index'))
