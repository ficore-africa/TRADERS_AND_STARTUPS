from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, Response, session
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired, Optional, ValidationError
from bson import ObjectId
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import logging
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from helpers.branding_helpers import draw_ficore_pdf_header, ficore_csv_header
import csv
import utils
from translations import trans

logger = logging.getLogger(__name__)

def non_negative(form, field):
    """Ensure the field value is non-negative."""
    if field.data < 0:
        raise ValidationError(trans('funds_non_negative', default='Value cannot be negative'))

class FundForm(FlaskForm):
    source = StringField(trans('funds_source', default='Funding Source'), validators=[DataRequired()])
    amount = FloatField(trans('funds_amount', default='Amount'), validators=[DataRequired(), non_negative])
    category = SelectField(trans('funds_category', default='Category'), 
                          choices=[
                              ('equity', trans('funds_equity', default='Equity')), 
                              ('debt', trans('funds_debt', default='Debt')), 
                              ('grant', trans('funds_grant', default='Grant')),
                              ('personal', trans('funds_personal', default='Personal')),  # Added for traders
                              ('other', trans('funds_other', default='Other'))  # Added for flexibility
                          ], 
                          validators=[DataRequired()])
    description = TextAreaField(trans('general_description', default='Description'), validators=[Optional()])
    submit = SubmitField(trans('funds_add_fund', default='Add Fund'))

funds_bp = Blueprint('funds', __name__, url_prefix='/funds')

@funds_bp.route('/')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])  # Updated to allow traders
def index():
    """List all fund records for the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'user_id': str(current_user.id), 'type': 'fund'}
        funds = list(db.records.find(query).sort('created_at', -1))
        
        for fund in funds:
            if fund.get('created_at') and fund['created_at'].tzinfo is None:
                fund['created_at'] = fund['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        can_interact = utils.can_user_interact(current_user)
        
        return render_template(
            'funds/index.html',
            funds=funds,
            can_interact=can_interact,
            title=trans('funds_index', default='Fund Tracking', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching funds for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@funds_bp.route('/manage')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def manage():
    """List all fund records for management (edit/delete) by the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'user_id': str(current_user.id), 'type': 'fund'}
        funds = list(db.records.find(query).sort('created_at', -1))
        
        for fund in funds:
            if fund.get('created_at') and fund['created_at'].tzinfo is None:
                fund['created_at'] = fund['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        can_interact = utils.can_user_interact(current_user)
        
        return render_template(
            'funds/manage_funds.html',
            funds=funds,
            can_interact=can_interact,
            title=trans('funds_manage', default='Manage Funds', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching funds for manage page for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('funds.index'))

@funds_bp.route('/view/<id>')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def view(id):
    """View detailed information about a specific fund (JSON API)."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'fund'}
        fund = db.records.find_one(query)
        if not fund:
            return jsonify({'error': trans('funds_record_not_found', default='Record not found')}), 404
        
        if fund.get('created_at') and fund['created_at'].tzinfo is None:
            fund['created_at'] = fund['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        fund['_id'] = str(fund['_id'])
        fund['created_at'] = fund['created_at'].isoformat() if fund.get('created_at') else None
        
        return jsonify(fund)
    except ValueError:
        logger.error(f"Invalid fund ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return jsonify({'error': trans('funds_invalid_id', default='Invalid fund ID')}), 404
    except Exception as e:
        logger.error(f"Error fetching fund {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return jsonify({'error': trans('funds_fetch_error', default='An error occurred')}), 500

@funds_bp.route('/view_page/<id>')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def view_page(id):
    """Render a detailed view page for a specific fund."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'fund'}
        fund = db.records.find_one(query)
        if not fund:
            flash(trans('funds_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('funds.index'))
        
        if fund.get('created_at') and fund['created_at'].tzinfo is None:
            fund['created_at'] = fund['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        can_interact = utils.can_user_interact(current_user)
        
        return render_template(
            'funds/view.html',
            fund=fund,
            can_interact=can_interact,
            title=trans('funds_details', default='Fund Details', lang=session.get('lang', 'en'))
        )
    except ValueError:
        logger.error(f"Invalid fund ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_invalid_id', default='Invalid fund ID'), 'danger')
        return redirect(url_for('funds.index'))
    except Exception as e:
        logger.error(f"Error rendering fund view page {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_view_error', default='An error occurred'), 'danger')
        return redirect(url_for('funds.index'))

@funds_bp.route('/generate_report/<id>')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def generate_report(id):
    """Generate PDF report for a fund."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('funds_subscription_required', default='Your trial or subscription has expired. Please subscribe to generate reports.'), 'danger')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'fund'}
        fund = db.records.find_one(query)
        
        if not fund:
            flash(trans('funds_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('funds.index'))
        
        if fund.get('created_at') and fund['created_at'].tzinfo is None:
            fund['created_at'] = fund['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        fund['source'] = utils.sanitize_input(fund['source'], max_length=100)
        fund['description'] = utils.sanitize_input(fund.get('description', 'No description provided'), max_length=500)
        category = trans(f'funds_{fund["category"]}', default=fund['category'].capitalize())
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        draw_ficore_pdf_header(p, current_user, y_start=10.5 * inch)
        
        header_height = 0.7
        extra_space = 0.2
        title_y = 10.5 - header_height - extra_space
        
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, title_y * inch, trans('funds_summary_title', default='FiCore Records - Fund Summary'))  # Updated title
        
        p.setFont("Helvetica", 12)
        y_position = title_y - 0.5
        p.drawString(inch, y_position * inch, f"{trans('funds_source', default='Source')}: {fund['source']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('funds_amount', default='Amount')}: {utils.format_currency(fund['amount'])}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('funds_category', default='Category')}: {category}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('general_description', default='Description')}: {fund['description']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('funds_date_recorded', default='Date Recorded')}: {utils.format_date(fund['created_at'])}")
        
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, trans('funds_summary_footer', default='This document summarizes a fund recorded on FiCore Records.'))  # Updated footer
        
        p.showPage()
        p.save()
        
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_Fund_Summary_{utils.sanitize_input(fund["source"], max_length=50)}.pdf'  # Updated filename
            }
        )
        
    except ValueError:
        logger.error(f"Invalid fund ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_invalid_id', default='Invalid fund ID'), 'danger')
        return redirect(url_for('funds.index'))
    except Exception as e:
        logger.error(f"Error generating fund report {id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_report_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('funds.index'))

@funds_bp.route('/generate_report_csv/<id>')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def generate_report_csv(id):
    """Generate CSV report for a fund."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('funds_subscription_required', default='Your trial or subscription has expired. Please subscribe to generate reports.'), 'danger')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'fund'}
        fund = db.records.find_one(query)
        
        if not fund:
            flash(trans('funds_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('funds.index'))
        
        if fund.get('created_at') and fund['created_at'].tzinfo is None:
            fund['created_at'] = fund['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        fund['source'] = utils.sanitize_input(fund['source'], max_length=100)
        fund['description'] = utils.sanitize_input(fund.get('description', 'No description provided'), max_length=500)
        category = trans(f'funds_{fund["category"]}', default=fund['category'].capitalize())
        
        output = []
        output.extend(ficore_csv_header(current_user))
        output.append([trans('funds_summary_title', default='FiCore Records - Fund Summary')])  # Updated title
        output.append([''])
        output.append([trans('funds_source', default='Source'), fund['source']])
        output.append([trans('funds_amount', default='Amount'), utils.format_currency(fund['amount'])])
        output.append([trans('funds_category', default='Category'), category])
        output.append([trans('general_description', default='Description'), fund['description']])
        output.append([trans('funds_date_recorded', default='Date Recorded'), utils.format_date(fund['created_at'])])
        output.append([''])
        output.append([trans('funds_summary_footer', default='This document summarizes a fund recorded on FiCore Records.')])  # Updated footer
        
        buffer = io.BytesIO()
        writer = csv.writer(buffer, lineterminator='\n')
        writer.writerows(output)
        buffer.seek(0)
        
        return Response(
            buffer,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_Fund_Summary_{utils.sanitize_input(fund["source"], max_length=50)}.csv'  # Updated filename
            }
        )
        
    except ValueError:
        logger.error(f"Invalid fund ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_invalid_id', default='Invalid fund ID'), 'danger')
        return redirect(url_for('funds.index'))
    except Exception as e:
        logger.error(f"Error generating fund report CSV {id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_report_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('funds.index'))

@funds_bp.route('/add', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def add():
    """Add a new fund record."""
    if not utils.can_user_interact(current_user):
        flash(trans('funds_subscription_required', default='Your trial or subscription has expired. Please subscribe to add funds.'), 'danger')
        return redirect(url_for('subscribe_bp.subscribe'))

    form = FundForm()
    if form.validate_on_submit():
        try:
            db = utils.get_mongo_db()
            fund_data = {
                'user_id': str(current_user.id),
                'type': 'fund',
                'source': utils.sanitize_input(form.source.data, max_length=100),
                'amount': utils.clean_currency(form.amount.data),
                'category': form.category.data,
                'description': utils.sanitize_input(form.description.data, max_length=500) if form.description.data else None,
                'created_at': datetime.now(timezone.utc)
            }
            db.records.insert_one(fund_data)
            
            flash(trans('funds_add_success', default='Fund added successfully'), 'success')
            return redirect(url_for('funds.index'))
        except Exception as e:
            logger.error(f"Error adding fund for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('funds_add_error', default='An error occurred while adding fund'), 'danger')

    return render_template(
        'funds/add.html',
        form=form,
        can_interact=utils.can_user_interact(current_user),
        title=trans('funds_add_fund', default='Add Fund', lang=session.get('lang', 'en'))
    )

@funds_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def edit(id):
    """Edit an existing fund record."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('funds_subscription_required', default='Your trial or subscription has expired. Please subscribe to edit funds.'), 'danger')
            return redirect(url_for('subscribe_bp.subscribe'))

        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'fund'}
        fund = db.records.find_one(query)
        
        if not fund:
            flash(trans('funds_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('funds.index'))
        
        if fund.get('created_at') and fund['created_at'].tzinfo is None:
            fund['created_at'] = fund['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        form = FundForm(data={
            'source': fund['source'],
            'amount': fund['amount'],
            'category': fund['category'],
            'description': fund.get('description', '')
        })

        if form.validate_on_submit():
            try:
                updated_record = {
                    'source': utils.sanitize_input(form.source.data, max_length=100),
                    'amount': utils.clean_currency(form.amount.data),
                    'category': form.category.data,
                    'description': utils.sanitize_input(form.description.data, max_length=500) if form.description.data else None,
                    'updated_at': datetime.now(timezone.utc)
                }
                db.records.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_record}
                )
                flash(trans('funds_edit_success', default='Fund updated successfully'), 'success')
                return redirect(url_for('funds.index'))
            except Exception as e:
                logger.error(f"Error updating fund {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                flash(trans('funds_edit_error', default='An error occurred'), 'danger')

        return render_template(
            'funds/edit.html',
            form=form,
            fund=fund,
            can_interact=utils.can_user_interact(current_user),
            title=trans('funds_edit_fund', default='Edit Fund', lang=session.get('lang', 'en'))
        )
    except ValueError:
        logger.error(f"Invalid fund ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_invalid_id', default='Invalid fund ID'), 'danger')
        return redirect(url_for('funds.index'))
    except Exception as e:
        logger.error(f"Error fetching fund {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_record_not_found', default='Record not found'), 'danger')
        return redirect(url_for('funds.index'))

@funds_bp.route('/delete/<id>', methods=['POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def delete(id):
    """Delete a fund record."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('funds_subscription_required', default='Your trial or subscription has expired. Please subscribe to delete funds.'), 'danger')
            return redirect(url_for('subscribe_bp.subscribe'))

        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'fund'}
        result = db.records.delete_one(query)
        if result.deleted_count:
            flash(trans('funds_delete_success', default='Fund deleted successfully'), 'success')
        else:
            flash(trans('funds_record_not_found', default='Record not found'), 'danger')
    except ValueError:
        logger.error(f"Invalid fund ID {id} for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_invalid_id', default='Invalid fund ID'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting fund {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('funds_delete_error', default='An error occurred'), 'danger')
    return redirect(url_for('funds.index'))
