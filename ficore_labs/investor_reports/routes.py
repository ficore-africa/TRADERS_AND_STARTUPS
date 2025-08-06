from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, Response, session
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFError
from wtforms import StringField, TextAreaField, SubmitField, DateField
from wtforms.validators import DataRequired, Optional, Length
from bson import ObjectId
from bson.errors import InvalidId
from datetime import datetime, date
import logging
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from helpers.branding_helpers import draw_ficore_pdf_header, ficore_csv_header
import csv
import utils
from translations import trans

# Try to use zoneinfo, fall back to pytz for compatibility
try:
    from zoneinfo import ZoneInfo
    TZ_MODULE = 'zoneinfo'
    UTC_TZ = ZoneInfo("UTC")
except ImportError:
    from pytz import UTC
    TZ_MODULE = 'pytz'
    UTC_TZ = UTC

logger = logging.getLogger(__name__)

class InvestorReportForm(FlaskForm):
    title = StringField(trans('investor_reports_title', default='Report Title'), validators=[DataRequired(), Length(max=100)])
    report_date = DateField(trans('investor_reports_date', default='Report Date'), validators=[DataRequired()])
    summary = TextAreaField(trans('investor_reports_summary', default='Summary'), validators=[DataRequired(), Length(max=1000)])
    financial_highlights = TextAreaField(trans('investor_reports_financial_highlights', default='Financial Highlights'), validators=[Optional(), Length(max=1000)])
    submit = SubmitField(trans('investor_reports_add_report', default='Add Investor Report'))

investor_reports_bp = Blueprint('investor_reports', __name__, url_prefix='/investor_reports')

@investor_reports_bp.route('/')
@login_required
@utils.requires_role(['startup', 'admin'])
def index():
    """List all investor reports for the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'user_id': str(current_user.id), 'type': 'investor_report'}
        reports = list(db.records.find(query).sort('report_date', -1))
        
        # Convert naive datetimes to timezone-aware
        for report in reports:
            if report.get('created_at') and report['created_at'].tzinfo is None:
                report['created_at'] = report['created_at'].replace(tzinfo=UTC_TZ)
            if report.get('report_date') and report['report_date'].tzinfo is None:
                report['report_date'] = report['report_date'].replace(tzinfo=UTC_TZ)
        
        return render_template(
            'investor_reports/index.html',
            reports=reports,
            title=trans('investor_reports_index', default='Investor Reports', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        )
    except Exception as e:
        logger.error(
            f"Error fetching investor reports for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@investor_reports_bp.route('/manage')
@login_required
@utils.requires_role(['startup', 'admin'])
def manage():
    """List all investor reports for management (edit/delete) by the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'user_id': str(current_user.id), 'type': 'investor_report'}
        reports = list(db.records.find(query).sort('report_date', -1))
        
        # Convert naive datetimes to timezone-aware
        for report in reports:
            if report.get('created_at') and report['created_at'].tzinfo is None:
                report['created_at'] = report['created_at'].replace(tzinfo=UTC_TZ)
            if report.get('report_date') and report['report_date'].tzinfo is None:
                report['report_date'] = report['report_date'].replace(tzinfo=UTC_TZ)
        
        return render_template(
            'investor_reports/manage_reports.html',
            reports=reports,
            title=trans('investor_reports_manage', default='Manage Investor Reports', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        )
    except Exception as e:
        logger.error(
            f"Error fetching investor reports for manage page for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('investor_reports.index'))

@investor_reports_bp.route('/view/<id>')
@login_required
@utils.requires_role(['startup', 'admin'])
def view(id):
    """View detailed information about a specific investor report (JSON API)."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        report = db.records.find_one(query)
        if not report:
            return jsonify({'error': trans('investor_reports_record_not_found', default='Record not found')}), 404
        
        # Convert naive datetimes to timezone-aware
        if report.get('created_at') and report['created_at'].tzinfo is None:
            report['created_at'] = report['created_at'].replace(tzinfo=UTC_TZ)
        if report.get('report_date') and report['report_date'].tzinfo is None:
            report['report_date'] = report['report_date'].replace(tzinfo=UTC_TZ)
        
        report['_id'] = str(report['_id'])
        report['report_date'] = report['report_date'].isoformat() if report.get('report_date') else None
        report['created_at'] = report['created_at'].isoformat() if report.get('created_at') else None
        
        return jsonify(report)
    except InvalidId:
        logger.error(
            f"Invalid ObjectId format for investor report ID {id} for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({'error': trans('investor_reports_invalid_id', default='Invalid report ID')}), 404
    except Exception as e:
        logger.error(
            f"Error fetching investor report {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({'error': trans('investor_reports_fetch_error', default='An error occurred')}), 500

@investor_reports_bp.route('/view_page/<id>')
@login_required
@utils.requires_role(['startup', 'admin'])
def view_page(id):
    """Render a detailed view page for a specific investor report."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        report = db.records.find_one(query)
        if not report:
            flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('investor_reports.index'))
        
        # Convert naive datetimes to timezone-aware
        if report.get('created_at') and report['created_at'].tzinfo is None:
            report['created_at'] = report['created_at'].replace(tzinfo=UTC_TZ)
        if report.get('report_date') and report['report_date'].tzinfo is None:
            report['report_date'] = report['report_date'].replace(tzinfo=UTC_TZ)
        
        return render_template(
            'investor_reports/view.html',
            report=report,
            title=trans('investor_reports_details', default='Investor Report Details', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        )
    except InvalidId:
        logger.error(
            f"Invalid ObjectId format for investor report ID {id} for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_invalid_id', default='Invalid report ID'), 'danger')
        return redirect(url_for('investor_reports.index'))
    except Exception as e:
        logger.error(
            f"Error rendering investor report view page {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_view_error', default='An error occurred'), 'danger')
        return redirect(url_for('investor_reports.index'))

@investor_reports_bp.route('/generate_report/<id>')
@login_required
@utils.requires_role(['startup', 'admin'])
def generate_report(id):
    """Generate PDF report for an investor report."""
    try:
        # Validate ObjectId format before querying
        try:
            ObjectId(id)
        except InvalidId:
            logger.error(
                f"Invalid ObjectId format for investor report ID {id} for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('investor_reports_invalid_id', default='Invalid report ID'), 'danger')
            return redirect(url_for('investor_reports.index'))
        
        if not utils.can_user_interact(current_user):
            logger.info(
                f"User {current_user.id} blocked from generating report {id}: trial expired or no subscription",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('investor_reports_subscription_required', default='Your trial has expired or you do not have an active subscription. Please subscribe to continue.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        logger.info(
            f"Querying for investor report with ID {id}, user_id {current_user.id}, type 'investor_report'",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        report = db.records.find_one(query)
        
        if not report:
            logger.error(
                f"No investor report found for ID {id}, user_id {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('investor_reports.index'))
        
        logger.info(
            f"Found investor report with ID {id} for user {current_user.id}: {report}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        
        # Convert naive datetimes to timezone-aware
        if report.get('created_at') and report['created_at'].tzinfo is None:
            report['created_at'] = report['created_at'].replace(tzinfo=UTC_TZ)
        if report.get('report_date') and report['report_date'].tzinfo is None:
            report['report_date'] = report['report_date'].replace(tzinfo=UTC_TZ)
        
        # Sanitize inputs for PDF generation
        report['title'] = utils.sanitize_input(report['title'], max_length=100)
        report['summary'] = utils.sanitize_input(report['summary'], max_length=1000)
        report['financial_highlights'] = utils.sanitize_input(report.get('financial_highlights', 'No highlights provided'), max_length=1000)
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        draw_ficore_pdf_header(p, current_user, y_start=10.5 * inch)
        
        header_height = 0.7
        extra_space = 0.2
        title_y = 10.5 - header_height - extra_space
        
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, title_y * inch, trans('investor_reports_report_title', default='FiCore Records - Investor Report'))
        
        p.setFont("Helvetica", 12)
        y_position = title_y - 0.5
        p.drawString(inch, y_position * inch, f"{trans('investor_reports_title', default='Title')}: {report['title']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('investor_reports_date', default='Report Date')}: {utils.format_date(report['report_date'])}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('investor_reports_summary', default='Summary')}: {report['summary']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('investor_reports_financial_highlights', default='Financial Highlights')}: {report['financial_highlights']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('investor_reports_date_recorded', default='Date Recorded')}: {utils.format_date(report['created_at'])}")
        
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, trans('investor_reports_report_footer', default='This document serves as an investor report recorded on FiCore Records.'))
        
        p.showPage()
        p.save()
        
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_Investor_Report_{utils.sanitize_input(report["title"], max_length=50)}.pdf'
            }
        )
        
    except Exception as e:
        logger.error(
            f"Error generating investor report {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_report_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('investor_reports.index'))

@investor_reports_bp.route('/generate_report_csv/<id>')
@login_required
@utils.requires_role(['startup', 'admin'])
def generate_report_csv(id):
    """Generate CSV report for an investor report."""
    try:
        # Validate ObjectId format before querying
        try:
            ObjectId(id)
        except InvalidId:
            logger.error(
                f"Invalid ObjectId format for investor report ID {id} for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('investor_reports_invalid_id', default='Invalid report ID'), 'danger')
            return redirect(url_for('investor_reports.index'))
        
        if not utils.can_user_interact(current_user):
            flash(trans('investor_reports_subscription_required', default='Your trial has expired or you do not have an active subscription. Please subscribe to continue.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        report = db.records.find_one(query)
        
        if not report:
            logger.error(
                f"No investor report found for ID {id}, user_id {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('investor_reports.index'))
        
        # Convert naive datetimes to timezone-aware
        if report.get('created_at') and report['created_at'].tzinfo is None:
            report['created_at'] = report['created_at'].replace(tzinfo=UTC_TZ)
        if report.get('report_date') and report['report_date'].tzinfo is None:
            report['report_date'] = report['report_date'].replace(tzinfo=UTC_TZ)
        
        # Sanitize inputs for CSV generation
        report['title'] = utils.sanitize_input(report['title'], max_length=100)
        report['summary'] = utils.sanitize_input(report['summary'], max_length=1000)
        report['financial_highlights'] = utils.sanitize_input(report.get('financial_highlights', 'No highlights provided'), max_length=1000)
        
        output = []
        output.extend(ficore_csv_header(current_user))
        output.append([trans('investor_reports_report_title', default='FiCore Records - Investor Report')])
        output.append([''])
        output.append([trans('investor_reports_title', default='Title'), report['title']])
        output.append([trans('investor_reports_date', default='Report Date'), utils.format_date(report['report_date'])])
        output.append([trans('investor_reports_summary', default='Summary'), report['summary']])
        output.append([trans('investor_reports_financial_highlights', default='Financial Highlights'), report['financial_highlights']])
        output.append([trans('investor_reports_date_recorded', default='Date Recorded'), utils.format_date(report['created_at'])])
        output.append([''])
        output.append([trans('investor_reports_report_footer', default='This document serves as an investor report recorded on FiCore Records.')])
        
        buffer = io.BytesIO()
        writer = csv.writer(buffer, lineterminator='\n')
        writer.writerows(output)
        buffer.seek(0)
        
        return Response(
            buffer,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_Investor_Report_{utils.sanitize_input(report["title"], max_length=50)}.csv'
            }
        )
        
    except Exception as e:
        logger.error(
            f"Error generating investor report CSV {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_report_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('investor_reports.index'))

@investor_reports_bp.route('/add', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['startup', 'admin'])
@utils.limiter.limit('10 per minute')
def add():
    """Add a new investor report."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('investor_reports_subscription_required', default='Your trial has expired or you do not have an active subscription. Please subscribe to continue.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))

        form = InvestorReportForm()
        if form.validate_on_submit():
            try:
                db = utils.get_mongo_db()
                # Convert date to datetime with UTC timezone
                report_date = form.report_date.data
                if isinstance(report_date, date):
                    report_date = datetime.combine(report_date, datetime.min.time(), tzinfo=UTC_TZ)
                else:
                    logger.warning(
                        f"Unexpected report_date type: {type(report_date)} for user {current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                    )
                    report_date = datetime.combine(report_date.date(), datetime.min.time(), tzinfo=UTC_TZ)

                report_data = {
                    'user_id': str(current_user.id),
                    'type': 'investor_report',
                    'title': utils.sanitize_input(form.title.data, max_length=100),
                    'report_date': report_date,
                    'summary': utils.sanitize_input(form.summary.data, max_length=1000),
                    'financial_highlights': utils.sanitize_input(form.financial_highlights.data, max_length=1000) if form.financial_highlights.data else None,
                    'created_at': datetime.now(UTC_TZ)
                }
                result = db.records.insert_one(report_data)
                logger.info(
                    f"Created investor report with ID {result.inserted_id} for user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                
                flash(trans('investor_reports_add_success', default='Investor report added successfully'), 'success')
                return redirect(url_for('investor_reports.index'))
            except Exception as e:
                logger.error(
                    f"Error adding investor report for user {current_user.id}: {str(e)}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('investor_reports_add_error', default='An error occurred while adding report'), 'danger')

        return render_template(
            'investor_reports/add.html',
            form=form,
            title=trans('investor_reports_add_report', default='Add Investor Report', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        )
    except CSRFError as e:
        logger.error(
            f"CSRF error in add investor report for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return render_template(
            'investor_reports/add.html',
            form=form,
            title=trans('investor_reports_add_report', default='Add Investor Report', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        ), 400

@investor_reports_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['startup', 'admin'])
@utils.limiter.limit('10 per minute')
def edit(id):
    """Edit an existing investor report."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('investor_reports_subscription_required', default='Your trial has expired or you do not have an active subscription. Please subscribe to continue.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))

        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        report = db.records.find_one(query)
        
        if not report:
            logger.error(
                f"No investor report found for ID {id}, user_id {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('investor_reports.index'))
        
        # Convert naive datetimes to timezone-aware
        if report.get('created_at') and report['created_at'].tzinfo is None:
            report['created_at'] = report['created_at'].replace(tzinfo=UTC_TZ)
        if report.get('report_date') and report['report_date'].tzinfo is None:
            report['report_date'] = report['report_date'].replace(tzinfo=UTC_TZ)
        
        form = InvestorReportForm(data={
            'title': report['title'],
            'report_date': report['report_date'],
            'summary': report['summary'],
            'financial_highlights': report.get('financial_highlights', '')
        })

        if form.validate_on_submit():
            try:
                # Convert date to datetime with UTC timezone
                report_date = form.report_date.data
                if isinstance(report_date, date):
                    report_date = datetime.combine(report_date, datetime.min.time(), tzinfo=UTC_TZ)
                else:
                    logger.warning(
                        f"Unexpected report_date type: {type(report_date)} for user {current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                    )
                    report_date = datetime.combine(report_date.date(), datetime.min.time(), tzinfo=UTC_TZ)

                updated_record = {
                    'title': utils.sanitize_input(form.title.data, max_length=100),
                    'report_date': report_date,
                    'summary': utils.sanitize_input(form.summary.data, max_length=1000),
                    'financial_highlights': utils.sanitize_input(form.financial_highlights.data, max_length=1000) if form.financial_highlights.data else None,
                    'updated_at': datetime.now(UTC_TZ)
                }
                db.records.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_record}
                )
                logger.info(
                    f"Updated investor report with ID {id} for user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('investor_reports_edit_success', default='Investor report updated successfully'), 'success')
                return redirect(url_for('investor_reports.index'))
            except Exception as e:
                logger.error(
                    f"Error updating investor report {id} for user {current_user.id}: {str(e)}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('investor_reports_edit_error', default='An error occurred'), 'danger')

        return render_template(
            'investor_reports/edit.html',
            form=form,
            report=report,
            title=trans('investor_reports_edit_report', default='Edit Investor Report', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        )
    except InvalidId:
        logger.error(
            f"Invalid ObjectId format for investor report ID {id} for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_invalid_id', default='Invalid report ID'), 'danger')
        return redirect(url_for('investor_reports.index'))
    except CSRFError as e:
        logger.error(
            f"CSRF error in edit investor report {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return render_template(
            'investor_reports/edit.html',
            form=form,
            report=report,
            title=trans('investor_reports_edit_report', default='Edit Investor Report', lang=session.get('lang', 'en')),
            can_interact=utils.can_user_interact(current_user)
        ), 400
    except Exception as e:
        logger.error(
            f"Error fetching investor report {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
        return redirect(url_for('investor_reports.index'))

@investor_reports_bp.route('/delete/<id>', methods=['POST'])
@login_required
@utils.requires_role(['startup', 'admin'])
@utils.limiter.limit('10 per minute')
def delete(id):
    """Delete an investor report."""
    try:
        # Validate ObjectId format before querying
        try:
            ObjectId(id)
        except InvalidId:
            logger.error(
                f"Invalid ObjectId format for investor report ID {id} for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('investor_reports_invalid_id', default='Invalid report ID'), 'danger')
            return redirect(url_for('investor_reports.index'))

        if not utils.can_user_interact(current_user):
            logger.info(
                f"User {current_user.id} blocked from deleting report {id}: trial expired or no subscription",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('investor_reports_subscription_required', default='Your trial has expired or you do not have an active subscription. Please subscribe to continue.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))

        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        result = db.records.delete_one(query)
        if result.deleted_count:
            logger.info(
                f"Deleted investor report with ID {id} for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('investor_reports_delete_success', default='Investor report deleted successfully'), 'success')
        else:
            logger.error(
                f"No investor report found for ID {id}, user_id {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
    except CSRFError as e:
        logger.error(
            f"CSRF error in delete investor report {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
    except Exception as e:
        logger.error(
            f"Error deleting investor report {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('investor_reports_delete_error', default='An error occurred'), 'danger')
    return redirect(url_for('investor_reports.index'))
