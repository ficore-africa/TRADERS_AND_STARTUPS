from flask import Blueprint, session, request, render_template, redirect, url_for, flash, jsonify, current_app, Response
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFError
from translations import trans
import utils
from bson import ObjectId
from datetime import datetime, date, timezone
from zoneinfo import ZoneInfo
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO, StringIO
from wtforms import DateField, StringField, SubmitField, SelectField
from wtforms.validators import Optional, Length
import csv
import logging
from helpers.branding_helpers import draw_ficore_pdf_header, ficore_csv_header
import pymongo.errors

logger = logging.getLogger(__name__)

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')

class ReportForm(FlaskForm):
    start_date = DateField(trans('reports_start_date', default='Start Date'), validators=[Optional()])
    end_date = DateField(trans('reports_end_date', default='End Date'), validators=[Optional()])
    format = SelectField('Format', choices=[('html', 'HTML'), ('pdf', 'PDF'), ('csv', 'CSV')], default='html', validators=[Optional()])
    submit = SubmitField(trans('reports_generate_report', default='Generate Report'))

class CustomerReportForm(FlaskForm):
    role = SelectField('User Role', choices=[('', 'All'), ('trader', 'Trader'), ('startup', 'Startup'), ('admin', 'Admin')], validators=[Optional(), Length(max=20)])
    format = SelectField('Format', choices=[('html', 'HTML'), ('pdf', 'PDF'), ('csv', 'CSV')], default='html', validators=[Optional()])
    submit = SubmitField('Generate Report')

def to_dict_record(record):
    if not record:
        return {'name': None, 'amount_owed': None}
    try:
        if record.get('created_at') and record['created_at'].tzinfo is None:
            record['created_at'] = record['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        if record.get('updated_at') and record['updated_at'].tzinfo is None:
            record['updated_at'] = record['updated_at'].replace(tzinfo=ZoneInfo("UTC"))
        created_at = utils.format_date(record.get('created_at'), format_type='iso') if record.get('created_at') else None
        updated_at = utils.format_date(record.get('updated_at'), format_type='iso') if record.get('updated_at') else None
    except Exception as e:
        logger.error(
            f"Error formatting dates in to_dict_record: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        created_at = None
        updated_at = None
    return {
        'id': str(record.get('_id', '')),
        'user_id': str(record.get('user_id', '')),
        'type': utils.sanitize_input(record.get('type', ''), max_length=20),
        'name': utils.sanitize_input(record.get('name', ''), max_length=100),
        'contact': utils.sanitize_input(record.get('contact', ''), max_length=100),
        'amount_owed': record.get('amount_owed', 0),
        'description': utils.sanitize_input(record.get('description', ''), max_length=1000),
        'created_at': created_at,
        'updated_at': updated_at
    }

def to_dict_cashflow(record):
    if not record:
        return {'party_name': None, 'amount': None}
    try:
        if record.get('created_at') and record['created_at'].tzinfo is None:
            record['created_at'] = record['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        if record.get('updated_at') and record['updated_at'].tzinfo is None:
            record['updated_at'] = record['updated_at'].replace(tzinfo=ZoneInfo("UTC"))
        created_at = utils.format_date(record.get('created_at'), format_type='iso')
        updated_at = utils.format_date(record.get('updated_at'), format_type='iso') if record.get('updated_at') else None
    except Exception as e:
        logger.error(
            f"Error formatting dates in to_dict_cashflow: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        created_at = None
        updated_at = None
    return {
        'id': str(record.get('_id', '')),
        'user_id': str(record.get('user_id', '')),
        'type': utils.sanitize_input(record.get('type', ''), max_length=20),
        'party_name': utils.sanitize_input(record.get('party_name', ''), max_length=100),
        'amount': record.get('amount', 0),
        'method': utils.sanitize_input(record.get('method', ''), max_length=50),
        'created_at': created_at,
        'updated_at': updated_at
    }

def to_dict_fund(record):
    if not record:
        return {'source': None, 'amount': None}
    try:
        if record.get('created_at') and record['created_at'].tzinfo is None:
            record['created_at'] = record['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        if record.get('updated_at') and record['updated_at'].tzinfo is None:
            record['updated_at'] = record['updated_at'].replace(tzinfo=ZoneInfo("UTC"))
        if record.get('date_received') and record['date_received'].tzinfo is None:
            record['date_received'] = record['date_received'].replace(tzinfo=ZoneInfo("UTC"))
        created_at = utils.format_date(record.get('created_at'), format_type='iso')
        updated_at = utils.format_date(record.get('updated_at'), format_type='iso') if record.get('updated_at') else None
        date_received = utils.format_date(record.get('date_received'), format_type='iso') if record.get('date_received') else None
    except Exception as e:
        logger.error(
            f"Error formatting dates in to_dict_fund: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        created_at = None
        updated_at = None
        date_received = None
    return {
        'id': str(record.get('_id', '')),
        'user_id': str(record.get('user_id', '')),
        'source': utils.sanitize_input(record.get('source', ''), max_length=100),
        'amount': record.get('amount', 0),
        'date_received': date_received,
        'status': utils.sanitize_input(record.get('status', ''), max_length=50),
        'created_at': created_at,
        'updated_at': updated_at
    }

def to_dict_forecast(record):
    if not record:
        return {'scenario': None, 'projected_revenue': None}
    try:
        if record.get('created_at') and record['created_at'].tzinfo is None:
            record['created_at'] = record['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        if record.get('updated_at') and record['updated_at'].tzinfo is None:
            record['updated_at'] = record['updated_at'].replace(tzinfo=ZoneInfo("UTC"))
        if record.get('period_start') and record['period_start'].tzinfo is None:
            record['period_start'] = record['period_start'].replace(tzinfo=ZoneInfo("UTC"))
        if record.get('period_end') and record['period_end'].tzinfo is None:
            record['period_end'] = record['period_end'].replace(tzinfo=ZoneInfo("UTC"))
        created_at = utils.format_date(record.get('created_at'), format_type='iso')
        updated_at = utils.format_date(record.get('updated_at'), format_type='iso') if record.get('updated_at') else None
        period_start = utils.format_date(record.get('period_start'), format_type='iso') if record.get('period_start') else None
        period_end = utils.format_date(record.get('period_end'), format_type='iso') if record.get('period_end') else None
    except Exception as e:
        logger.error(
            f"Error formatting dates in to_dict_forecast: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        created_at = None
        updated_at = None
        period_start = None
        period_end = None
    return {
        'id': str(record.get('_id', '')),
        'user_id': str(record.get('user_id', '')),
        'scenario': utils.sanitize_input(record.get('scenario', ''), max_length=100),
        'projected_revenue': record.get('projected_revenue', 0),
        'projected_expenses': record.get('projected_expenses', 0),
        'period_start': period_start,
        'period_end': period_end,
        'created_at': created_at,
        'updated_at': updated_at
    }

def to_dict_investor_report(record):
    if not record:
        return {'title': None, 'financial_metrics': None}
    try:
        if record.get('created_at') and record['created_at'].tzinfo is None:
            record['created_at'] = record['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        if record.get('updated_at') and record['updated_at'].tzinfo is None:
            record['updated_at'] = record['updated_at'].replace(tzinfo=ZoneInfo("UTC"))
        created_at = utils.format_date(record.get('created_at'), format_type='iso')
        updated_at = utils.format_date(record.get('updated_at'), format_type='iso') if record.get('updated_at') else None
    except Exception as e:
        logger.error(
            f"Error formatting dates in to_dict_investor_report: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        created_at = None
        updated_at = None
    return {
        'id': str(record.get('_id', '')),
        'user_id': str(record.get('user_id', '')),
        'title': utils.sanitize_input(record.get('title', ''), max_length=100),
        'financial_metrics': record.get('financial_metrics', {}),
        'created_at': created_at,
        'updated_at': updated_at
    }

@reports_bp.route('/')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def index():
    try:
        can_interact = utils.can_user_interact(current_user)
        logger.info(
            f"Rendering reports index for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return render_template(
            'reports/index.html',
            title=trans('reports_index', default='Reports', lang=session.get('lang', 'en')),
            can_interact=can_interact
        )
    except Exception as e:
        logger.error(
            f"Error loading reports index for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('reports_load_error', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@reports_bp.route('/profit_loss', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
@utils.limiter.limit('10 per minute')
def profit_loss():
    form = ReportForm()
    can_interact = utils.can_user_interact(current_user)
    if not can_interact:
        logger.warning(
            f"Subscription required for user {current_user.id} to generate profit/loss report",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('subscription_required', default='Subscription required to generate reports. Please subscribe.'), 'warning')
        return redirect(url_for('subscribe_bp.subscribe'))
    cashflows = []
    query = {'user_id': str(current_user.id)}
    if form.validate_on_submit():
        try:
            if form.format.data not in ['html', 'pdf', 'csv']:
                logger.error(
                    f"Invalid format {form.format.data} for profit/loss report by user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('reports_invalid_format', default='Invalid report format'), 'danger')
                return redirect(url_for('reports.profit_loss'))
            db = utils.get_mongo_db()
            if form.start_date.data:
                start_datetime = datetime.combine(form.start_date.data, datetime.min.time(), tzinfo=ZoneInfo("UTC"))
                query['created_at'] = {'$gte': start_datetime}
            if form.end_date.data:
                end_datetime = datetime.combine(form.end_date.data, datetime.max.time(), tzinfo=ZoneInfo("UTC"))
                query['created_at'] = query.get('created_at', {}) | {'$lte': end_datetime}
            cashflows = [to_dict_cashflow(cf) for cf in db.cashflows.find(query).sort('created_at', -1)]
            output_format = form.format.data
            logger.info(
                f"Generating profit/loss report for user {current_user.id}, format: {output_format}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            if output_format == 'pdf':
                return generate_profit_loss_pdf(cashflows)
            elif output_format == 'csv':
                return generate_profit_loss_csv(cashflows)
        except pymongo.errors.PyMongoError as e:
            logger.error(
                f"MongoDB error generating profit/loss report for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
        except Exception as e:
            logger.error(
                f"Error generating profit/loss report for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    else:
        try:
            db = utils.get_mongo_db()
            cashflows = [to_dict_cashflow(cf) for cf in db.cashflows.find(query).sort('created_at', -1)]
        except pymongo.errors.PyMongoError as e:
            logger.error(
                f"MongoDB error fetching cashflows for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
        except Exception as e:
            logger.error(
                f"Error fetching cashflows for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    logger.info(
        f"Rendering profit/loss report page for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return render_template(
        'reports/profit_loss.html',
        form=form,
        cashflows=cashflows,
        title=trans('reports_profit_loss', default='Profit/Loss Report', lang=session.get('lang', 'en')),
        can_interact=can_interact
    )
    try:
        pass
    except CSRFError as e:
        logger.error(
            f"CSRF error in profit/loss report for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('reports_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return render_template(
            'reports/profit_loss.html',
            form=form,
            cashflows=cashflows,
            title=trans('reports_profit_loss', default='Profit/Loss Report', lang=session.get('lang', 'en')),
            can_interact=can_interact
        ), 400

@reports_bp.route('/debtors_creditors', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
@utils.limiter.limit('10 per minute')
def debtors_creditors():
    form = ReportForm()
    can_interact = utils.can_user_interact(current_user)
    if not can_interact:
        logger.warning(
            f"Subscription required for user {current_user.id} to generate debtors/creditors report",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('subscription_required', default='Subscription required to generate reports. Please subscribe.'), 'warning')
        return redirect(url_for('subscribe_bp.subscribe'))
    records = []
    query = {'user_id': str(current_user.id)}
    if form.validate_on_submit():
        try:
            if form.format.data not in ['html', 'pdf', 'csv']:
                logger.error(
                    f"Invalid format {form.format.data} for debtors/creditors report by user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('reports_invalid_format', default='Invalid report format'), 'danger')
                return redirect(url_for('reports.debtors_creditors'))
            db = utils.get_mongo_db()
            if form.start_date.data:
                start_datetime = datetime.combine(form.start_date.data, datetime.min.time(), tzinfo=ZoneInfo("UTC"))
                query['created_at'] = {'$gte': start_datetime}
            if form.end_date.data:
                end_datetime = datetime.combine(form.end_date.data, datetime.max.time(), tzinfo=ZoneInfo("UTC"))
                query['created_at'] = query.get('created_at', {}) | {'$lte': end_datetime}
            records = [to_dict_record(r) for r in db.records.find(query).sort('created_at', -1)]
            output_format = form.format.data
            logger.info(
                f"Generating debtors/creditors report for user {current_user.id}, format: {output_format}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            if output_format == 'pdf':
                return generate_debtors_creditors_pdf(records)
            elif output_format == 'csv':
                return generate_debtors_creditors_csv(records)
        except pymongo.errors.PyMongoError as e:
            logger.error(
                f"MongoDB error generating debtors/creditors report for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
        except Exception as e:
            logger.error(
                f"Error generating debtors/creditors report for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    else:
        try:
            db = utils.get_mongo_db()
            records = [to_dict_record(r) for r in db.records.find(query).sort('created_at', -1)]
        except pymongo.errors.PyMongoError as e:
            logger.error(
                f"MongoDB error fetching records for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
        except Exception as e:
            logger.error(
                f"Error fetching records for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    logger.info(
        f"Rendering debtors/creditors report page for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return render_template(
        'reports/debtors_creditors.html',
        form=form,
        records=records,
        title=trans('reports_debtors_creditors', default='Debtors/Creditors Report', lang=session.get('lang', 'en')),
        can_interact=can_interact
    )
    try:
        pass
    except CSRFError as e:
        logger.error(
            f"CSRF error in debtors/creditors report for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('reports_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return render_template(
            'reports/debtors_creditors.html',
            form=form,
            records=records,
            title=trans('reports_debtors_creditors', default='Debtors/Creditors Report', lang=session.get('lang', 'en')),
            can_interact=can_interact
        ), 400

@reports_bp.route('/funds', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['startup', 'admin'])
@utils.limiter.limit('10 per minute')
def funds():
    form = ReportForm()
    can_interact = utils.can_user_interact(current_user)
    if not can_interact:
        logger.warning(
            f"Subscription required for user {current_user.id} to generate funds report",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('subscription_required', default='Subscription required to generate reports. Please subscribe.'), 'warning')
        return redirect(url_for('subscribe_bp.subscribe'))
    funds = []
    query = {'user_id': str(current_user.id)}
    if form.validate_on_submit():
        try:
            if form.format.data not in ['html', 'pdf', 'csv']:
                logger.error(
                    f"Invalid format {form.format.data} for funds report by user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('reports_invalid_format', default='Invalid report format'), 'danger')
                return redirect(url_for('reports.funds'))
            db = utils.get_mongo_db()
            if form.start_date.data:
                start_datetime = datetime.combine(form.start_date.data, datetime.min.time(), tzinfo=ZoneInfo("UTC"))
                query['created_at'] = {'$gte': start_datetime}
            if form.end_date.data:
                end_datetime = datetime.combine(form.end_date.data, datetime.max.time(), tzinfo=ZoneInfo("UTC"))
                query['created_at'] = query.get('created_at', {}) | {'$lte': end_datetime}
            funds = [to_dict_fund(f) for f in db.funds.find(query).sort('created_at', -1)]
            output_format = form.format.data
            logger.info(
                f"Generating funds report for user {current_user.id}, format: {output_format}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            if output_format == 'pdf':
                return generate_funds_pdf(funds)
            elif output_format == 'csv':
                return generate_funds_csv(funds)
        except pymongo.errors.PyMongoError as e:
            logger.error(
                f"MongoDB error generating funds report for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
        except Exception as e:
            logger.error(
                f"Error generating funds report for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    else:
        try:
            db = utils.get_mongo_db()
            funds = [to_dict_fund(f) for f in db.funds.find(query).sort('created_at', -1)]
        except pymongo.errors.PyMongoError as e:
            logger.error(
                f"MongoDB error fetching funds for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
        except Exception as e:
            logger.error(
                f"Error fetching funds for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    logger.info(
        f"Rendering funds report page for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return render_template(
        'reports/funds.html',
        form=form,
        funds=funds,
        title=trans('reports_funds', default='Funds Report', lang=session.get('lang', 'en')),
        can_interact=can_interact
    )
    try:
        pass
    except CSRFError as e:
        logger.error(
            f"CSRF error in funds report for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('reports_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return render_template(
            'reports/funds.html',
            form=form,
            funds=funds,
            title=trans('reports_funds', default='Funds Report', lang=session.get('lang', 'en')),
            can_interact=can_interact
        ), 400

@reports_bp.route('/forecasts', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['startup', 'admin'])
@utils.limiter.limit('10 per minute')
def forecasts():
    form = ReportForm()
    can_interact = utils.can_user_interact(current_user)
    if not can_interact:
        logger.warning(
            f"Subscription required for user {current_user.id} to generate forecasts report",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('subscription_required', default='Subscription required to generate reports. Please subscribe.'), 'warning')
        return redirect(url_for('subscribe_bp.subscribe'))
    forecasts = []
    query = {'user_id': str(current_user.id)}
    if form.validate_on_submit():
        try:
            if form.format.data not in ['html', 'pdf', 'csv']:
                logger.error(
                    f"Invalid format {form.format.data} for forecasts report by user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('reports_invalid_format', default='Invalid report format'), 'danger')
                return redirect(url_for('reports.forecasts'))
            db = utils.get_mongo_db()
            if form.start_date.data:
                start_datetime = datetime.combine(form.start_date.data, datetime.min.time(), tzinfo=ZoneInfo("UTC"))
                query['period_start'] = {'$gte': start_datetime}
            if form.end_date.data:
                end_datetime = datetime.combine(form.end_date.data, datetime.max.time(), tzinfo=ZoneInfo("UTC"))
                query['period_end'] = query.get('period_end', {}) | {'$lte': end_datetime}
            forecasts = [to_dict_forecast(f) for f in db.forecasts.find(query).sort('created_at', -1)]
            output_format = form.format.data
            logger.info(
                f"Generating forecasts report for user {current_user.id}, format: {output_format}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            if output_format == 'pdf':
                return generate_forecasts_pdf(forecasts)
            elif output_format == 'csv':
                return generate_forecasts_csv(forecasts)
        except pymongo.errors.PyMongoError as e:
            logger.error(
                f"MongoDB error generating forecasts report for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
        except Exception as e:
            logger.error(
                f"Error generating forecasts report for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    else:
        try:
            db = utils.get_mongo_db()
            forecasts = [to_dict_forecast(f) for f in db.forecasts.find(query).sort('created_at', -1)]
        except pymongo.errors.PyMongoError as e:
            logger.error(
                f"MongoDB error fetching forecasts for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
        except Exception as e:
            logger.error(
                f"Error fetching forecasts for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    logger.info(
        f"Rendering forecasts report page for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return render_template(
        'reports/forecasts.html',
        form=form,
        forecasts=forecasts,
        title=trans('reports_forecasts', default='Forecasts Report', lang=session.get('lang', 'en')),
        can_interact=can_interact
    )
    try:
        pass
    except CSRFError as e:
        logger.error(
            f"CSRF error in forecasts report for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('reports_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return render_template(
            'reports/forecasts.html',
            form=form,
            forecasts=forecasts,
            title=trans('reports_forecasts', default='Forecasts Report', lang=session.get('lang', 'en')),
            can_interact=can_interact
        ), 400

@reports_bp.route('/investor_reports', methods=['GET', 'POST'])
@login_required
@utils.requires_role(['startup', 'admin'])
@utils.limiter.limit('10 per minute')
def investor_reports():
    form = ReportForm()
    can_interact = utils.can_user_interact(current_user)
    if not can_interact:
        logger.warning(
            f"Subscription required for user {current_user.id} to generate investor reports",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('subscription_required', default='Subscription required to generate reports. Please subscribe.'), 'warning')
        return redirect(url_for('subscribe_bp.subscribe'))
    reports = []
    query = {'user_id': str(current_user.id)}
    if form.validate_on_submit():
        try:
            if form.format.data not in ['html', 'pdf', 'csv']:
                logger.error(
                    f"Invalid format {form.format.data} for investor reports by user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('reports_invalid_format', default='Invalid report format'), 'danger')
                return redirect(url_for('reports.investor_reports'))
            db = utils.get_mongo_db()
            if form.start_date.data:
                start_datetime = datetime.combine(form.start_date.data, datetime.min.time(), tzinfo=ZoneInfo("UTC"))
                query['created_at'] = {'$gte': start_datetime}
            if form.end_date.data:
                end_datetime = datetime.combine(form.end_date.data, datetime.max.time(), tzinfo=ZoneInfo("UTC"))
                query['created_at'] = query.get('created_at', {}) | {'$lte': end_datetime}
            reports = [to_dict_investor_report(r) for r in db.investor_reports.find(query).sort('created_at', -1)]
            output_format = form.format.data
            logger.info(
                f"Generating investor reports for user {current_user.id}, format: {output_format}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            if output_format == 'pdf':
                return generate_investor_reports_pdf(reports)
            elif output_format == 'csv':
                return generate_investor_reports_csv(reports)
        except pymongo.errors.PyMongoError as e:
            logger.error(
                f"MongoDB error generating investor reports for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
        except Exception as e:
            logger.error(
                f"Error generating investor reports for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    else:
        try:
            db = utils.get_mongo_db()
            reports = [to_dict_investor_report(r) for r in db.investor_reports.find(query).sort('created_at', -1)]
        except pymongo.errors.PyMongoError as e:
            logger.error(
                f"MongoDB error fetching investor reports for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
        except Exception as e:
            logger.error(
                f"Error fetching investor reports for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    logger.info(
        f"Rendering investor reports page for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return render_template(
        'reports/investor_reports.html',
        form=form,
        reports=reports,
        title=trans('reports_investor_reports', default='Investor Reports', lang=session.get('lang', 'en')),
        can_interact=can_interact
    )
    try:
        pass
    except CSRFError as e:
        logger.error(
            f"CSRF error in investor reports for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('reports_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return render_template(
            'reports/investor_reports.html',
            form=form,
            reports=reports,
            title=trans('reports_investor_reports', default='Investor Reports', lang=session.get('lang', 'en')),
            can_interact=can_interact
        ), 400

@reports_bp.route('/admin/customer-reports', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit('10 per minute')
def customer_reports():
    form = CustomerReportForm()
    can_interact = utils.can_user_interact(current_user)  # Should always be True for admins
    if form.validate_on_submit():
        try:
            role = utils.sanitize_input(form.role.data, max_length=20) if form.role.data else None
            report_format = form.format.data
            if report_format not in ['html', 'pdf', 'csv']:
                logger.error(
                    f"Invalid format {report_format} for customer reports by user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('reports_invalid_format', default='Invalid report format'), 'danger')
                return redirect(url_for('reports.customer_reports'))
            if role and role not in ['', 'trader', 'startup', 'admin']:
                logger.error(
                    f"Invalid role {role} for customer reports by user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('reports_invalid_role', default='Invalid role selected'), 'danger')
                return redirect(url_for('reports.customer_reports'))
            db = utils.get_mongo_db()
            pipeline = [
                {'$match': {'role': role}} if role else {},
                {'$lookup': {
                    'from': 'records',
                    'let': {'user_id': '$_id'},
                    'pipeline': [
                        {'$match': {'$expr': {'$eq': ['$user_id', '$$user_id']}}},
                        {'$group': {
                            '_id': '$type',
                            'total_amount': {'$sum': '$amount_owed'}
                        }}
                    ],
                    'as': 'record_totals'
                }},
                {'$lookup': {
                    'from': 'cashflows',
                    'let': {'user_id': '$_id'},
                    'pipeline': [
                        {'$match': {'$expr': {'$eq': ['$user_id', '$$user_id']}}},
                        {'$group': {
                            '_id': '$type',
                            'total_amount': {'$sum': '$amount'}
                        }}
                    ],
                    'as': 'cashflow_totals'
                }},
                {'$lookup': {
                    'from': 'funds',
                    'let': {'user_id': '$_id'},
                    'pipeline': [
                        {'$match': {'$expr': {'$eq': ['$user_id', '$$user_id']}}},
                        {'$sort': {'created_at': -1}},
                        {'$limit': 1}
                    ],
                    'as': 'latest_fund'
                }},
                {'$lookup': {
                    'from': 'forecasts',
                    'let': {'user_id': '$_id'},
                    'pipeline': [
                        {'$match': {'$expr': {'$eq': ['$user_id', '$$user_id']}}},
                        {'$sort': {'created_at': -1}},
                        {'$limit': 1}
                    ],
                    'as': 'latest_forecast'
                }}
            ]
            users = list(db.users.aggregate(pipeline))
            report_data = []
            for user in users:
                record_totals = {r['_id']: r['total_amount'] for r in user['record_totals']} if user['record_totals'] else {'debtor': 0, 'creditor': 0}
                cashflow_totals = {c['_id']: c['total_amount'] for c in user['cashflow_totals']} if user['cashflow_totals'] else {'receipt': 0, 'payment': 0}
                latest_fund = to_dict_fund(user['latest_fund'][0] if user['latest_fund'] else None)
                latest_forecast = to_dict_forecast(user['latest_forecast'][0] if user['latest_forecast'] else None)
                data = {
                    'username': utils.sanitize_input(str(user['_id']), max_length=100),
                    'email': utils.sanitize_input(user.get('email', ''), max_length=100),
                    'role': utils.sanitize_input(user.get('role', ''), max_length=20),
                    'is_trial': user.get('is_trial', False),
                    'trial_end': utils.format_date(user.get('trial_end')) if user.get('trial_end') else '-',
                    'is_subscribed': user.get('is_subscribed', False),
                    'total_debtors': record_totals.get('debtor', 0),
                    'total_creditors': record_totals.get('creditor', 0),
                    'total_receipts': cashflow_totals.get('receipt', 0),
                    'total_payments': cashflow_totals.get('payment', 0),
                    'latest_fund_amount': latest_fund['amount'] if latest_fund['amount'] is not None else '-',
                    'latest_forecast_revenue': latest_forecast['projected_revenue'] if latest_forecast['projected_revenue'] is not None else '-'
                }
                report_data.append(data)
            logger.info(
                f"Generating customer report for user {current_user.id}, format: {report_format}, role: {role or 'all'}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            if report_format == 'html':
                return render_template('reports/customer_reports.html', report_data=report_data, title='Customer Reports', can_interact=can_interact)
            elif report_format == 'pdf':
                return generate_customer_report_pdf(report_data)
            elif report_format == 'csv':
                return generate_customer_report_csv(report_data)
        except pymongo.errors.PyMongoError as e:
            logger.error(
                f"MongoDB error generating customer report for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred while generating the report'), 'danger')
        except Exception as e:
            logger.error(
                f"Error generating customer report for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('reports_generation_error', default='An error occurred while generating the report'), 'danger')
    logger.info(
        f"Rendering customer reports form for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return render_template('reports/customer_reports_form.html', form=form, title='Generate Customer Report', can_interact=can_interact)
    try:
        pass
    except CSRFError as e:
        logger.error(
            f"CSRF error in customer reports for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('reports_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return render_template('reports/customer_reports_form.html', form=form, title='Generate Customer Report', can_interact=can_interact), 400

def generate_profit_loss_pdf(cashflows):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    header_height = 0.7
    extra_space = 0.2
    row_height = 0.3
    bottom_margin = 0.5
    max_y = 10.5
    title_y = max_y - header_height - extra_space
    page_height = (max_y - bottom_margin) * inch
    rows_per_page = int((page_height - (title_y - 0.6) * inch) / (row_height * inch))

    def draw_table_headers(y):
        p.setFillColor(colors.black)
        p.drawString(1 * inch, y * inch, trans('general_date', default='Date'))
        p.drawString(2.5 * inch, y * inch, trans('general_party_name', default='Party Name'))
        p.drawString(4 * inch, y * inch, trans('general_type', default='Type'))
        p.drawString(5 * inch, y * inch, trans('general_amount', default='Amount'))
        return y - row_height

    draw_ficore_pdf_header(p, current_user, y_start=max_y)
    p.setFont("Helvetica", 12)
    p.drawString(1 * inch, title_y * inch, trans('reports_profit_loss_report', default='Profit/Loss Report'))
    p.drawString(1 * inch, (title_y - 0.3) * inch, f"{trans('reports_generated_on', default='Generated on')}: {utils.format_date(datetime.now(timezone.utc))}")
    y = title_y - 0.6
    y = draw_table_headers(y)

    total_income = 0
    total_expense = 0
    row_count = 0

    for t in cashflows:
        if row_count >= rows_per_page:
            p.showPage()
            draw_ficore_pdf_header(p, current_user, y_start=max_y)
            y = title_y - 0.6
            y = draw_table_headers(y)
            row_count = 0

        p.drawString(1 * inch, y * inch, utils.format_date(t['created_at']))
        p.drawString(2.5 * inch, y * inch, utils.sanitize_input(t['party_name'], max_length=100))
        p.drawString(4 * inch, y * inch, trans(t['type'], default=t['type']))
        p.drawString(5 * inch, y * inch, utils.format_currency(t['amount']))
        if t['type'] == 'receipt':
            total_income += t['amount']
        else:
            total_expense += t['amount']
        y -= row_height
        row_count += 1

    if row_count + 3 <= rows_per_page:
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_income', default='Total Income')}: {utils.format_currency(total_income)}")
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_expense', default='Total Expense')}: {utils.format_currency(total_expense)}")
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_net_profit', default='Net Profit')}: {utils.format_currency(total_income - total_expense)}")
    else:
        p.showPage()
        draw_ficore_pdf_header(p, current_user, y_start=max_y)
        y = title_y - 0.6
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_income', default='Total Income')}: {utils.format_currency(total_income)}")
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_expense', default='Total Expense')}: {utils.format_currency(total_expense)}")
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_net_profit', default='Net Profit')}: {utils.format_currency(total_income - total_expense)}")

    p.save()
    buffer.seek(0)
    logger.info(
        f"Generated profit/loss PDF for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=profit_loss.pdf'})

def generate_profit_loss_csv(cashflows):
    output = []
    output.extend(ficore_csv_header(current_user))
    output.append([trans('general_date', default='Date'), trans('general_party_name', default='Party Name'), trans('general_type', default='Type'), trans('general_amount', default='Amount')])
    total_income = 0
    total_expense = 0
    for t in cashflows:
        output.append([utils.format_date(t['created_at']), utils.sanitize_input(t['party_name'], max_length=100), trans(t['type'], default=t['type']), utils.format_currency(t['amount'])])
        if t['type'] == 'receipt':
            total_income += t['amount']
        else:
            total_expense += t['amount']
    output.append(['', '', '', f"{trans('reports_total_income', default='Total Income')}: {utils.format_currency(total_income)}"])
    output.append(['', '', '', f"{trans('reports_total_expense', default='Total Expense')}: {utils.format_currency(total_expense)}"])
    output.append(['', '', '', f"{trans('reports_net_profit', default='Net Profit')}: {utils.format_currency(total_income - total_expense)}"])
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(output)
    buffer.seek(0)
    logger.info(
        f"Generated profit/loss CSV for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return Response(buffer.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=profit_loss.csv'})

def generate_debtors_creditors_pdf(records):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    header_height = 0.7
    extra_space = 0.2
    row_height = 0.3
    bottom_margin = 0.5
    max_y = 10.5
    title_y = max_y - header_height - extra_space
    page_height = (max_y - bottom_margin) * inch
    rows_per_page = int((page_height - (title_y - 0.6) * inch) / (row_height * inch))

    def draw_table_headers(y):
        p.setFillColor(colors.black)
        p.drawString(1 * inch, y * inch, trans('general_date', default='Date'))
        p.drawString(2.5 * inch, y * inch, trans('general_name', default='Name'))
        p.drawString(4 * inch, y * inch, trans('general_type', default='Type'))
        p.drawString(5 * inch, y * inch, trans('general_amount_owed', default='Amount Owed'))
        p.drawString(6.5 * inch, y * inch, trans('general_description', default='Description'))
        return y - row_height

    draw_ficore_pdf_header(p, current_user, y_start=max_y)
    p.setFont("Helvetica", 12)
    p.drawString(1 * inch, title_y * inch, trans('reports_debtors_creditors_report', default='Debtors/Creditors Report'))
    p.drawString(1 * inch, (title_y - 0.3) * inch, f"{trans('reports_generated_on', default='Generated on')}: {utils.format_date(datetime.now(timezone.utc))}")
    y = title_y - 0.6
    y = draw_table_headers(y)

    total_debtors = 0
    total_creditors = 0
    row_count = 0

    for r in records:
        if row_count >= rows_per_page:
            p.showPage()
            draw_ficore_pdf_header(p, current_user, y_start=max_y)
            y = title_y - 0.6
            y = draw_table_headers(y)
            row_count = 0

        p.drawString(1 * inch, y * inch, utils.format_date(r['created_at']))
        p.drawString(2.5 * inch, y * inch, utils.sanitize_input(r['name'], max_length=100))
        p.drawString(4 * inch, y * inch, trans(r['type'], default=r['type']))
        p.drawString(5 * inch, y * inch, utils.format_currency(r['amount_owed']))
        p.drawString(6.5 * inch, y * inch, utils.sanitize_input(r.get('description', ''), max_length=20))
        if r['type'] == 'debtor':
            total_debtors += r['amount_owed']
        else:
            total_creditors += r['amount_owed']
        y -= row_height
        row_count += 1

    if row_count + 2 <= rows_per_page:
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_debtors', default='Total Debtors')}: {utils.format_currency(total_debtors)}")
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_creditors', default='Total Creditors')}: {utils.format_currency(total_creditors)}")
    else:
        p.showPage()
        draw_ficore_pdf_header(p, current_user, y_start=max_y)
        y = title_y - 0.6
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_debtors', default='Total Debtors')}: {utils.format_currency(total_debtors)}")
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_creditors', default='Total Creditors')}: {utils.format_currency(total_creditors)}")

    p.save()
    buffer.seek(0)
    logger.info(
        f"Generated debtors/creditors PDF for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=debtors_creditors.pdf'})

def generate_debtors_creditors_csv(records):
    output = []
    output.extend(ficore_csv_header(current_user))
    output.append([trans('general_date', default='Date'), trans('general_name', default='Name'), trans('general_type', default='Type'), trans('general_amount_owed', default='Amount Owed'), trans('general_description', default='Description')])
    total_debtors = 0
    total_creditors = 0
    for r in records:
        output.append([utils.format_date(r['created_at']), utils.sanitize_input(r['name'], max_length=100), trans(r['type'], default=r['type']), utils.format_currency(r['amount_owed']), utils.sanitize_input(r.get('description', ''), max_length=1000)])
        if r['type'] == 'debtor':
            total_debtors += r['amount_owed']
        else:
            total_creditors += r['amount_owed']
    output.append(['', '', '', f"{trans('reports_total_debtors', default='Total Debtors')}: {utils.format_currency(total_debtors)}", ''])
    output.append(['', '', '', f"{trans('reports_total_creditors', default='Total Creditors')}: {utils.format_currency(total_creditors)}", ''])
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(output)
    buffer.seek(0)
    logger.info(
        f"Generated debtors/creditors CSV for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return Response(buffer.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=debtors_creditors.csv'})

def generate_funds_pdf(funds):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    header_height = 0.7
    extra_space = 0.2
    row_height = 0.3
    bottom_margin = 0.5
    max_y = 10.5
    title_y = max_y - header_height - extra_space
    page_height = (max_y - bottom_margin) * inch
    rows_per_page = int((page_height - (title_y - 0.6) * inch) / (row_height * inch))

    def draw_table_headers(y):
        p.setFillColor(colors.black)
        p.drawString(1 * inch, y * inch, trans('general_date', default='Date'))
        p.drawString(2.5 * inch, y * inch, trans('funds_source', default='Source'))
        p.drawString(4 * inch, y * inch, trans('general_amount', default='Amount'))
        p.drawString(5 * inch, y * inch, trans('general_status', default='Status'))
        return y - row_height

    draw_ficore_pdf_header(p, current_user, y_start=max_y)
    p.setFont("Helvetica", 12)
    p.drawString(1 * inch, title_y * inch, trans('reports_funds_report', default='Funds Report'))
    p.drawString(1 * inch, (title_y - 0.3) * inch, f"{trans('reports_generated_on', default='Generated on')}: {utils.format_date(datetime.now(timezone.utc))}")
    y = title_y - 0.6
    y = draw_table_headers(y)

    total_amount = 0
    row_count = 0

    for f in funds:
        if row_count >= rows_per_page:
            p.showPage()
            draw_ficore_pdf_header(p, current_user, y_start=max_y)
            y = title_y - 0.6
            y = draw_table_headers(y)
            row_count = 0

        p.drawString(1 * inch, y * inch, utils.format_date(f['created_at']))
        p.drawString(2.5 * inch, y * inch, utils.sanitize_input(f['source'], max_length=100))
        p.drawString(4 * inch, y * inch, utils.format_currency(f['amount']))
        p.drawString(5 * inch, y * inch, trans(f['status'], default=f['status']))
        total_amount += f['amount']
        y -= row_height
        row_count += 1

    if row_count + 1 <= rows_per_page:
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_funds', default='Total Funds')}: {utils.format_currency(total_amount)}")
    else:
        p.showPage()
        draw_ficore_pdf_header(p, current_user, y_start=max_y)
        y = title_y - 0.6
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_funds', default='Total Funds')}: {utils.format_currency(total_amount)}")

    p.save()
    buffer.seek(0)
    logger.info(
        f"Generated funds PDF for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=funds.pdf'})

def generate_funds_csv(funds):
    output = []
    output.extend(ficore_csv_header(current_user))
    output.append([trans('general_date', default='Date'), trans('funds_source', default='Source'), trans('general_amount', default='Amount'), trans('general_status', default='Status')])
    total_amount = 0
    for f in funds:
        output.append([utils.format_date(f['created_at']), utils.sanitize_input(f['source'], max_length=100), utils.format_currency(f['amount']), trans(f['status'], default=f['status'])])
        total_amount += f['amount']
    output.append(['', '', f"{trans('reports_total_funds', default='Total Funds')}: {utils.format_currency(total_amount)}", ''])
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(output)
    buffer.seek(0)
    logger.info(
        f"Generated funds CSV for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return Response(buffer.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=funds.csv'})

def generate_forecasts_pdf(forecasts):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    header_height = 0.7
    extra_space = 0.2
    row_height = 0.3
    bottom_margin = 0.5
    max_y = 10.5
    title_y = max_y - header_height - extra_space
    page_height = (max_y - bottom_margin) * inch
    rows_per_page = int((page_height - (title_y - 0.6) * inch) / (row_height * inch))

    def draw_table_headers(y):
        p.setFillColor(colors.black)
        p.drawString(1 * inch, y * inch, trans('general_date', default='Date'))
        p.drawString(2 * inch, y * inch, trans('forecasts_scenario', default='Scenario'))
        p.drawString(3.5 * inch, y * inch, trans('forecasts_projected_revenue', default='Projected Revenue'))
        p.drawString(4.5 * inch, y * inch, trans('forecasts_projected_expenses', default='Projected Expenses'))
        p.drawString(5.5 * inch, y * inch, trans('forecasts_period', default='Period'))
        return y - row_height

    draw_ficore_pdf_header(p, current_user, y_start=max_y)
    p.setFont("Helvetica", 12)
    p.drawString(1 * inch, title_y * inch, trans('reports_forecasts_report', default='Forecasts Report'))
    p.drawString(1 * inch, (title_y - 0.3) * inch, f"{trans('reports_generated_on', default='Generated on')}: {utils.format_date(datetime.now(timezone.utc))}")
    y = title_y - 0.6
    y = draw_table_headers(y)

    total_revenue = 0
    total_expenses = 0
    row_count = 0

    for f in forecasts:
        if row_count >= rows_per_page:
            p.showPage()
            draw_ficore_pdf_header(p, current_user, y_start=max_y)
            y = title_y - 0.6
            y = draw_table_headers(y)
            row_count = 0

        period = f"{utils.format_date(f['period_start'])} - {utils.format_date(f['period_end'])}" if f['period_start'] and f['period_end'] else '-'
        p.drawString(1 * inch, y * inch, utils.format_date(f['created_at']))
        p.drawString(2 * inch, y * inch, utils.sanitize_input(f['scenario'][:20], max_length=20))
        p.drawString(3.5 * inch, y * inch, utils.format_currency(f['projected_revenue']))
        p.drawString(4.5 * inch, y * inch, utils.format_currency(f['projected_expenses']))
        p.drawString(5.5 * inch, y * inch, period[:20])
        total_revenue += f['projected_revenue']
        total_expenses += f['projected_expenses']
        y -= row_height
        row_count += 1

    if row_count + 2 <= rows_per_page:
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_projected_revenue', default='Total Projected Revenue')}: {utils.format_currency(total_revenue)}")
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_projected_expenses', default='Total Projected Expenses')}: {utils.format_currency(total_expenses)}")
    else:
        p.showPage()
        draw_ficore_pdf_header(p, current_user, y_start=max_y)
        y = title_y - 0.6
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_projected_revenue', default='Total Projected Revenue')}: {utils.format_currency(total_revenue)}")
        y -= row_height
        p.drawString(1 * inch, y * inch, f"{trans('reports_total_projected_expenses', default='Total Projected Expenses')}: {utils.format_currency(total_expenses)}")

    p.save()
    buffer.seek(0)
    logger.info(
        f"Generated forecasts PDF for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=forecasts.pdf'})

def generate_forecasts_csv(forecasts):
    output = []
    output.extend(ficore_csv_header(current_user))
    output.append([
        trans('general_date', default='Date'),
        trans('forecasts_scenario', default='Scenario'),
        trans('forecasts_projected_revenue', default='Projected Revenue'),
        trans('forecasts_projected_expenses', default='Projected Expenses'),
        trans('forecasts_period', default='Period')
    ])
    total_revenue = 0
    total_expenses = 0
    for f in forecasts:
        period = f"{utils.format_date(f['period_start'])} - {utils.format_date(f['period_end'])}" if f['period_start'] and f['period_end'] else '-'
        output.append([
            utils.format_date(f['created_at']),
            utils.sanitize_input(f['scenario'], max_length=100),
            utils.format_currency(f['projected_revenue']),
            utils.format_currency(f['projected_expenses']),
            period
        ])
        total_revenue += f['projected_revenue']
        total_expenses += f['projected_expenses']
    output.append(['', '', f"{trans('reports_total_projected_revenue', default='Total Projected Revenue')}: {utils.format_currency(total_revenue)}", f"{trans('reports_total_projected_expenses', default='Total Projected Expenses')}: {utils.format_currency(total_expenses)}", ''])
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(output)
    buffer.seek(0)
    logger.info(
        f"Generated forecasts CSV for user {current_user.id}",
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
    )
    return Response(buffer.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=forecasts.csv'})

def generate_investor_reports_pdf(reports):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    header_height = 0.7
    extra_space = 0.2
    row_height = 0.3
    bottom_margin = 0.5
    max_y = 10.5
    title_y = max_y - header_height - extra_space
    page_height = (max_y - bottom_margin) * inch
    rows_per_page = int((page_height - (title_y - 0.6) * inch) / (row_height * inch))

    def draw_table_headers(y):
        p.setFillColor(colors.black)
        p.drawString(1 * inch, y * inch, trans('general_date', default='Date'))
        p.drawString(2.5 * inch, y * inch, trans('investor_report_title', default='Report Title'))
        p.drawString(4 * inch, y * inch, trans('investor_report_metrics', default='Key Metrics'))
        return y - row_height

    draw_ficore_pdf_header(p, current_user, y_start=max_y)
    p.setFont("Helvetica", 12)
    p.drawString(1 * inch, title_y * inch, trans('reports_investor_reports', default='Investor Reports'))
    p.drawString(1 * inch, (title_y - 0.3) * inch, f"{trans('reports_generated_on', default='Generated on')}: {utils.format_date(datetime.now(timezone.utc))}")
    y = title_y - 0.6
    y = draw_table_headers(y)

    row_count = 0
    for r in reports:
        if row_count >= rows_per_page:
            p.showPage()
            draw_ficore_pdf_header(p, current_user, y_start=max_y)
            y = title_y - 0.6
            y = draw_table_headers(y)
            row_count = 0

        metrics_summary = ', '.join([f"{k}: {utils.format_currency(v)}" if isinstance(v, (int, float)) else f"{k}: {v}" for k, v in r['financial_metrics'].items()])[:50]
        p.drawString(1 * inch, y * inch, utils.format_date(r['created_at']))
        p.drawString(2.5 * inch, y * inch, r['title'][:20])
        p.drawString(4 * inch, y * inch, metrics_summary)
        y -= row_height
        row_count += 1

    p.save()
    buffer.seek(0)
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=investor_reports.pdf'})

def generate_investor_reports_csv(reports):
    output = []
    output.extend(ficore_csv_header(current_user))
    output.append([trans('general_date', default='Date'), trans('investor_report_title', default='Report Title'), trans('investor_report_metrics', default='Key Metrics')])
    for r in reports:
        metrics_summary = ', '.join([f"{k}: {utils.format_currency(v)}" if isinstance(v, (int, float)) else f"{k}: {v}" for k, v in r['financial_metrics'].items()])
        output.append([utils.format_date(r['created_at']), r['title'], metrics_summary])
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(output)
    buffer.seek(0)
    return Response(buffer.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=investor_reports.csv'})

def generate_customer_report_pdf(report_data):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    header_height = 0.7
    extra_space = 0.2
    row_height = 0.2
    bottom_margin = 0.5
    max_y = 10.5
    title_y = max_y - header_height - extra_space
    page_height = (max_y - bottom_margin) * inch
    rows_per_page = int((page_height - (title_y - 0.6) * inch) / (row_height * inch))

    def draw_table_headers(y):
        p.setFillColor(colors.black)
        headers = [
            'Username', 'Email', 'Role', 'Trial', 'Trial End', 'Subscribed',
            'Debtors', 'Creditors', 'Receipts', 'Payments', 'Latest Fund', 'Latest Forecast'
        ]
        x_positions = [0.5 * inch + i * 0.5 * inch for i in range(len(headers))]
        for header, x in zip(headers, x_positions):
            p.drawString(x, y * inch, header)
        return y - row_height, x_positions

    draw_ficore_pdf_header(p, current_user, y_start=max_y)
    p.setFont("Helvetica", 8)
    p.drawString(0.5 * inch, title_y * inch, trans('reports_customer_report', default='Customer Report'))
    p.drawString(0.5 * inch, (title_y - 0.3) * inch, f"{trans('reports_generated_on', default='Generated on')}: {utils.format_date(datetime.utcnow())}")
    y = title_y - 0.6
    y, x_positions = draw_table_headers(y)

    row_count = 0
    for data in report_data:
        if row_count >= rows_per_page:
            p.showPage()
            draw_ficore_pdf_header(p, current_user, y_start=max_y)
            y = title_y - 0.6
            y, x_positions = draw_table_headers(y)
            row_count = 0

        values = [
            data['username'][:15],
            data['email'][:15],
            data['role'],
            str(data['is_trial']),
            data['trial_end'],
            str(data['is_subscribed']),
            utils.format_currency(data['total_debtors']),
            utils.format_currency(data['total_creditors']),
            utils.format_currency(data['total_receipts']),
            utils.format_currency(data['total_payments']),
            str(data['latest_fund_amount']),
            str(data['latest_forecast_revenue'])
        ]
        for value, x in zip(values, x_positions):
            p.drawString(x, y * inch, str(value)[:15])
        y -= row_height
        row_count += 1

    p.save()
    buffer.seek(0)
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=customer_report.pdf'})

def generate_customer_report_csv(report_data):
    output = []
    output.extend(ficore_csv_header(current_user))
    headers = [
        'Username', 'Email', 'Role', 'Is Trial', 'Trial End', 'Is Subscribed',
        'Total Debtors', 'Total Creditors', 'Total Receipts', 'Total Payments',
        'Latest Fund Amount', 'Latest Forecast Revenue'
    ]
    output.append(headers)
    for data in report_data:
        row = [
            data['username'], data['email'], data['role'], data['is_trial'], data['trial_end'], data['is_subscribed'],
            utils.format_currency(data['total_debtors']), utils.format_currency(data['total_creditors']),
            utils.format_currency(data['total_receipts']), utils.format_currency(data['total_payments']),
            data['latest_fund_amount'], data['latest_forecast_revenue']
        ]
        output.append(row)
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(output)
    buffer.seek(0)
    return Response(buffer.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=customer_report.csv'})
